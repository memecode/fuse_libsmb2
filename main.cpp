/*
  fuse_libsmb2: a user space filesystem using libsmb2 
*/

#define FUSE_USE_VERSION 31
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

#include <string>

#include <fuse3/fuse.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>

#define CODE_REF		code_ref(__FILE__, __LINE__, __func__).c_str()
extern std::string code_ref( const char *file, int line, const char *func );

#define LOG_DEBUG(...)	log_printf("DEBG", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_INFO(...)	log_printf("INFO", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_WARN(...)	log_printf("WARN", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_ERR(...)	log_printf("ERRR", __FILE__, __LINE__, __func__, __VA_ARGS__)
extern void log_printf(const char *type, const char *file, int line, const char *func, ...);

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */
static struct options {
    const char *uri;
    int show_help;
} options;

static smb2_context *smb2 = nullptr;
std::string smb2_path;


#ifdef _WINDOWS
	
	#define DEFAULT_USER_ID     0
	#define DEFAULT_GROUP_ID    0
	
	#define SMB_FILE			_S_IFREG
	#define SMB_LINK			_S_IFREG
	#define SMB_FILE_READ		_S_IREAD
	#define SMB_FILE_WRITE		_S_IWRITE
	#define SMB_DIR				_S_IFDIR
	#define SMB_DIR_READ		_S_IREAD | _S_IEXEC | 0x4 /* IDK what this is... but windows needs it */
	#define SMB_DIR_WRITE		_S_IWRITE

#else
	
	#define DEFAULT_USER_ID     1000
	#define DEFAULT_GROUP_ID    1000

	// Files are 644
	#define SMB_FILE			S_IFREG
	#define SMB_LINK			S_IFLNK
	#define SMB_FILE_READ       S_IRUSR | \
								S_IRGRP | \
								S_IROTH
	#define SMB_FILE_WRITE      S_IWUSR

	// Dir are 755
	#define SMB_DIR				S_IFDIR
	#define SMB_DIR_READ        S_IRUSR | S_IXUSR | \
								S_IRGRP | S_IXGRP | \
								S_IROTH | S_IXOTH
	#define SMB_DIR_WRITE       S_IWUSR
#endif

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("--uri=%s", uri),
    OPTION("-h", show_help),
    OPTION("--help", show_help),
    FUSE_OPT_END
};

static std::string full_path(const char *path)
{
    std::string p = smb2_path + path;
    if (p[0] == '/')
        return p.substr(1);
    return p;
}

static std::string code_ref( const char *file, int line, const char *func )
{
    char s[256];
    auto last = strrchr(file, '/');
    snprintf(s, sizeof(s), "%s:%i:%s", last?last+1:file, line, func);
    return s;
}

void log_printf(const char *type, const char *file, int line, const char *func, const char *fmt, ...)
{
	char s[512];
	auto ch = snprintf(s, sizeof(s), "%s:%s:%i:%s ", type, file, line, func);

	va_list args;
	va_start(args, fmt);
	vsnprintf(s+ch, sizeof(s)-ch, fmt, args);
	va_end(args);

	printf("%s\n", s);
}

static void *wrapper_init(struct fuse_conn_info *conn,
            struct fuse_config *cfg)
{
    (void) conn;
    cfg->kernel_cache = 1;
    return NULL;
}

static bool convert_stat(struct fuse_stat *out, smb2_stat_64 *in)
{
    out->st_size = (off_t)in->smb2_size;
    out->st_mtim.tv_sec = (time_t)in->smb2_mtime;
    out->st_atim.tv_sec = (time_t)in->smb2_atime;
    out->st_ctim.tv_sec = (time_t)in->smb2_ctime;
    
	#if 0
    bool read_only = (in->smb2_attrib & SMB2_FILE_ATTRIBUTE_READONLY) != 0;
	#else
	bool read_only = false;
	#endif

    switch (in->smb2_type)
    {
    case SMB2_TYPE_LINK:
        out->st_mode = SMB_LINK | SMB_FILE_READ;
        if (!read_only)
            out->st_mode |= SMB_FILE_WRITE;
        break;
    case SMB2_TYPE_FILE:
        out->st_mode = SMB_FILE | SMB_FILE_READ;
        if (!read_only)
            out->st_mode |= SMB_FILE_WRITE;
        break;
    case SMB2_TYPE_DIRECTORY:
        out->st_mode = SMB_DIR | SMB_DIR_READ;
        if (!read_only)
            out->st_mode |= SMB_DIR_WRITE;
        break;
    }

    out->st_uid = DEFAULT_USER_ID;
    out->st_gid = DEFAULT_GROUP_ID;

    return true;
}

static int wrapper_getattr( const char *path,
                            struct fuse_stat *stbuf,
                            struct fuse_file_info *fi )
{
    (void) fi;

	LOG_DEBUG("path=%s", path);

    auto full = full_path( path );
    memset(stbuf, 0, sizeof(struct stat));

    if( strcmp(path, "/") == 0 ) 
    {
		// 0x41ff
        stbuf->st_mode = SMB_DIR | SMB_DIR_READ | SMB_DIR_WRITE;
        stbuf->st_nlink = 2;
        stbuf->st_uid = DEFAULT_USER_ID;
        stbuf->st_gid = DEFAULT_GROUP_ID;
    }
    else if( path )
    {
        smb2_stat_64 s = {};
        auto result = smb2_stat( smb2, full.c_str(), &s );
        if( -EACCES == result )
        {
            // For entries without permissions we create an empty stat record rather than ENOENT
            stbuf->st_mode = SMB_FILE;
            stbuf->st_uid = DEFAULT_USER_ID;
            stbuf->st_gid = DEFAULT_GROUP_ID;
            return 0;
        }
        else if( result )
        {
            printf( "%s error: smb2_stat(%s) failed: %i, %s\n", CODE_REF, full.c_str(), result, smb2_get_error(smb2) );
            return result;
        }

        if( !convert_stat( stbuf, &s ) )
        {
            printf( "%s error: convert_stat(%s) failed\n", CODE_REF, full.c_str() );
            return -EINVAL;
        }
    }
    else return -ENOENT;

    return 0;
}

static int wrapper_readdir( const char *path,
                            void *buf,
                            fuse_fill_dir_t filler,
                            fuse_off_t offset,
                            struct fuse_file_info *fi,
                            enum fuse_readdir_flags flags )
{
    auto none = (fuse_fill_dir_flags)0;
    auto full = full_path( path );

	LOG_DEBUG("path=%s", path);

    if (!smb2)
    {
        printf( "%s error: no smb2.\n", CODE_REF );
        return -ENOENT;
    }
    auto dir = smb2_opendir( smb2, full.c_str() );
    if (dir == NULL)
    {
        printf("%s error: smb2_opendir failed. %s\n", CODE_REF, smb2_get_error(smb2));
        return -ENOENT;
    }

    // filler(buf, ".", NULL, 0, none);
    // filler(buf, "..", NULL, 0, none);

    smb2dirent *ent = nullptr;
    while ((ent = smb2_readdir(smb2, dir)))
    {
        struct fuse_stat st = {};
        convert_stat(&st, &ent->st);
        filler(	buf,
                ent->name,
                &st,
                0,
                none);

        if (ent->st.smb2_type == SMB2_TYPE_LINK)
        {
            printf("link: %s = %x\n", ent->name, ent->st.smb2_attrib);
            
            /*
            char buf[256];
            if (url->path && url->path[0])
            {
                asprintf(&link, "%s/%s", url->path, ent->name);
            }
            else
            {
                asprintf(&link, "%s", ent->name);
            }
            smb2_readlink(smb2, link, buf, 256);
            printf("    -> [%s]\n", buf);
            free(link);
            */
        }
    }	

    smb2_closedir(smb2, dir);

    return 0;
}

static int wrapper_open( const char *path,
                         struct fuse_file_info *fi)
{
	LOG_DEBUG("path=%s", path);

    auto full = full_path( path );

    smb2fh *fh = smb2_open(smb2, full.c_str(), fi->flags);
    if (!fh)
    {
        printf( "%s error: path=%s err=%s\n", CODE_REF, full.c_str(), smb2_get_error(smb2) );
        return -ENOENT;
    }

    fi->fh = (uint64_t)fh;
    printf( "%s open(%s)=%p\n", CODE_REF, full.c_str(), fh );
    return 0;
}

static int wrapper_read( const char *path,
                         char *buf,
                         size_t size,
                         fuse_off_t offset,
                         struct fuse_file_info *fi )
{
	LOG_DEBUG("path=%s", path);

    if( !fi )
    {
        printf( "%s error: no file info\n", CODE_REF );
        return -EINVAL;
    }

    auto fh = (smb2fh*)fi->fh;
    if( !fh )
    {
        printf( "%s error: no file handle\n", CODE_REF );
        return -EINVAL;
    }

    if( offset != smb2_lseek( smb2, fh, offset, SEEK_SET, NULL ) )
    {
        printf( "%s error: smb2_lseek failed\n", CODE_REF );
        return -EFAULT;
    }

    printf( "%s smb2_read @ %i (%p, %zi)", CODE_REF, (int)offset, buf, size );
    auto rd = smb2_read( smb2, fh, (uint8_t*) buf, size );
    printf( " = %i\n", rd );
    return rd;
}

static int wrapper_release( const char *path, struct fuse_file_info *fi )
{
	LOG_DEBUG("path=%s", path);

    if( !fi )
    {
        printf( "%s error: no file info\n", CODE_REF );
        return -EINVAL;
    }

    auto fh = (smb2fh*)fi->fh;
    if( !fh )
    {
        printf( "%s error: no file handle\n", CODE_REF );
        return -EINVAL;
    }

    smb2_close( smb2, fh );
    fi->fh = 0;
    return 0;
}

static const struct fuse_operations smb2_ops = {
    .getattr	= wrapper_getattr,
    .open		= wrapper_open,
    .read		= wrapper_read,
    .release    = wrapper_release,
    .readdir	= wrapper_readdir,
    .init		= wrapper_init,
};

static void show_help(const char *progname)
{
    printf("usage: %s [options] <mountpoint>\n\n", progname);
    printf("File-system specific options:\n"
           "    --uri=<uri>         Path to the SMB server in the 'smb://hostname[/path]' form\n"
           "\n");
}

int main(int argc, char *argv[])
{
    int ret;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	#ifdef _WINDOWS
	WSADATA _data;
	WSAStartup(MAKEWORD(2, 2), &_data);
	#endif

	struct stat st;
	auto r = stat("C:\\Users\\Matthew\\work\\smb", &st);
	int asd=0;


    /* Set defaults -- we have to use strdup so that
       fuse_opt_parse can free the defaults if other
       values are specified */
    options.uri = nullptr;

    /* Parse options */
    if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
        return 1;

    /* When --help is specified, first print our own file-system
       specific help text, then signal fuse_main to show
       additional help (by adding `--help` to the options again)
       without usage: line (by setting argv[0] to the empty
       string) */
    if( options.show_help || !options.uri )
    {
        show_help( argv[0] );
        assert( fuse_opt_add_arg(&args, "--help") == 0 );
        args.argv[0][0] = '\0';
    }

    if (options.uri)
    {
        smb2 = smb2_init_context();
        auto url = smb2_parse_url(smb2, options.uri);
        if (url == NULL)
        {
            fprintf( stderr, "Failed to parse url: %s\n", smb2_get_error(smb2) );
            return -1;
        }

        if (url)
            printf("url domain:%s user:%s server:%s share:%s path:%s\n",
                url->domain,
                url->user,
                url->server,
                url->share,
                url->path);

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
		smb2_set_password(smb2, "_groon");
        if (smb2_connect_share(smb2, url->server, url->share, url->user) < 0)
        {
            printf("smb2_connect_share failed. %s\n", smb2_get_error(smb2));
            return -1;
        }

        if (url->path)
            smb2_path = url->path;
    }

    ret = fuse_main( args.argc, args.argv, &smb2_ops, NULL );
    fuse_opt_free_args( &args );
    return ret;
}
