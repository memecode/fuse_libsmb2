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
#include <mutex>
#include <sstream>
#include <memory>

#ifdef HAIKU
#include <fuse/fuse.h>
#else
#include <fuse3/fuse.h>
#endif

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>

#define CODE_REF		code_ref(__FILE__, __LINE__, __func__).c_str()
static std::string code_ref( const char *file, int line, const char *func );

#define LOG_DEBUG(...)	// log_printf("DBG", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_INFO(...)	log_printf("INF", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_WARN(...)	log_printf("WRN", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_ERR(...)	log_printf("ERR", __FILE__, __LINE__, __func__, __VA_ARGS__)
void log_printf(const char *type, const char *file, int line, const char *func, ...);

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */
static struct options {
    const char *uri;
    const char *userId;
    int show_help;
} options;

#ifdef _WINDOWS

#define DIR_CHAR            '\\'

#define DEFAULT_USER_ID     0
#define DEFAULT_GROUP_ID    0

#define SMB_FILE            _S_IFREG
#define SMB_LINK            _S_IFREG
#define SMB_FILE_READ       0444
#define SMB_FILE_WRITE      0200
#define SMB_DIR             _S_IFDIR
#define SMB_DIR_READ        0555
#define SMB_DIR_WRITE       0200

#else
    
#define DIR_CHAR            '/'

#define DEFAULT_USER_ID     1000
#define DEFAULT_GROUP_ID    1000

// Files are 644
#define SMB_FILE            S_IFREG
#define SMB_LINK            S_IFLNK
#define SMB_FILE_READ       S_IRUSR | \
                            S_IRGRP | \
                            S_IROTH
#define SMB_FILE_WRITE      S_IWUSR

// Dir are 755
#define SMB_DIR             S_IFDIR
#define SMB_DIR_READ        S_IRUSR | S_IXUSR | \
                            S_IRGRP | S_IXGRP | \
                            S_IROTH | S_IXOTH
#define SMB_DIR_WRITE       S_IWUSR

typedef struct stat fuse_stat;
typedef off_t fuse_off_t;

#endif

static smb2_context *smb2 = nullptr;
static std::string smb2_path;
static std::mutex smb2_mutex;
static int user_id = DEFAULT_USER_ID;
static int group_id = DEFAULT_GROUP_ID;

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("--uri=%s", uri),
    OPTION("--userId=%s", userId),
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
    std::stringstream s;
    auto last = strrchr(file, DIR_CHAR);
    s << ( last?last+1:file ) << ":" << line << ":" <<  func;
    return s.str();
}

void log_printf(const char *type, const char *file, int line, const char *func, const char *fmt, ...)
{
    std::stringstream s;
    auto last = strrchr(file, DIR_CHAR);
    s << type << ":" << (last?last+1:file) << ":" << line << ":" << func << " ";

    va_list args, copy;
    va_start( args, fmt );
    va_copy( copy, args );
    auto len = vsnprintf(nullptr, 0, fmt, args);
    if( len > 0 )
    {
        std::unique_ptr<char[]> data( new char[ len + 1 ] );
        if( data )
        {
            vsnprintf( data.get(), len + 1, fmt, copy );
            s << data.get();
        }
    }
    va_end(args);
    va_end(copy);

    auto formatted = s.str();
    printf("%s\n", formatted.c_str());
}

static void *wrapper_init(struct fuse_conn_info *conn
    #ifndef HAIKU
    , struct fuse_config *cfg
    #endif
    )
{
    std::unique_lock<std::mutex> lock(smb2_mutex);
    (void) conn;
    #ifndef HAIKU
    cfg->kernel_cache = 1;
    #endif
    return NULL;
}

static bool convert_stat(fuse_stat *out, smb2_stat_64 *in)
{
    out->st_size = (off_t)in->smb2_size;
    out->st_mtim.tv_sec = (time_t)in->smb2_mtime;
    out->st_atim.tv_sec = (time_t)in->smb2_atime;
    out->st_ctim.tv_sec = (time_t)in->smb2_ctime;
    
    #if 0
    bool read_only = (in->smb2_attrib & SMB2_FILE_ATTRIBUTE_READONLY) != 0;
    #else
    bool read_only = true;
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

    out->st_uid = user_id;
    out->st_gid = group_id;

    return true;
}

static int wrapper_getattr( const char *path,
                            fuse_stat *stbuf
                            #ifndef HAIKU
                            , struct fuse_file_info *fi
                            #endif
                            )
{
    std::unique_lock<std::mutex> lock(smb2_mutex);
    #ifndef HAIKU
    (void) fi;
    #endif

    // LOG_DEBUG("path=%s", path);

    auto full = full_path( path );
    memset(stbuf, 0, sizeof(struct stat));

    if( strcmp(path, "/") == 0 ) 
    {
        stbuf->st_mode = SMB_DIR | SMB_DIR_READ | SMB_DIR_WRITE;
        stbuf->st_nlink = 2;
        stbuf->st_uid = user_id;
        stbuf->st_gid = group_id;
    }
    else if( path )
    {
        smb2_stat_64 s = {};
        auto result = smb2_stat( smb2, full.c_str(), &s );
        if( -EACCES == result )
        {
            // For entries without permissions we create an empty stat record rather than ENOENT
            stbuf->st_mode = SMB_FILE;
            stbuf->st_uid = user_id;
            stbuf->st_gid = group_id;
            LOG_ERR( "smb2_stat(%s) failed: %i, %s", full.c_str(), result, smb2_get_error(smb2) );
            return 0;
        }
        else if( result )
        {
            LOG_ERR( "smb2_stat(%s) failed: %i, %s", full.c_str(), result, smb2_get_error(smb2) );
            return result;
        }

        if( !convert_stat( stbuf, &s ) )
        {
            LOG_ERR( "convert_stat(%s) failed\n", CODE_REF, full.c_str() );
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
                            struct fuse_file_info *fi
                            #ifndef HAIKU
                            , enum fuse_readdir_flags flags 
                            #endif
                            )
{
    std::unique_lock<std::mutex> lock(smb2_mutex);
    #ifndef HAIKU
    auto none = (fuse_fill_dir_flags)0;
    #endif
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

    smb2dirent *ent = nullptr;
    while ((ent = smb2_readdir(smb2, dir)))
    {
        fuse_stat st = {};
        convert_stat(&st, &ent->st);
        filler(	buf,
                ent->name,
                &st,
                0
                #ifndef HAIKU
                , none
                #endif
                );

        if (ent->st.smb2_type == SMB2_TYPE_LINK)
        {
            // printf("link: %s = %x\n", ent->name, ent->st.smb2_attrib);
            
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

#ifndef O_ACCMODE
#define O_ACCMODE (O_RDWR|O_WRONLY|O_RDONLY)
#endif /* !O_ACCMODE */

static int wrapper_open( const char *path,
                         struct fuse_file_info *fi)
{
    std::unique_lock<std::mutex> lock(smb2_mutex);

    if ((fi->flags & O_ACCMODE) != O_RDONLY)
        return -EACCES;

    auto full = full_path( path );
    auto fh = smb2_open(smb2, full.c_str(), fi->flags);
    if (!fh)
    {
        LOG_ERR( "smb2_open failed path=%s err=%s", full.c_str(), smb2_get_error(smb2) );
        return -ENOENT;
    }

    // LOG_DEBUG("full=%s fh=%p fi->flags=0x%x", full.c_str(), fh, fi->flags);
    fi->fh = (uint64_t)fh;
    return 0;
}

static int wrapper_read( const char *path,
                         char *buf,
                         size_t size,
                         fuse_off_t offset,
                         struct fuse_file_info *fi )
{
    std::unique_lock<std::mutex> lock(smb2_mutex);
    // LOG_DEBUG("path=%s", path);

    if( !fi )
    {
        LOG_ERR( "no file info\n" );
        return -EINVAL;
    }

    auto fh = (smb2fh*)fi->fh;
    if( !fh )
    {
        LOG_ERR( "no file handle\n" );
        return -EINVAL;
    }

    if( offset != smb2_lseek( smb2, fh, offset, SEEK_SET, NULL ) )
    {
        LOG_ERR( "smb2_lseek failed: %s", smb2_get_error(smb2) );
        return -EFAULT;
    }

    return smb2_read( smb2, fh, (uint8_t*) buf, (uint32_t) size );
}

static int wrapper_release( const char *path, struct fuse_file_info *fi )
{
    std::unique_lock<std::mutex> lock(smb2_mutex);
    // LOG_DEBUG("path=%s", path);

    if( !fi )
    {
        LOG_ERR( "no file info\n" );
        return -EINVAL;
    }

    auto fh = (smb2fh*)fi->fh;
    if( !fh )
    {
        LOG_ERR( "no file handle\n" );
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
           "    --uri=<uri>          Path to the SMB server in the 'smb://[user[:password]@]hostname[/path]' form\n"
           "    --user=<user:group>  Set the user and group for entries returned to fuse.\n"
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

    if( options.userId )
    {
        user_id = atoi( options.userId );
        if( auto colon = strchr( options.userId, ':' ) )
        {
            group_id = atoi( colon + 1 );
        }
        LOG_INFO( "uid=%i gid=%i", user_id, group_id );
    }

    if( options.uri )
    {
        smb2 = smb2_init_context();
        auto url = smb2_parse_url(smb2, options.uri);
        if( nullptr == url )
        {
            LOG_ERR( "Failed to parse url: %s", smb2_get_error(smb2) );
            smb2_destroy_context( smb2 );
            fuse_opt_free_args( &args );
            return -1;
        }

        if (url->user)
        {
            auto sep = strchr(url->user, ':');
            if (sep)
            {
                // separate the username and password out...
                smb2_set_password(smb2, sep + 1);

                size_t userLen = sep - url->user;
                char *user = (char*)malloc(userLen + 1);
                if (user)
                {
                    memcpy(user, url->user, userLen);
                    user[userLen] = 0;
                    free((void*)url->user);
                    url->user = user;
                }
            }
        }

        LOG_INFO( "url domain:%s user:%s server:%s share:%s path:%s",
            url->domain,
            url->user,
            url->server,
            url->share,
            url->path );

        smb2_set_security_mode( smb2, SMB2_NEGOTIATE_SIGNING_ENABLED );
        if( smb2_connect_share(smb2, url->server, url->share, url->user) < 0 )
        {
            LOG_ERR( "smb2_connect_share failed. %s", smb2_get_error( smb2 ) );
            return -1;
        }

        if (url->path)
            smb2_path = url->path;
    }

    ret = fuse_main( args.argc, args.argv, &smb2_ops, NULL );

    if( nullptr != smb2 )
    {
        smb2_destroy_context( smb2 );
    }
    fuse_opt_free_args( &args );
    return ret;
}
