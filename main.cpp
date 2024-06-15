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
#include <time.h>
#ifndef WINDOWS
#include <poll.h>
#endif

#include <string>
#include <mutex>
#include <sstream>
#include <memory>
#include <unordered_map>

#ifdef HAIKU
#include <fuse/fuse.h>
#else
#include <fuse3/fuse.h>
#endif

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>

#define CACHED_ATTR		1
#define ASYNC_LOCKING	1
#define DEBUG_STATS		1
#define CODE_REF		code_ref(__FILE__, __LINE__, __func__).c_str()
static std::string code_ref( const char *file, int line, const char *func );

#define LOG_DEBUG(...)	// log_printf("DBG", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_INFO(...)	log_printf("INF", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_WARN(...)	log_printf("WRN", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_ERR(...)	log_printf("ERR", __FILE__, __LINE__, __func__, __VA_ARGS__)
void log_printf(const char *type, const char *file, int line, const char *func, ...);

#if DEBUG_STATS
enum TFnType
{
    F_getattr,
    F_open,
    F_read,
    F_release,
    F_readdir,
    F_init,

    F_Max
};
int fnCounts[F_Max] = {};
extern void fnDoStats();
#endif

int wrapper_readdir( const char *path, void *buf, fuse_fill_dir_t filler, fuse_off_t offset, struct fuse_file_info *fi
                    #ifndef HAIKU
                    , enum fuse_readdir_flags flags 
                    #endif
                    );

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
static t_socket cfd = -1;
static int cevents = 0;

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
    #if DEBUG_STATS
    fnCounts[F_init]++;
    #endif
    (void) conn;
    #ifndef HAIKU
    cfg->kernel_cache = 1;
    #endif
    return NULL;
}

std::string parentFolder(const std::string &path)
{
	for (int i = path.size() - 1; i > 0; i--)
	{
		auto ch = path[i];
		if (ch == '/' || ch == '\\')
			return path.substr(0, i);
	}

	return "/";
}

struct PathParts
{
	std::string folder, leaf;
};

PathParts splitPath(const std::string &path)
{
	PathParts p;
	auto lastSep = path.rfind("/");
	if (lastSep == std::string::npos)
	{
		p.folder = "/";
		p.leaf = path;
	}
	else
	{
		p.folder = path.substr(0, lastSep);
		p.leaf   = path.substr(lastSep+1);
	}
	return p;
}

#if CACHED_ATTR
struct smb2entry
{
	std::string name;
	smb2dirent e;

	smb2entry(smb2dirent &entry)
	{
		name = entry.name;
		e = entry;
		e.name = name.c_str();
	}

	smb2entry(const smb2entry &s)
	{
		name = s.name;
		e = s.e;
		e.name = name.c_str();
	}
};
typedef std::vector<smb2entry> TDirVec;
std::unordered_map<std::string, TDirVec> entryMap;

bool add_cache(std::string &folder, smb2dirent *ent)
{
	if (folder.empty())
		folder = "/";

	smb2entry e(*ent);
	entryMap[folder].push_back(e);
	
	// LOG_INFO("add_cache(%s, %s)\n", folder.c_str(), e.e.name);

	return true;
}

smb2entry *get_cache(std::string &path)
{
	auto p = splitPath(path);
	auto it = entryMap.find(p.folder);
	if (it == entryMap.end())
		return NULL;

	for (auto &entry: it->second)
	{
		if (entry.name == p.leaf)
			return &entry;
	}

	return NULL;
}
#endif

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

struct smb2_cb_data
{
    bool finished = false;
    int status = 0;
};

static int wait_loop(smb2_cb_data &data)
{
    while (!data.finished)
    {
		#ifdef WINDOWS
		WSAPOLLFD pfd;
        pfd.fd = cfd;
        pfd.events = cevents;
		if (WSAPoll(&pfd, 1, 1000) < 0)
		#else
	    struct pollfd pfd;
        pfd.fd = cfd;
        pfd.events = cevents;
        if (poll(&pfd, 1, 1000) < 0)
		#endif
        {
            LOG_ERR("Poll failed");
            return -EINVAL;
        }
        if (pfd.revents == 0)
        {
            continue;
        }

        std::unique_lock<std::mutex> lock(smb2_mutex);
		auto result = smb2_service(smb2, pfd.revents);
        if (result < 0)
        {
            LOG_ERR("smb2_service failed with : %s\n", smb2_get_error(smb2));
            return result;
        }
    }

	return 0;
}

static int wrapper_getattr( const char *path,
                            fuse_stat *stbuf
                            #ifndef HAIKU
                            , struct fuse_file_info *fi
                            #endif
                            )
{
    #if DEBUG_STATS
    fnCounts[F_getattr]++;
    fnDoStats();
    #endif
    #ifndef HAIKU
    (void) fi;
    #endif

    auto full = full_path( path );
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0)
    {
        stbuf->st_mode = SMB_DIR | SMB_DIR_READ | SMB_DIR_WRITE;
        stbuf->st_nlink = 2;
        stbuf->st_uid = user_id;
        stbuf->st_gid = group_id;
		return 0;
    }    
	if( !path )
	{
		return -ENOENT;
	}

	#if CACHED_ATTR

		// For large folders, the numbers of getattr calls is huge. If each of them requires a
		// mostly synchronous client->server round trip it severaly limits the number of calls
		// of this function. This will hang the client (e.g. windows explorer).
		//
		// This code path attempts to cache the results in bulk via a call to readdir, and then
		// return getattr data from that cache.
		wrapper_readdir(parentFolder(path).c_str(),
						NULL,
						[](auto buf, auto name, auto stbuf, auto off
							#ifndef HAIKU
							, auto flags
							#endif
						)
						{
							return 0;
						},
						0,
						NULL
						#ifndef HAIKU
						, (fuse_readdir_flags)0
						#endif
						);

		auto ent = get_cache(full);
		if (!ent)
			return -ENOENT;

		if( !convert_stat( stbuf, &ent->e.st ) )
		{
			LOG_ERR( "convert_stat(%s) failed\n", CODE_REF, full.c_str() );
			return -EINVAL;
		}

	#else

		smb2_stat_64 s = {};
		smb2_cb_data data;

		#if ASYNC_LOCKING
			{
				std::unique_lock<std::mutex> lock(smb2_mutex);
				smb2_stat_async(
					smb2,
					full.c_str(),
					&s,
					[](auto smb2, auto status, auto command_data, auto cb_data)
					{
						auto data = (smb2_cb_data*)cb_data;
						data->finished = 1;
						data->status = status;
					},
					&data);
			}

			auto result = wait_loop(data);
			if (result < 0)
				return result;
		#else
			{
				std::unique_lock<std::mutex> lock(smb2_mutex);
				data.status = smb2_stat( smb2, full.c_str(), &s );
			}
		#endif

		if( -EACCES == data.status )
		{
			// For entries without permissions we create an empty stat record rather than ENOENT
			stbuf->st_mode = SMB_FILE;
			stbuf->st_uid = user_id;
			stbuf->st_gid = group_id;
			LOG_ERR( "smb2_stat(%s) failed: %i, %s", full.c_str(), data.status, smb2_get_error(smb2) );
			return 0;
		}
		else if( data.status )
		{
			LOG_ERR( "smb2_stat(%s) failed: %i, %s", full.c_str(), data.status, smb2_get_error(smb2) );
			return data.status;
		}

		if( !convert_stat( stbuf, &s ) )
		{
			LOG_ERR( "convert_stat(%s) failed\n", CODE_REF, full.c_str() );
			return -EINVAL;
		}
	
	#endif

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
    #if DEBUG_STATS
    fnCounts[F_readdir]++;
    fnDoStats();
    #endif

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

		#if CACHED_ATTR
		add_cache(full, ent);
		#endif

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
    #if DEBUG_STATS
    fnCounts[F_open]++;
    fnDoStats();
    #endif

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
    #if DEBUG_STATS
    fnCounts[F_read]++;
    fnDoStats();
    #endif

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
    #if DEBUG_STATS
    fnCounts[F_release]++;
	fnDoStats();
    #endif

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

clock_t getClock()
{
    return clock() / (CLOCKS_PER_SEC / 1000);
}

#if DEBUG_STATS
void fnDoStats()
{
    static clock_t ts = 0;
    auto now = getClock();
    if (now - ts >= 1000)
    {
        ts = now;
        printf("stats: attr=%i, open=%i, read=%i, rel=%i, readdir=%i\n",
            fnCounts[F_getattr], fnCounts[F_open], fnCounts[F_read], fnCounts[F_release], fnCounts[F_readdir]);
        memset(fnCounts, 0, sizeof(fnCounts));
    }
}
#endif

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
        smb2_fd_event_callbacks(smb2,
            [](struct smb2_context *smb2, t_socket fd, int cmd)
            {
                if (cmd == SMB2_ADD_FD) {
                        cfd = fd;
                }
                if (cmd == SMB2_DEL_FD) {
                        cfd = -1;
                }
            },
            [](struct smb2_context *smb2, t_socket fd, int events)
            {
                cevents = events;
            });

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

