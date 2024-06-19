/*
  fuse_libsmb2: a user space filesystem using libsmb2 
*/
	
#include "fuse_libsmb2.h"

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

smb2_context *smb2 = nullptr;
std::string smb2_path;
std::mutex smb2_mutex;
int user_id = DEFAULT_USER_ID;
int group_id = DEFAULT_GROUP_ID;
t_socket cfd = -1;
int cevents = 0;

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("--uri=%s", uri),
    OPTION("--userId=%s", userId),
    OPTION("-h", show_help),
    OPTION("--help", show_help),
    FUSE_OPT_END
};

clock_t getClock()
{
    return clock() / (CLOCKS_PER_SEC / 1000);
}

std::string full_path(const char *path)
{
    std::string p = smb2_path + path;
    if (p[0] == '/')
        return p.substr(1);
    return p;
}

std::string code_ref( const char *file, int line, const char *func )
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
    DEBUG_DO_STATS(F_init);
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
    out->st_size = in->smb2_size;
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

int wait_loop(smb2_cb_data &data)
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

void generic_cb(struct smb2_context *smb2, int status, void *command_data, void *cb_data)
{
	auto data = (smb2_cb_data*)cb_data;
	data->finished = true;
	data->status = status;
}

int wrapper_getattr(const char *path,
                    fuse_stat *stbuf
                    #ifndef HAIKU
                    , struct fuse_file_info *fi
                    #endif
                    )
{
    DEBUG_DO_STATS(F_getattr);
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
		auto ent = get_cache(full);
		if (!ent)
		{
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

			ent = get_cache(full);
			if (!ent)
				return -ENOENT;
		}

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

int wrapper_readdir(const char *path,
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
    DEBUG_DO_STATS(F_readdir);

    #ifndef HAIKU
    auto none = (fuse_fill_dir_flags)0;
    #endif
    auto full = full_path( path );

    if (!smb2)
    {
        printf( "%s error: no smb2.\n", CODE_REF );
        return -ENOENT;
    }

	auto startTs = getClock();
	int entries = 0;
	#if CACHED_ATTR
	auto it = entryMap.find(full);
	if (it != entryMap.end())
	{
		for (auto &entry: it->second)
		{
			fuse_stat st = {};
			convert_stat(&st, &entry.e.st);
			filler(	buf,
					entry.e.name,
					&st,
					0
					#ifndef HAIKU
					, none
					#endif
					);
			entries++;
		}
	}
	else
	#endif
	{
		auto dir = smb2_opendir( smb2, full.c_str() );
		if (dir == NULL)
		{
			printf("%s error: smb2_opendir(%s) failed. %s\n", CODE_REF, path, smb2_get_error(smb2));
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
			entries++;

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
    
	}

	if (getClock() - startTs > 100)
		LOG_INFO("readdir:path=%s entries=%i time=%i", path, entries, (int)(getClock()-startTs));
    return 0;
}

#ifndef O_ACCMODE
#define O_ACCMODE (O_RDWR|O_WRONLY|O_RDONLY)
#endif /* !O_ACCMODE */

int wrapper_open( const char *path, struct fuse_file_info *fi)
{
    std::unique_lock<std::mutex> lock(smb2_mutex);
    DEBUG_DO_STATS(F_open);

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

int wrapper_read( const char *path,
                         char *buf,
                         size_t size,
                         fuse_off_t offset,
                         struct fuse_file_info *fi )
{
    DEBUG_DO_STATS(F_read);
    
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

	smb2_cb_data data;
	{
		std::unique_lock<std::mutex> lock(smb2_mutex);
		int result = smb2_pread_async(	smb2,
										fh,
										(uint8_t*) buf,
										size,
										offset, 
										[](auto smb2, auto status, auto command_data, auto cb_data)
										{
											auto data = (smb2_cb_data*)cb_data;
											data->finished = true;
											data->status = status;
										},
										&data);
		if (result < 0)
		{
			LOG_ERR("smb2_pread_async failed: %i\n", result);
			return result;
		}
	}

	auto result = wait_loop(data);
	if (result < 0)
		return result;

	return data.status;
}

int wrapper_release( const char *path, struct fuse_file_info *fi )
{
    std::unique_lock<std::mutex> lock(smb2_mutex);
    DEBUG_DO_STATS(F_release);

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

static const struct fuse_operations smb2_ops =
{	
    .getattr	= wrapper_getattr,
	.mkdir		= wrapper_mkdir,
	.unlink     = wrapper_unlink,
	.rmdir		= wrapper_rmdir,
	.rename		= wrapper_rename,
	.truncate	= wrapper_truncate,
    .open		= wrapper_open,
    .read		= wrapper_read,
    .release    = wrapper_release,
    .readdir	= wrapper_readdir,
    .init		= wrapper_init,
};

#if DEBUG_STATS
int fnCounts[F_Max] = {};
void fnDoStats(TFnType type)
{
    static clock_t ts = 0;
	fnCounts[type]++;
    auto now = getClock();
    if (now - ts >= 1000)
    {
        ts = now;
        printf("stats: attr=%i, open=%i, read=%i, rel=%i, dir=%i, mk=%i, rm=%i, un=%i, rename=%i, trun=%i\n",
            fnCounts[F_getattr], fnCounts[F_open], fnCounts[F_read], fnCounts[F_release], fnCounts[F_readdir],
			fnCounts[F_mkdir], fnCounts[F_rmdir], fnCounts[F_unlink], fnCounts[F_rename], fnCounts[F_truncate]);
        memset(fnCounts, 0, sizeof(fnCounts));
    }
}

const char *fnTypeToString(TFnType type)
{
	switch (type)
	{
		case F_getattr: return "getattr";
		case F_open:    return "open";
		case F_read:    return "read";
		case F_write:	return "write";
		case F_release: return "release";
		case F_readdir: return "readdir";
		case F_init:    return "init";
		case F_mkdir:   return "mkdir";
		case F_rmdir:   return "rmdir";
		case F_unlink:  return "unlink";
		case F_rename:  return "rename";
		case F_truncate: return "truncate";
	}
    return NULL;
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

	#if 0 // checking stat mode flags...
	struct _stat64 st;
	auto res = _stat64("P:\\Photos", &st);
	LOG_INFO("dir.flags=%x vs %x", st.st_mode, SMB_DIR | SMB_DIR_READ);
	res = _stat64("P:\\Photos\\aboveallelse.jpg", &st);
	LOG_INFO("file.flags=%x vs %x", st.st_mode, SMB_FILE | SMB_FILE_READ);
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

