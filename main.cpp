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

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("--uri=%s", uri),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

static void *smb2_init(struct fuse_conn_info *conn,
			struct fuse_config *cfg)
{
	(void) conn;
	cfg->kernel_cache = 1;
	return NULL;
}

static bool convert_stat(struct stat *out, smb2_stat_64 *in)
{
	out->st_size = in->smb2_size;
	out->st_mtim.tv_sec = (time_t)in->smb2_mtime;
	out->st_atim.tv_sec = (time_t)in->smb2_atime;
	out->st_ctim.tv_sec = (time_t)in->smb2_ctime;
	// out->st_nlink = 1;

	switch (in->smb2_type)
	{
	case SMB2_TYPE_LINK:
		out->st_mode = S_IFLNK | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
		break;
	case SMB2_TYPE_FILE:
		out->st_mode = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
		break;
	case SMB2_TYPE_DIRECTORY:
		out->st_mode = S_IFDIR |
						S_IRUSR | S_IWUSR | S_IXUSR |
						S_IRGRP | S_IXGRP |
						S_IROTH | S_IXOTH;
		// out->st_nlink = 2;
		break;
	}

	out->st_uid = 1000;
	out->st_gid = 1000;

	return true;
}

static int smb2_getattr( const char *path,
						 struct stat *stbuf,
			 			 struct fuse_file_info *fi )
{
	(void) fi;

	std::string full = smb2_path + path;
	memset(stbuf, 0, sizeof(struct stat));

	if (strcmp(path, "/") == 0)
	{
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	}
	else if (path)
	{
		smb2_stat_64 s = {};
		if( smb2_stat(smb2, full.c_str() + 1, &s) )
		{
			printf( "%s: smb2_stat(%s) failed: %s\n", __func__, path, smb2_get_error(smb2) );
			return -ENOENT;
		}

		if( !convert_stat (stbuf, &s ) )
		{
			printf( "%s: convert_stat(%s) failed\n", __func__, path );
			return -EINVAL;
		}
	}

	return 0;
}

static int smb2_readdir(const char *path,
						void *buf,
						fuse_fill_dir_t filler,
			 			off_t offset,
						struct fuse_file_info *fi,
			 			enum fuse_readdir_flags flags)
{
    auto none = (fuse_fill_dir_flags)0;
	std::string full = smb2_path + path;

	if (!smb2)
	{
		printf("%s: no smb2.\n", __func__);
		return -ENOENT;
	}
	auto dir = smb2_opendir(smb2, full.c_str() + 1);
	if (dir == NULL)
	{
		printf("%s: smb2_opendir failed. %s\n", __func__, smb2_get_error(smb2));
		return -ENOENT;
	}

	filler(buf, ".", NULL, 0, none);
	filler(buf, "..", NULL, 0, none);

	smb2dirent *ent = nullptr;
	while ((ent = smb2_readdir(smb2, dir)))
	{
		struct stat st = {};
		convert_stat(&st, &ent->st);
		filler(	buf,
				ent->name,
				&st,
				0,
				none);

		if (ent->st.smb2_type == SMB2_TYPE_LINK)
		{
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

static int smb2_open(const char *path, struct fuse_file_info *fi)
{
	printf("smb2_open(%s)\n", path);

	// FIXME
	// if (strcmp(path+1, options.filename) != 0)
	//	return -ENOENT;

	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int smb2_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	size_t len;
	(void) fi;

	printf("smb2_read(%s)\n", path);

	/* FIXME
	if(strcmp(path+1, options.filename) != 0)
	 	return -ENOENT;

	len = strlen(options.contents);
	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, options.contents + offset, size);
	} else
	*/
		size = 0;

	return size;
}

static const struct fuse_operations smb2_ops = {
	.getattr	= smb2_getattr,
	.open		= smb2_open,
	.read		= smb2_read,
	.readdir	= smb2_readdir,
	.init		= smb2_init,
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

		printf("uri=%s\n", options.uri);
		if (url)
			printf("url domain:%s user:%s server:%s share:%s path:%s\n",
				url->domain,
				url->user,
				url->server,
				url->share,
				url->path);

		smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
		if (smb2_connect_share(smb2, url->server, url->share, url->user) < 0)
		{
			printf("smb2_connect_share failed. %s\n", smb2_get_error(smb2));
			return -1;
		}

		if (url->path)
			smb2_path = url->path;
	}

	printf("fuse_main starting...\n");
	ret = fuse_main( args.argc, args.argv, &smb2_ops, NULL );
	printf("fuse_main done.\n");
	fuse_opt_free_args( &args );
	return ret;
}
