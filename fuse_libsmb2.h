#pragma once

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
#include <vector>

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
#define NOT_IMPL		-ENOSYS
#define CODE_REF		code_ref(__FILE__, __LINE__, __func__).c_str()
static std::string code_ref( const char *file, int line, const char *func );

#define LOG_DEBUG(...)	log_printf("DBG", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_INFO(...)	log_printf("INF", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_WARN(...)	log_printf("WRN", __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_ERR(...)	log_printf("ERR", __FILE__, __LINE__, __func__, __VA_ARGS__)
void log_printf(const char *type, const char *file, int line, const char *func, ...);

enum TFnType
{
    F_getattr,
    F_open,
    F_read,
    F_write,
    F_release,
    F_readdir,
    F_init,
	F_mkdir,
	F_rmdir,
	F_unlink,
	F_rename,
	F_truncate,
	
	F_Max
};
extern const char *fnTypeToString(TFnType type);
#if DEBUG_STATS
#define DEBUG_DO_STATS(type) fnDoStats(type)
extern void fnDoStats(TFnType type);
#else
#define DEBUG_DO_STATS(type)
#endif

#ifdef _WINDOWS

    #define DIR_CHAR            '\\'

    #define DEFAULT_USER_ID     0
    #define DEFAULT_GROUP_ID    0

    #define SMB_FILE            _S_IFREG
    #define SMB_LINK            _S_IFREG
    #define SMB_FILE_READ       _S_IREAD|0xb6 // 0444
    #define SMB_FILE_WRITE      _S_IWRITE|0xb6 // 0200
    #define SMB_DIR             _S_IFDIR
    #define SMB_DIR_READ		_S_IREAD |0xff // 0555
    #define SMB_DIR_WRITE       _S_IWRITE|0xff // 0200

    #define strcasecmp          stricmp

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

struct PathParts
{
	std::string folder, leaf;
};

struct smb2_cb_data
{
    bool finished = false;
    int status = 0;
};

// Global smb2 stuff:
extern smb2_context *smb2;
extern std::string smb2_path;
extern std::mutex smb2_mutex;
extern int user_id;
extern int group_id;
extern t_socket cfd;
extern int cevents;

// Utility functions
extern clock_t getClock();
extern std::string full_path(const char *path);
extern std::string code_ref(const char *file, int line, const char *func);
extern void log_printf(const char *type, const char *file, int line, const char *func, const char *fmt, ...);
extern PathParts splitPath(const std::string &path);

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
extern std::unordered_map<std::string, TDirVec> entryMap;
#endif

// Main functionality
extern int wait_loop(smb2_cb_data &data);
extern void generic_cb(struct smb2_context *smb2, int status, void *command_data, void *cb_data);

// Read operations
extern int wrapper_getattr(const char *path, fuse_stat *stbuf
                    #ifndef HAIKU
                    , struct fuse_file_info *fi
                    #endif
                    );
extern int wrapper_readdir(const char *path, void *buf, fuse_fill_dir_t filler, fuse_off_t offset, struct fuse_file_info *fi
                    #ifndef HAIKU
                    , enum fuse_readdir_flags flags 
                    #endif
                    );
extern int wrapper_open(const char *path, struct fuse_file_info *fi);
extern int wrapper_read(const char *path, char *buf, size_t size, fuse_off_t offset, struct fuse_file_info *fi);
extern int wrapper_release(const char *path, struct fuse_file_info *fi);

// Write operations
extern int wrapper_mkdir(const char *path, fuse_mode_t mode);
extern int wrapper_rmdir(const char *path);
extern int wrapper_unlink(const char *path);
extern int wrapper_rename(const char *oldpath, const char *newpath, unsigned int flags);
extern int wrapper_truncate(const char *path, fuse_off_t size, struct fuse3_file_info *fi);
extern int wrapper_write(const char *path, const char *buf, size_t size, fuse_off_t off, struct fuse3_file_info *fi);
