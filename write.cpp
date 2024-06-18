#include "fuse_libsmb2.h"
#include <functional>

int fn_template(TFnType type, std::function<int(smb2_cb_data*)> method)
{
    DEBUG_DO_STATS(type);

	smb2_cb_data data;

	{
		std::unique_lock<std::mutex> lock(smb2_mutex);
		auto result = method(&data);
		if (result < 0)
		{
			LOG_ERR("%s: method %s failed: %i\n", __FUNCTION__, fnTypeToString(type), result);
			return result;
		}
	}

	auto result = wait_loop(data);
	if (result < 0)
	{
		LOG_ERR("%s: wait_loop failed for %s: %i\n", __FUNCTION__, fnTypeToString(type), result);
		return result;
	}

	return data.status;
}

int wrapper_mkdir(const char *path, fuse_mode_t mode)
{
    return fn_template(	F_mkdir,
						[full=full_path(path)](auto data)
						{
							return smb2_mkdir_async(smb2, full.c_str(), generic_cb, data);
						});
}

int wrapper_rmdir(const char *path)
{
    return fn_template(	F_rmdir,
						[full=full_path(path)](auto data)
						{
							return smb2_rmdir_async(smb2, full.c_str(), generic_cb, data);
						});
}

int wrapper_unlink(const char *path)
{
    return fn_template(	F_unlink,
						[full=full_path(path)](auto data)
						{
							return smb2_unlink_async(smb2, full.c_str(), generic_cb, data);
						});
}

int wrapper_rename(const char *oldpath, const char *newpath, unsigned int flags)
{
    return fn_template(	F_rename,
						[from=full_path(oldpath), to=full_path(newpath), flags](auto data)
						{
							return smb2_rename_async(smb2, from.c_str(), to.c_str(), generic_cb, data);
						});
}

int wrapper_truncate(const char *path, fuse_off_t size, struct fuse3_file_info *fi)
{
    return fn_template(	F_truncate,
						[full=full_path(path), size](auto data)
						{
							return smb2_truncate_async(smb2, full.c_str(), size, generic_cb, data);
						});
}

int wrapper_write(const char *path, const char *buf, size_t size, fuse_off_t offset, struct fuse3_file_info *fi)
{
    DEBUG_DO_STATS(F_write);
    
    if( !fi )
    {
        LOG_ERR("no file info\n");
        return -EINVAL;
    }

    auto fh = (smb2fh*)fi->fh;
    if( !fh )
    {
        LOG_ERR("no file handle\n");
        return -EINVAL;
    }

	smb2_cb_data data;
	{
		std::unique_lock<std::mutex> lock(smb2_mutex);
		int result = smb2_pwrite_async(	smb2,
										fh,
										(uint8_t*) buf,
										size,
										offset, 
										generic_cb,
										&data);
		if (result < 0)
		{
			LOG_ERR("smb2_pwrite_async failed: %i\n", result);
			return result;
		}
	}

	auto result = wait_loop(data);
	if (result < 0)
		return result;

	return data.status;
}
