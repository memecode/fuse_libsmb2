#include "fuse_libsmb2.h"

int wrapper_mkdir(const char *path, fuse_mode_t mode)
{
    #if DEBUG_STATS
    fnDoStats(F_mkdir);
    #endif

    auto full = full_path( path );
	smb2_cb_data data;

	{
		std::unique_lock<std::mutex> lock(smb2_mutex);
		auto result = smb2_mkdir_async(smb2, full.c_str(), generic_cb, &data);
	}

	auto result = wait_loop(data);
	if (result < 0)
		return result;

	return data.status;
}
