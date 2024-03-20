
cmake_minimum_required(VERSION 3.12)
project(fuse_libssh2)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)

add_executable(fuse_libsmb2 main.cpp)
target_link_libraries(fuse_libsmb2
    PRIVATE
        fuse3
    PUBLIC
        smb2)

install(TARGETS fuse_libsmb2 EXPORT fuse_libsmb2
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib${LIB_SUFFIX}
        LIBRARY DESTINATION lib${LIB_SUFFIX})
