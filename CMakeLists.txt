
cmake_minimum_required(VERSION 3.12)
project(fuse_libssh2)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set (CMAKE_CXX_STANDARD 14)

get_filename_component(LIBSMB2_DIR ${CMAKE_CURRENT_LIST_DIR}/../sahlberg-libsmb2 ABSOLUTE)
if (EXISTS ${LIBSMB2_DIR})
    # this is mostly for desktop development. It's nice to have a proper cmake target for libsmb2
    # but don't fail if the folder doesn't exist.
    add_subdirectory(${LIBSMB2_DIR} libsmb2)
else()
    # buildroot should have already built libsmb2 and fuse, the 2 dependencies of this code
    # these should be available in /usr/lib etc
endif()

add_executable(fuse_libsmb2 main.cpp)
if(WIN32)
	set(WIN_FSP "C:/Program Files (x86)/WinFsp")
	set(FUSE_LIB "${WIN_FSP}/lib/winfsp-x64.lib")
    target_include_directories(fuse_libsmb2
        PUBLIC
            "${WIN_FSP}/inc"
            ${LIBSMB2_DIR}/include)
else()
	set(FUSE_LIB "fuse3")
    target_include_directories(fuse_libsmb2 PUBLIC ${LIBSMB2_DIR}/include)
endif()
target_link_libraries(fuse_libsmb2
    PRIVATE
        ${FUSE_LIB}
    PUBLIC
        smb2)

install(TARGETS fuse_libsmb2 EXPORT fuse_libsmb2
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib${LIB_SUFFIX}
        LIBRARY DESTINATION lib${LIB_SUFFIX})
