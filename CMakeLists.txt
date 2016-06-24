cmake_minimum_required(VERSION 2.6)

project(enet)

# The "configure" step.
include(CheckFunctionExists)
include(CheckStructHasMember)
include(CheckTypeSize)
check_function_exists("fcntl" HAS_FCNTL)
check_function_exists("poll" HAS_POLL)
check_function_exists("getaddrinfo" HAS_GETADDRINFO)
check_function_exists("getnameinfo" HAS_GETNAMEINFO)
check_function_exists("gethostbyname_r" HAS_GETHOSTBYNAME_R)
check_function_exists("gethostbyaddr_r" HAS_GETHOSTBYADDR_R)
check_function_exists("inet_pton" HAS_INET_PTON)
check_function_exists("inet_ntop" HAS_INET_NTOP)
check_struct_has_member("struct msghdr" "msg_flags" "sys/types.h;sys/socket.h" HAS_MSGHDR_FLAGS)
set(CMAKE_EXTRA_INCLUDE_FILES "sys/types.h" "sys/socket.h")
check_type_size("socklen_t" HAS_SOCKLEN_T BUILTIN_TYPES_ONLY)
unset(CMAKE_EXTRA_INCLUDE_FILES)
 
if(HAS_FCNTL)
    add_definitions(-DHAS_FCNTL=1)
endif()
if(HAS_POLL)
    add_definitions(-DHAS_POLL=1)
endif()
if(HAS_GETNAMEINFO)
    add_definitions(-DHAS_GETNAMEINFO=1)
endif()
if(HAS_GETADDRINFO)
    add_definitions(-DHAS_GETADDRINFO=1)
endif()
if(HAS_GETHOSTBYNAME_R)
    add_definitions(-DHAS_GETHOSTBYNAME_R=1)
endif()
if(HAS_GETHOSTBYADDR_R)
    add_definitions(-DHAS_GETHOSTBYADDR_R=1)
endif()
if(HAS_INET_PTON)
    add_definitions(-DHAS_INET_PTON=1)
endif()
if(HAS_INET_NTOP)
    add_definitions(-DHAS_INET_NTOP=1)
endif()
if(HAS_MSGHDR_FLAGS)
    add_definitions(-DHAS_MSGHDR_FLAGS=1)
endif()
if(HAS_SOCKLEN_T)
    add_definitions(-DHAS_SOCKLEN_T=1)
endif()
 
include_directories(${PROJECT_SOURCE_DIR}/include)

file(GLOB SRC_ALL
    "${CMAKE_CURRENT_SOURCE_DIR}/callbacks.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/compress.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/host.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/list.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/packet.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/peer.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/protocol.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/unix.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/win32.c"
)

file(GLOB HDR_ALL
    "${CMAKE_CURRENT_SOURCE_DIR}/include/enet/callbacks.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/enet/enet.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/enet/list.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/enet/protocol.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/enet/time.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/enet/types.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/enet/unix.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/enet/utility.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/enet/win32.h"
)

# Visual Studio specific (Filters / Source Groups)
source_group("Source Files" FILES ${SRC_ALL})
source_group("Header Files" FILES ${HDR_ALL})


add_library(enet STATIC
    ${SRC_ALL}
    ${HDR_ALL}
    )

install(TARGETS enet
    LIBRARY DESTINATION "lib"
    ARCHIVE DESTINATION "lib/static"
    )

install(DIRECTORY "include/"
    DESTINATION   "include"
    FILES_MATCHING PATTERN       "include/enet/*.h"
    )
