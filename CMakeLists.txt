project(vfs.smb)

cmake_minimum_required(VERSION 2.6)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})

enable_language(CXX)

find_package(LibSmbClient REQUIRED)
find_package(xbmc REQUIRED)
find_package(xbmcplatform REQUIRED)

include_directories(${XBMC_INCLUDE_DIR}
                    ${XBMCPLATFORM_INCLUDE_DIRS}
                    ${LIBSMBCLIENT_INCLUDE_DIRS})

set(SMB_SOURCES src/SMB.cpp
                src/SMBFile.cpp)

set(DEPLIBS ${LIBSMBCLIENT_LIBRARIES})

add_definitions(-D_LARGEFILE64_SOURCE
                -D_FILE_OFFSET_BITS=64
                -D__STDC_FORMAT_MACROS)

build_addon(vfs.smb SMB DEPLIBS)
