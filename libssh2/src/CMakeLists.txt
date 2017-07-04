# Copyright (c) 2014 Alexander Lamaison <alexander.lamaison@gmail.com>
#
# Redistribution and use in source and binary forms,
# with or without modification, are permitted provided
# that the following conditions are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the following
#   disclaimer in the documentation and/or other materials
#   provided with the distribution.
#
#   Neither the name of the copyright holder nor the names
#   of any other contributors may be used to endorse or
#   promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.

include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckFunctionExistsMayNeedLibrary)
include(CheckIncludeFiles)
include(CheckTypeSize)
include(CheckSymbolExists)
include(CheckNonblockingSocketSupport)
include(SocketLibraries)

## Cryptography backend choice

set(CRYPTO_BACKEND
  ""
  CACHE
  STRING
  "The backend to use for cryptography: OpenSSL, Libgcrypt or WinCNG, mbedTLS
or empty to try any available")

# If the crypto backend was given, rather than searching for the first
# we are able to find, the find_package commands must abort configuration
# and report to the user.
if(CRYPTO_BACKEND)
  set(SPECIFIC_CRYPTO_REQUIREMENT REQUIRED)
endif()

if(CRYPTO_BACKEND STREQUAL "OpenSSL" OR NOT CRYPTO_BACKEND)

  find_package(OpenSSL ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(OPENSSL_FOUND)
    set(CRYPTO_BACKEND "OpenSSL")
    set(CRYPTO_SOURCES openssl.c openssl.h)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS LIBSSH2_OPENSSL)
    list(APPEND PRIVATE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
    list(APPEND LIBRARIES ${OPENSSL_LIBRARIES})
    list(APPEND PC_REQUIRES_PRIVATE libssl libcrypto)

    if (WIN32)
      # Statically linking to OpenSSL requires crypt32 for some Windows APIs.
      # This should really be handled by FindOpenSSL.cmake.
      list(APPEND LIBRARIES crypt32)
      list(APPEND PC_LIBS -lcrypt32)

      find_file(DLL_LIBEAY32
	NAMES libeay32.dll crypto.dll
        HINTS ${_OPENSSL_ROOT_HINTS} PATHS ${_OPENSSL_ROOT_PATHS}
        PATH_SUFFIXES bin)
      if (NOT DLL_LIBEAY32)
        message(WARNING
          "Unable to find OpenSSL libeay32 DLL, executables may not run")
      endif()

      find_file(DLL_SSLEAY32
        NAMES ssleay32.dll ssl.dll
        HINTS ${_OPENSSL_ROOT_HINTS} PATHS ${_OPENSSL_ROOT_PATHS}
        PATH_SUFFIXES bin)
      if (NOT DLL_SSLEAY32)
        message(WARNING
          "Unable to find OpenSSL ssleay32 DLL, executables may not run")
      endif()

      if(DLL_LIBEAY32 AND DLL_SSLEAY32)
        list(APPEND _RUNTIME_DEPENDENCIES ${DLL_LIBEAY32} ${DLL_SSLEAY32})
      endif()
    endif()

    # Not all OpenSSL have AES-CTR functions.
    set(SAVE_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
    check_function_exists(EVP_aes_128_ctr HAVE_EVP_AES_128_CTR)
    set(CMAKE_REQUIRED_LIBRARIES ${SAVE_CMAKE_REQUIRED_LIBRARIES})
  endif()
endif()

if(CRYPTO_BACKEND STREQUAL "Libgcrypt" OR NOT CRYPTO_BACKEND)

  find_package(Libgcrypt ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(LIBGCRYPT_FOUND)
    set(CRYPTO_BACKEND "Libgcrypt")
    set(CRYPTO_SOURCES libgcrypt.c libgcrypt.h)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS LIBSSH2_LIBGCRYPT)
    list(APPEND PRIVATE_INCLUDE_DIRECTORIES ${LIBGCRYPT_INCLUDE_DIRS})
    list(APPEND LIBRARIES ${LIBGCRYPT_LIBRARIES})
    list(APPEND PC_LIBS -lgcrypt)
  endif()
endif()

if(CRYPTO_BACKEND STREQUAL "WinCNG" OR NOT CRYPTO_BACKEND)

  # The check actually compiles the header.  This requires windows.h.
  check_include_files("windows.h;bcrypt.h" HAVE_BCRYPT_H)

  if(HAVE_BCRYPT_H)
    set(CRYPTO_BACKEND "WinCNG")
    set(CRYPTO_SOURCES wincng.c wincng.h)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS LIBSSH2_WINCNG)

    set(HAVE_LIBCRYPT32 TRUE)
    list(APPEND LIBRARIES bcrypt)
    list(APPEND PC_LIBS -lbcrypt)

    check_include_files(ntdef.h HAVE_NTDEF_H)
    check_include_files(ntstatus.h HAVE_NTSTATUS_H)

    # Reading keys from files is optional and depends on Wincrypt
    check_include_files("windows.h;wincrypt.h" HAVE_WINCRYPT_H)

    if(HAVE_WINCRYPT_H)
      list(APPEND LIBRARIES crypt32)
      list(APPEND PC_LIBS -lcrypt32)
    endif()

  elseif(${SPECIFIC_CRYPTO_REQUIREMENT} STREQUAL ${REQUIRED})
    message(FATAL_ERROR "WinCNG not available")
  endif()
endif()

if(CRYPTO_BACKEND STREQUAL "mbedTLS" OR NOT CRYPTO_BACKEND)

  find_package(mbedTLS ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(MBEDTLS_FOUND)
    set(CRYPTO_BACKEND "mbedTLS")
    set(CRYPTO_SOURCES mbedtls.c mbedtls.h)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS LIBSSH2_MBEDTLS)
    list(APPEND PRIVATE_INCLUDE_DIRECTORIES ${MBEDTLS_INCLUDE_DIR})
    list(APPEND LIBRARIES ${MBEDTLS_LIBRARIES})
    list(APPEND PC_LIBS -lmbedcrypto)
    link_directories(${MBEDTLS_LIBRARY_DIR})
  endif()
endif()

if(NOT CRYPTO_BACKEND)
  message(FATAL_ERROR "No suitable cryptography backend found.")
endif()

## Library definition

include(GNUInstallDirs)
set(SOURCES
  ${CRYPTO_SOURCES}
  agent.c
  channel.c
  channel.h
  comp.c
  comp.h
  crypt.c
  crypto.h
  global.c
  hostkey.c
  keepalive.c
  kex.c
  knownhost.c
  libssh2_priv.h
  mac.c
  mac.h
  misc.c
  misc.h
  packet.c
  packet.h
  pem.c
  publickey.c
  scp.c
  session.c
  session.h
  sftp.c
  sftp.h
  transport.c
  transport.h
  userauth.c
  userauth.h
  version.c)

if(WIN32)
  list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/win32/libssh2.rc)
endif()

add_library(libssh2 ${SOURCES})
# we want it to be called libssh2 on all platforms
set_target_properties(libssh2 PROPERTIES PREFIX "")

target_compile_definitions(libssh2 PRIVATE ${PRIVATE_COMPILE_DEFINITIONS})
target_include_directories(libssh2
  PRIVATE ${PRIVATE_INCLUDE_DIRECTORIES}
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>)

## Options

option(CLEAR_MEMORY "Enable clearing of memory before being freed" ON)
if(CLEAR_MEMORY)
    add_definitions(-DLIBSSH2_CLEAR_MEMORY)
endif(CLEAR_MEMORY)

add_feature_info("Shared library" BUILD_SHARED_LIBS
  "creating libssh2 as a shared library (.so/.dll)")

option(ENABLE_ZLIB_COMPRESSION "Use zlib for compression")
add_feature_info(Compression ENABLE_ZLIB_COMPRESSION
  "using zlib for compression")
if(ENABLE_ZLIB_COMPRESSION)
  find_package(ZLIB REQUIRED)

  target_include_directories(libssh2 PRIVATE ${ZLIB_INCLUDE_DIRS})
  list(APPEND LIBRARIES ${ZLIB_LIBRARIES})
  list(APPEND PC_REQUIRES_PRIVATE zlib)
  if(ZLIB_FOUND)
    target_compile_definitions(libssh2 PRIVATE LIBSSH2_HAVE_ZLIB=1)
  endif()
endif()

option(ENABLE_CRYPT_NONE "Permit \"none\" cipher -- NOT RECOMMENDED")
add_feature_info("\"none\" cipher" ENABLE_CRYPT_NONE "")
if(ENABLE_CRYPT_NONE)
  target_compile_definitions(libssh2 PRIVATE LIBSSH2_CRYPT_NONE=1)
endif()

option(ENABLE_MAC_NONE "Permit \"none\" MAC -- NOT RECOMMMENDED")
add_feature_info("\"none\" MAC" ENABLE_MAC_NONE "")
if(ENABLE_MAC_NONE)
  target_compile_definitions(libssh2 PRIVATE LIBSSH2_MAC_NONE=1)
endif()

option(ENABLE_GEX_NEW
  "Enable diffie-hellman-group-exchange-sha1 method" ON)
add_feature_info("diffie-hellman-group-exchange-sha1" ENABLE_GEX_NEW
  "\"new\" diffie-hellman-group-exchange-sha1 method")
if(ENABLE_GEX_NEW)
  target_compile_definitions(libssh2 PRIVATE LIBSSH2_DH_GEX_NEW=1)
endif()

# Enable debugging logging by default if the user configured a debug build
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(DEBUG_LOGGING_DEFAULT ON)
else()
  set(DEBUG_LOGGING_DEFAULT OFF)
endif()
option(ENABLE_DEBUG_LOGGING "log execution with debug trace"
  ${DEBUG_LOGGING_DEFAULT})
add_feature_info(Logging ENABLE_DEBUG_LOGGING
   "Logging of execution with debug trace")
if(ENABLE_DEBUG_LOGGING)
  target_compile_definitions(libssh2 PRIVATE LIBSSH2DEBUG)
endif()

## Platform checks
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(inttypes.h HAVE_INTTYPES_H)
check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(sys/select.h HAVE_SYS_SELECT_H)

check_include_files(sys/uio.h HAVE_SYS_UIO_H)
check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_files(sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_files(sys/time.h HAVE_SYS_TIME_H)
check_include_files(sys/un.h HAVE_SYS_UN_H)
check_include_files(windows.h HAVE_WINDOWS_H)
check_include_files(ws2tcpip.h HAVE_WS2TCPIP_H)
check_include_files(winsock2.h HAVE_WINSOCK2_H)

check_type_size("long long" LONGLONG)

if(HAVE_SYS_TIME_H)
  check_symbol_exists(gettimeofday sys/time.h HAVE_GETTIMEOFDAY)
else()
  check_function_exists(gettimeofday HAVE_GETTIMEOFDAY)
endif()
if(HAVE_STDLIB_H)
  check_symbol_exists(strtoll stdlib.h HAVE_STRTOLL)
else()
  check_function_exists(strtoll HAVE_STRTOLL)
endif()
if (NOT HAVE_STRTOLL)
  # Try _strtoi64 if strtoll isn't available
  check_symbol_exists(_strtoi64 stdlib.h HAVE_STRTOI64)
endif()
check_symbol_exists(snprintf stdio.h HAVE_SNPRINTF)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin" OR
   ${CMAKE_SYSTEM_NAME} STREQUAL "Interix")
  # poll() does not work on these platforms
  #
  # Interix: "does provide poll(), but the implementing developer must
  # have been in a bad mood, because poll() only works on the /proc
  # filesystem here"
  #
  # Mac OS X's poll has funny behaviors, like:
  # not being able to do poll on no fildescriptors (10.3?)
  # not being able to poll on some files (like anything in /dev)
  # not having reliable timeout support
  # inconsistent return of POLLHUP where other implementations give POLLIN
  message("poll use is disabled on this platform")
else()
  check_function_exists(poll HAVE_POLL)
endif()

append_needed_socket_libraries(LIBRARIES)

# Non-blocking socket support tests.  Must be after after library tests to
# link correctly
set(SAVE_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
set(CMAKE_REQUIRED_LIBRARIES ${LIBRARIES})
check_nonblocking_socket_support()
set(CMAKE_REQUIRED_LIBRARIES ${SAVE_CMAKE_REQUIRED_LIBRARIES})

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/libssh2_config_cmake.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/libssh2_config.h)
# to find generated header
target_include_directories(libssh2 PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

# Check for the OS.
# Daniel's note: this should not be necessary and we need to work to
# get this removed.
if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  target_compile_definitions(libssh2 PRIVATE LIBSSH2_WIN32)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
  target_compile_definitions(libssh2 PRIVATE LIBSSH2_DARWIN)
endif()

if(CMAKE_VERSION VERSION_LESS "2.8.12")
  # Fall back to over-linking dependencies
  target_link_libraries(libssh2 ${LIBRARIES})
else()
  target_link_libraries(libssh2 PRIVATE ${LIBRARIES})
endif()

## Installation

install(FILES
  ${PROJECT_SOURCE_DIR}/include/libssh2.h
  ${PROJECT_SOURCE_DIR}/include/libssh2_publickey.h
  ${PROJECT_SOURCE_DIR}/include/libssh2_sftp.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(TARGETS libssh2
  EXPORT Libssh2Config
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

if(BUILD_SHARED_LIBS)
  list(APPEND _RUNTIME_DEPENDENCIES $<TARGET_FILE:libssh2>)
endif()

set(RUNTIME_DEPENDENCIES ${_RUNTIME_DEPENDENCIES} CACHE INTERNAL
    "Files that must be in the same directory as the executables at runtime.")

# Package config

## During package installation, install Libssh2Config.cmake
install(EXPORT Libssh2Config
  NAMESPACE Libssh2::
  DESTINATION lib/cmake/libssh2)

## During build, register directly from build tree
# create Libssh2Config.cmake
export(TARGETS libssh2 NAMESPACE Libssh2:: FILE Libssh2Config.cmake)
export(PACKAGE Libssh2) # register it

## Export a .pc file for client projects not using CMaek
if(PC_REQUIRES_PRIVATE)
  string(REPLACE ";" "," PC_REQUIRES_PRIVATE "${PC_REQUIRES_PRIVATE}")
endif()
if(PC_LIBS)
  string(REPLACE ";" " " PC_LIBS "${PC_LIBS}")
endif()
configure_file(libssh2.pc.in libssh2.pc @ONLY)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/libssh2.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

## Versioning

set_target_properties(libssh2 PROPERTIES
  SOVERSION 1
  VERSION 1.0.1)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/Libssh2ConfigVersion.cmake
  VERSION "${LIBSSH2_VERSION_MAJOR}.${LIBSSH2_VERSION_MINOR}.${LIBSSH2_VERSION_PATCH}"
  COMPATIBILITY SameMajorVersion)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/Libssh2ConfigVersion.cmake
  DESTINATION lib/cmake/libssh2)
