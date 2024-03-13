if(WIN32)
    #
    # We need 3.12 or later, so that we can set policy CMP0074; see
    # below.
    cmake_minimum_required(VERSION 3.12)
else(WIN32)
    cmake_minimum_required(VERSION 2.8.6)
endif(WIN32)

#
# Apple doesn't build with an install_name starting with @rpath, and
# neither do we with autotools; don't do so with CMake, either, and
# suppress warnings about that.
#
if(POLICY CMP0042)
    cmake_policy(SET CMP0042 OLD)
endif()

#
# Squelch noise about quoted strings in if() statements.
# WE KNOW WHAT WE'RE DOING, WE'RE DOING EVERYTHING THE WAY THAT NEWER
# VERSIONS OF CMAKE EXPECT BY DEFAULT, DON'T WASTE OUR TIME WITH NOISE.
#
if(POLICY CMP0054)
    cmake_policy(SET CMP0054 NEW)
endif()

#
# We want find_file() and find_library() to honor {packagename}_ROOT,
# as that appears to be the only way, with the Visual Studio 2019 IDE
# and its CMake support, to tell CMake where to look for the Npcap
# or WinPcap SDK.
#
if(POLICY CMP0074)
    cmake_policy(SET CMP0074 NEW)
endif()

#
# We want check_include_file() to honor CMAKE_REQUIRED_LIBRARIES; see
# the big comment before the check_include_file() test for
# infiniband/verbs.h for the reason.
#
if(POLICY CMP0075)
    cmake_policy(SET CMP0075 NEW)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules)

#
# We only need a C++ compiler for Haiku; all code except for its
# pcap module is in C.
#
# We do that by specifying just C in the project() call and, after
# that finishes, checking for Haiku and, if we're building for
# Haiku, use enable_language() to check for C++.  This means that
# we don't require a C++ compiler on platforms other than Haiku.
#
# CMAKE_SYSTEM_NAME is set by project(), so we can't do this by
# testing CMAKE_SYSTEM_NAME and then passing different language
# lists to project() based on the system.
#
project(pcap C)

#
# For getting raw lists of --libs and --libs --static information from a
# pkg-config module.
#
# In CMake up to 2.8.12, pkg_check_modules() sets:
#
#    <XPREFIX>_LIBRARIES, which is a list of library names to which, on
#      a UN*X, -l can be prefixed - i.e., names, without extensions,
#      rather than full paths to the file.
#    <XPREFIX>_LIBRARY_DIRS, which is a list of paths to directories
#      containing the libraries, to which, on a UN*X, -L can be
#      prefixed.
#    <XPREFIX>_LDFLAGS, which is a list of *all* required linker flags
#    <XPREFIX>_LDFLAGS_OTHER, which is a list of all linker flags other
#      than -l and -L flags
#
# In 3.0 (at least as of 3.0.2), it also sets:
#
#    <XPREFIX>_LINK_LIBRARIES, which is a list of full paths to the
#      library files.
#
# but if <XPREFIX> is <PREFIX>_STATIC, <XPREFIX>_LINK_LIBRARIES is
# currently not set by CMake.
#
# Unfortunately, pkg_check_modules() sets the
# PKG_CONFIG_ALLOW_SYSTEM_LIBS environment variable when running
# pkg-config, so the output of --libs, etc. may include a -L for the
# system library, which we do *NOT* want to put in our libpcap.pc and
# pcap-config files.
#
# So we just run pkg-config ourselves, so that we get its output
# directly without any processing by CMake.
#
macro(pkg_get_link_info _prefix _package)
  if (PKG_CONFIG_EXECUTABLE)
    #
    # Get the --libs information.
    #
    # We force PKG_CONFIG_ALLOW_SYSTEM_LIBS to be undefined, as
    # at least some versions of CMake appear to define it in
    # pkg_check_modules() before running pkg-config and *not* undefine
    # it after running it.
    #
    unset(ENV{PKG_CONFIG_ALLOW_SYSTEM_LIBS})
    set(_pkg_config_result "")
    execute_process(
      COMMAND ${PKG_CONFIG_EXECUTABLE} "--libs" ${_package}
      OUTPUT_VARIABLE _pkg_config_result
      RESULT_VARIABLE _pkg_config_failed
      OUTPUT_STRIP_TRAILING_WHITESPACE)

    if (_pkg_config_failed)
      #
      # pkg-config failed; assume that means that there is no such
      # package for it to find.  XXX - what do we do here?
      #
      set(${_prefix}_FOUND_WITH_PKG_CONFIG FALSE)
    else()
      #
      # pkg-config succeeded; replace CR and LF with spaces.
      #
      string(REGEX REPLACE "[\r\n]" " " ${_prefix}_LIBS "${_pkg_config_result}")

      #
      # Now get the --libs --static information.
      #
      set(_pkg_config_result "")
      execute_process(
        COMMAND ${PKG_CONFIG_EXECUTABLE} "--libs" "--static" ${_package}
        OUTPUT_VARIABLE _pkg_config_result
        RESULT_VARIABLE _pkg_config_failed
        OUTPUT_STRIP_TRAILING_WHITESPACE)

      if (_pkg_config_failed)
        #
        # pkg-config failed; assume that means that there is no such
        # package for it to find.  XXX - what do we do here?
        #
        set(${_prefix}_FOUND_WITH_PKG_CONFIG FALSE)
      else()
        #
        # pkg-config succeeded; replace CR and LF with spaces.
        #
        string(REGEX REPLACE "[\r\n]" " " ${_prefix}_LIBS_STATIC "${_pkg_config_result}")

        #
        # List this package in its PACKAGE_NAME variable.
        #
        set(${_prefix}_PACKAGE_NAME "${_package}")

        #
        # It worked.
        #
        set(${_prefix}_FOUND_WITH_PKG_CONFIG TRUE)
      endif()
    endif()
  endif()
endmacro()

macro(get_link_info_from_library_path  _library_prefix _library_name)
  if(NOT ${_library_prefix}_LIBRARY STREQUAL "${_library_prefix}_LIBRARY-NOTFOUND")
    get_filename_component(_lib_directory "${${_library_prefix}_LIBRARY}}" DIRECTORY)

    #
    # The closest thing to a list of "system library directories" in
    # which the linker will, by default, search for libraries appears to
    # be CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES, so that's what we use
    # when we're trying to construct a -L argument, for insertion into
    # pcap-config and libpcap.pc, for a library upon which we depend.
    #
    # In some versions of CMake it appears to have duplicate entries,
    # but that shouldn't affect a search for a directory in that list.
    #
    list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${_lib_directory}" _lib_index)
    if(_lib_index EQUAL -1)
      #
      # No, so add a -L flag to get the linker to search in that
      # directory.
      #
      set(${_library_prefix}_LIBS "-L${_lib_directory}")
      set(${_library_prefix}_LIBS_STATIC "-L${_lib_directory}")
      set(${_libraryprefix}_LIBS_PRIVATE "-L${_lib_directory}")
    endif()
    set(${_library_prefix}_LIBS "${${_library_prefix}_LIBS} -l${_library_name}")
    set(${_library_prefix}_LIBS_STATIC "${${_library_prefix}_LIBS} -l${_library_name}")
    set(${_library_prefix}_LIBS_PRIVATE "${${_library_prefix}_LIBS} -l${_library_name}")
  endif()
endmacro()

if(CMAKE_SYSTEM_NAME STREQUAL "Haiku")
    enable_language(CXX)

    #
    # OK, this is a royal pain.
    #
    # CMake will try to determine the sizes of some data types, including
    # void *, early in the process of configuration; apparently, it's done
    # as part of processing the project() command.
    #
    # At least as of CMake 2.8.6, it does so by checking the size of
    # "void *" in C, setting CMAKE_C_SIZEOF_DATA_PTR based on that,
    # setting CMAKE_SIZEOF_VOID_P to that, and then checking the size
    # of "void *" in C++, setting CMAKE_CXX_SIZEOF_DATA_PTR based on
    # that, and then setting CMAKE_SIZEOF_VOID_P to *that*.
    #
    # The compile tests include whatever C flags may have been provided
    # to CMake in the CFLAGS and CXXFLAGS environment variables.
    #
    # If you set an architecture flag such as -m32 or -m64 in CFLAGS
    # but *not* in CXXFLAGS, the size for C++ will win, and hilarity
    # will ensue.
    #
    # Or if, at least on Solaris, you have a newer version of GCC
    # installed, but *not* a newer version of G++, and you have Oracle
    # Studio installed, it will find GCC, which will default to building
    # 64-bit, and Oracle Studio's C++ compiler, which will default to
    # building 32-bit, the size for C++ will win, and, again, hilarity
    # will ensue.
    #
    # So we make sure both languages have the same pointer sizes with
    # the flags they're given; if they don't, it means that the
    # compilers for the languages will, with those flags, not produce
    # code that can be linked together.
    #
    # This is unlikely to happen on Haiku, but it *has* happened on
    # Solaris; we do this for future-proofing, in case we ever need
    # C++ on a platform where that can happen.
    #
    if(NOT ${CMAKE_C_SIZEOF_DATA_PTR} EQUAL ${CMAKE_CXX_SIZEOF_DATA_PTR})
         message(FATAL_ERROR
"C compiler ${CMAKE_C_COMPILER} produces code with \
${CMAKE_C_SIZEOF_DATA_PTR}-byte pointers while C++ compiler \
${CMAKE_CXX_COMPILER} produces code with \
${CMAKE_CXX_SIZEOF_DATA_PTR}-byte pointers. \
This prevents code in these languages from being combined.")
    endif()
endif()

#
# Show the bit width for which we're compiling.
# This can help debug problems if you're dealing with a compiler that
# defaults to generating 32-bit code even when running on a 64-bit
# platform, and where that platform may provide only 64-bit versions of
# libraries that we might use (looking at *you*, Oracle Studio!).
#
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(STATUS "Building 32-bit")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(STATUS "Building 64-bit")
endif()

#
# Solaris pkg-config is annoying.  For at least one package (D-Bus, I'm
# looking at *you*!), there are separate include files for 32-bit and
# 64-bit builds (I guess using "unsigned long long" as a 64-bit integer
# type on a 64-bit build is like crossing the beams or soething), and
# there are two separate .pc files, so if we're doing a 32-bit build we
# should make sure we look in /usr/lib/pkgconfig for .pc files and if
# we're doing a 64-bit build we should make sure we look in
# /usr/lib/amd64/pkgconfig for .pc files.
#
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS" AND CMAKE_SYSTEM_VERSION MATCHES "5[.][0-9.]*")
    #
    # Note: string(REPLACE) does not appear to support using ENV{...}
    # as an argument, so we set a variable and then use set() to set
    # the environment variable.
    #
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        #
        # 64-bit build.  If /usr/lib/pkgconfig appears in the path,
        # prepend /usr/lib/amd64/pkgconfig to it; otherwise,
        # put /usr/lib/amd64 at the end.
        #
        if((NOT DEFINED ENV{PKG_CONFIG_PATH}) OR "$ENV{PKG_CONFIG_PATH}" EQUAL "")
            #
            # Not set, or empty.  Set it to /usr/lib/amd64/pkgconfig.
            #
            set(fixed_path "/usr/lib/amd64/pkgconfig")
        elseif("$ENV{PKG_CONFIG_PATH}" MATCHES "/usr/lib/pkgconfig")
            #
            # It contains /usr/lib/pkgconfig.  Prepend
            # /usr/lib/amd64/pkgconfig to /usr/lib/pkgconfig.
            #
            string(REPLACE "/usr/lib/pkgconfig"
                "/usr/lib/amd64/pkgconfig:/usr/lib/pkgconfig"
                fixed_path "$ENV{PKG_CONFIG_PATH}")
        else()
            #
            # Not empty, but doesn't contain /usr/lib/pkgconfig.
            # Append /usr/lib/amd64/pkgconfig to it.
            #
            set(fixed_path "$ENV{PKG_CONFIG_PATH}:/usr/lib/amd64/pkgconfig")
        endif()
        set(ENV{PKG_CONFIG_PATH} "${fixed_path}")
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
        #
        # 32-bit build.  If /usr/amd64/lib/pkgconfig appears in the path,
        # prepend /usr/lib/pkgconfig to it.
        #
        if("$ENV{PKG_CONFIG_PATH}" MATCHES "/usr/lib/amd64/pkgconfig")
            #
            # It contains /usr/lib/amd64/pkgconfig.  Prepend
            # /usr/lib/pkgconfig to /usr/lib/amd64/pkgconfig.
            #
            string(REPLACE "/usr/lib/amd64/pkgconfig"
                "/usr/lib/pkgconfig:/usr/lib/amd64/pkgconfig"
                fixed_path "$ENV{PKG_CONFIG_PATH}")
            set(ENV{PKG_CONFIG_PATH} "${fixed_path}")
        endif()
    endif()
endif()

include(CheckCCompilerFlag)

#
# For checking if a compiler flag works and adding it if it does.
#
macro(check_and_add_compiler_option _option)
    message(STATUS "Checking C compiler flag ${_option}")
    string(REPLACE "=" "-" _temp_option_variable ${_option})
    string(REGEX REPLACE "^-" "" _option_variable ${_temp_option_variable})
    check_c_compiler_flag("${_option}" ${_option_variable})
    if(${${_option_variable}})
        set(C_ADDITIONAL_FLAGS "${C_ADDITIONAL_FLAGS} ${_option}")
    endif()
endmacro()

#
# If we're building with Visual Studio, we require Visual Studio 2015,
# in order to get sufficient C99 compatibility.  Check for that.
#
# If not, try the appropriate flag for the compiler to enable C99
# features.
#
set(C_ADDITIONAL_FLAGS "")
if(MSVC)
    if(MSVC_VERSION LESS 1900)
        message(FATAL_ERROR "Visual Studio 2015 or later is required")
    endif()

    #
    # Treat source files as being in UTF-8 with MSVC if it's not using
    # the Clang front end.
    # We assume that UTF-8 source is OK with other compilers and with
    # MSVC if it's using the Clang front end.
    #
    if(NOT ${CMAKE_C_COMPILER} MATCHES "clang*")
        set(C_ADDITIONAL_FLAGS "${C_ADDITIONAL_FLAGS} /utf-8")
    endif(NOT ${CMAKE_C_COMPILER} MATCHES "clang*")
else(MSVC)
    #
    # For checking if a compiler flag works, failing if it doesn't,
    # and adding it otherwise.
    #
    macro(require_and_add_compiler_option _option)
        message(STATUS "Checking C compiler flag ${_option}")
        string(REPLACE "=" "-" _temp_option_variable ${_option})
        string(REGEX REPLACE "^-" "" _option_variable ${_temp_option_variable})
        check_c_compiler_flag("${_option}" ${_option_variable})
        if(${${_option_variable}})
            set(C_ADDITIONAL_FLAGS "${C_ADDITIONAL_FLAGS} ${_option}")
        else()
            message(FATAL_ERROR "C99 support is required, but the compiler doesn't support a compiler flag to enable it")
        endif()
    endmacro()

    #
    # Try to enable as many C99 features as we can.
    # At minimum, we want C++/C99-style // comments.
    #
    # Newer versions of compilers might default to supporting C99, but
    # older versions may require a special flag.
    #
    # Prior to CMake 3.1, setting CMAKE_C_STANDARD will not have any effect,
    # so, unless and until we require CMake 3.1 or later, we have to do it
    # ourselves on pre-3.1 CMake, so we just do it ourselves on all versions
    # of CMake.
    #
    # Note: with CMake 3.1 through 3.5, the only compilers for which CMake
    # handles CMAKE_C_STANDARD are GCC and Clang.  3.6 adds support only
    # for Intel C; 3.9 adds support for PGI C, Sun C, and IBM XL C, and
    # 3.10 adds support for Cray C and IAR C, but no version of CMake has
    # support for HP C.  Therefore, even if we use CMAKE_C_STANDARD with
    # compilers for which CMake supports it, we may still have to do it
    # ourselves on other compilers.
    #
    # See the CMake documentation for the CMAKE_<LANG>_COMPILER_ID variables
    # for a list of compiler IDs.
    #
    # XXX - this just tests whether the option works, fails if it doesn't,
    # and adds it if it does.  We don't test whether it's necessary in order
    # to get the C99 features that we use, or whether, if it's used, it
    # enables all the features that we require.
    #
    if(CMAKE_C_COMPILER_ID MATCHES "GNU" OR
       CMAKE_C_COMPILER_ID MATCHES "Clang")
        require_and_add_compiler_option("-std=gnu99")
    elseif(CMAKE_C_COMPILER_ID MATCHES "XL")
        #
        # We want support for extensions picked up for GNU C compatibility,
        # so we use -qlanglvl=extc99.
        #
        require_and_add_compiler_option("-qlanglvl=extc99")
    elseif(CMAKE_C_COMPILER_ID MATCHES "HP")
        require_and_add_compiler_option("-AC99")
    elseif(CMAKE_C_COMPILER_ID MATCHES "Sun")
        require_and_add_compiler_option("-xc99")
    elseif(CMAKE_C_COMPILER_ID MATCHES "Intel")
        require_and_add_compiler_option("-c99")
    endif()
endif(MSVC)

#
# If we're building with MinGW, we need to specify _WIN32_WINNT as
# 0x0600 ("NT 6.0", a/k/a Vista/Windows Server 2008) or higher
# in order to get the full IPv6 API, including inet_ntop(), and we
# need to specify it as 0x0601 ("NT 6.1", a/k/a Windows 7) or higher
# in order to get NdisMediumIP.
#
# NOTE: pcap does *NOT* work with msvcrt.dll; it must link with
# a newer version of the C library, i.e. Visual Studio 2015 or
# later, as it depends on C99 features introduced in VS 2015.
#
if(MINGW)
    add_definitions(-D_WIN32_WINNT=0x0601)
endif(MINGW)

#
# Build all runtimes in the top-level binary directory; that way,
# on Windows, the executables will be in the same directory as
# the DLLs, so the system will find pcap.dll when any of the
# executables are run.
#
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run)

###################################################################
#   Parameters
###################################################################

if(WIN32)
    #
    # On Windows, allow the library name to be overridden, for the
    # benefit of projects that combine libpcap with their own
    # kernel-mode code to support capturing.
    #
    set(LIBRARY_NAME pcap CACHE STRING "Library name")
else()
    #
    # On UN*X, it's always been libpcap.
    #
    set(LIBRARY_NAME pcap)
endif()

option(INET6 "Enable IPv6" ON)
if(WIN32)
    option(USE_STATIC_RT "Use static Runtime" ON)
endif(WIN32)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
set(dpdk_ROOT "" CACHE PATH "Path to directory with include and lib subdirectories for DPDK")
if(WIN32)
    set(Packet_ROOT "" CACHE PATH "Path to directory with include and lib subdirectories for packet.dll")
    set(AirPcap_ROOT "" CACHE PATH "Path to directory with include and lib subdirectories for airpcap.dll")
endif(WIN32)

option(ENABLE_PROFILING "Enable code profiling" OFF)

# To pacify those who hate the protochain instruction
option(NO_PROTOCHAIN "Disable protochain instruction" OFF)

#
# Start out with the capture mechanism type unspecified; the user
# can explicitly specify it and, if they don't, we'll pick an
# appropriate one.
#
set(PCAP_TYPE "" CACHE STRING "Packet capture type")

#
# Default to having remote capture support on Windows and, for now, to
# not having it on UN*X.
#
if(WIN32)
    option(ENABLE_REMOTE "Enable remote capture" ON)
else()
    option(ENABLE_REMOTE "Enable remote capture" OFF)
endif(WIN32)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    option(BUILD_WITH_LIBNL "Build with libnl" ON)
endif()

#
# Additional capture modules.
#
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    option(DISABLE_LINUX_USBMON "Disable Linux usbmon USB sniffing support" OFF)
endif()
option(DISABLE_BLUETOOTH "Disable Bluetooth sniffing support" OFF)
option(DISABLE_NETMAP "Disable netmap support" OFF)
option(DISABLE_DPDK "Disable DPDK support" OFF)

#
# We don't support D-Bus sniffing on macOS; see
#
# https://bugs.freedesktop.org/show_bug.cgi?id=74029
#
if(APPLE)
    option(DISABLE_DBUS "Disable D-Bus sniffing support" ON)
else(APPLE)
    option(DISABLE_DBUS "Disable D-Bus sniffing support" OFF)
endif(APPLE)
option(DISABLE_RDMA "Disable RDMA sniffing support" OFF)

option(DISABLE_DAG "Disable Endace DAG card support" OFF)

option(DISABLE_SEPTEL "Disable Septel card support" OFF)
set(SEPTEL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../septel" CACHE PATH "Path to directory with include and lib subdirectories for Septel API")

option(DISABLE_SNF "Disable Myricom SNF support" OFF)

option(DISABLE_TC "Disable Riverbed TurboCap support" OFF)

#
# Debugging options.
#
option(BDEBUG "Build optimizer debugging code" OFF)
option(YYDEBUG "Build parser debugging code" OFF)

###################################################################
#   Versioning
###################################################################

# Get, parse, format and set pcap's version string from [pcap_root]/VERSION
# for later use.

# Get MAJOR, MINOR, PATCH & SUFFIX
file(STRINGS ${pcap_SOURCE_DIR}/VERSION
    PACKAGE_VERSION
    LIMIT_COUNT 1 # Read only the first line
)

# Get "just" MAJOR
string(REGEX MATCH "^([0-9]+)" PACKAGE_VERSION_MAJOR "${PACKAGE_VERSION}")

# Get MAJOR, MINOR & PATCH
string(REGEX MATCH "^([0-9]+.)?([0-9]+.)?([0-9]+)" PACKAGE_VERSION_NOSUFFIX "${PACKAGE_VERSION}")

if(WIN32)
    # Convert PCAP_VERSION_NOSUFFIX to Windows preferred version format
    string(REPLACE "." "," PACKAGE_VERSION_PREDLL ${PACKAGE_VERSION_NOSUFFIX})

    # Append NANO (used for Windows internal versioning) to PCAP_VERSION_PREDLL
    # 0 means unused.
    set(PACKAGE_VERSION_DLL ${PACKAGE_VERSION_PREDLL},0)
endif(WIN32)

set(PACKAGE_NAME "${LIBRARY_NAME}")
set(PACKAGE_STRING "${LIBRARY_NAME} ${PACKAGE_VERSION}")

######################################
# Project settings
######################################

add_definitions(-DHAVE_CONFIG_H)

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${pcap_SOURCE_DIR}
)

include(CheckFunctionExists)
include(CMakePushCheckState)
include(CheckSymbolExists)

if(WIN32)

    if(IS_DIRECTORY ${CMAKE_HOME_DIRECTORY}/../../Common)
        include_directories(${CMAKE_HOME_DIRECTORY}/../../Common)
    endif(IS_DIRECTORY ${CMAKE_HOME_DIRECTORY}/../../Common)

    find_package(Packet)
    if(Packet_FOUND)
        set(HAVE_PACKET32 TRUE)
        include_directories(${Packet_INCLUDE_DIRS})
        #
        # Check whether we have the NPcap PacketIsLoopbackAdapter()
        # function.
        #
        cmake_push_check_state()
        set(CMAKE_REQUIRED_LIBRARIES ${Packet_LIBRARIES})
        check_function_exists(PacketIsLoopbackAdapter HAVE_PACKET_IS_LOOPBACK_ADAPTER)
        check_function_exists(PacketGetTimestampModes HAVE_PACKET_GET_TIMESTAMP_MODES)
        cmake_pop_check_state()
    endif(Packet_FOUND)

    message(STATUS "checking for Npcap's version.h")
    check_symbol_exists(WINPCAP_PRODUCT_NAME "${CMAKE_SOURCE_DIR}/../../version.h" HAVE_VERSION_H)
    if(HAVE_VERSION_H)
        message(STATUS "HAVE version.h")
    else(HAVE_VERSION_H)
        message(STATUS "MISSING version.h")
    endif(HAVE_VERSION_H)

endif(WIN32)

if(MSVC)
    add_definitions(-D__STDC__)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif(MSVC)

if(USE_STATIC_RT)
    message(STATUS "Use STATIC runtime")
        if(MSVC)
            foreach(RT_FLAG
                CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
                CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
                CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
                CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
                string(REGEX REPLACE "/MD" "/MT" ${RT_FLAG} "${${RT_FLAG}}")
            endforeach(RT_FLAG)
        elseif(MINGW)
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc")
        endif()
else (USE_STATIC_RT)
    message(STATUS "Use DYNAMIC runtime")
endif(USE_STATIC_RT)

###################################################################
#   Detect available platform features
###################################################################

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckStructHasMember)
include(CheckTypeSize)

#
# Tests are a bit expensive with Visual Studio on Windows, so, on
# Windows, we skip tests for UN*X-only headers and functions.
#

#
# Header files.
#
check_include_file(inttypes.h HAVE_INTTYPES_H)
check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(unistd.h HAVE_UNISTD_H)
if(NOT HAVE_UNISTD_H)
    add_definitions(-DYY_NO_UNISTD_H)
endif(NOT HAVE_UNISTD_H)
check_include_file(bitypes.h HAVE_SYS_BITYPES_H)
if(NOT WIN32)
    check_include_file(sys/ioccom.h HAVE_SYS_IOCCOM_H)
    check_include_file(sys/sockio.h HAVE_SYS_SOCKIO_H)
    check_include_file(sys/select.h HAVE_SYS_SELECT_H)

    check_include_file(netpacket/packet.h HAVE_NETPACKET_PACKET_H)
    check_include_file(netinet/if_ether.h HAVE_NETINET_IF_ETHER_H)
endif(NOT WIN32)

#
# Functions.
#
# First, check for the __atomic_load_n() and __atomic_store_n()
# builtins.
#
# We can't use check_function_exists(), as it tries to declare
# the function, and attempting to declare a compiler builtin
# can produce an error.
#
# We don't use check_symbol_exists(), as it expects a header
# file to be specified to declare the function, but there isn't
# such a header file.
#
# So we use check_c_source_compiles().
#
check_c_source_compiles(
"int
main(void)
{
	int i = 17;
	return __atomic_load_n(&i, __ATOMIC_RELAXED);
}
"
            HAVE___ATOMIC_LOAD_N)
check_c_source_compiles(
"int
main(void)
{
	int i;
	__atomic_store_n(&i, 17, __ATOMIC_RELAXED);
	return 0;
}
"
            HAVE___ATOMIC_STORE_N)

#
# Now check for various system functions.
#
check_function_exists(strerror HAVE_STRERROR)
check_function_exists(strerror_r HAVE_STRERROR_R)
if(HAVE_STRERROR_R)
    #
    # We have strerror_r; if we define _GNU_SOURCE, is it a
    # POSIX-compliant strerror_r() or a GNU strerror_r()?
    #
    check_c_source_compiles(
"#define _GNU_SOURCE
#include <string.h>

/* Define it GNU-style; that will cause an error if it's not GNU-style */
extern char *strerror_r(int, char *, size_t);

int
main(void)
{
	return 0;
}
"
            HAVE_GNU_STRERROR_R)
    if(NOT HAVE_GNU_STRERROR_R)
        set(HAVE_POSIX_STRERROR_R YES)
    endif(NOT HAVE_GNU_STRERROR_R)
else(HAVE_STRERROR_R)
    #
    # We don't have strerror_r; do we have _wcserror_s?
    #
    check_function_exists(_wcserror_s HAVE__WCSERROR_S)
endif(HAVE_STRERROR_R)

#
# Make sure we have vsnprintf() and snprintf(); we require them.
# We use check_symbol_exists(), as they aren't necessarily external
# functions - in Visual Studio, for example, they're inline functions
# calling a common external function.
#
check_symbol_exists(vsnprintf "stdio.h" HAVE_VSNPRINTF)
if(NOT HAVE_VSNPRINTF)
    message(FATAL_ERROR "vsnprintf() is required but wasn't found")
endif(NOT HAVE_VSNPRINTF)
check_symbol_exists(snprintf "stdio.h" HAVE_SNPRINTF)
if(NOT HAVE_SNPRINTF)
    message(FATAL_ERROR "snprintf() is required but wasn't found")
endif()

check_function_exists(strlcpy HAVE_STRLCPY)
check_function_exists(strlcat HAVE_STRLCAT)
check_function_exists(asprintf HAVE_ASPRINTF)
check_function_exists(vasprintf HAVE_VASPRINTF)
check_function_exists(strtok_r HAVE_STRTOK_R)
if(NOT WIN32)
    check_function_exists(vsyslog HAVE_VSYSLOG)
endif()

#
# These tests are for network applications that need socket functions
# and getaddrinfo()/getnameinfo()-ish functions.  We now require
# getaddrinfo() and getnameinfo().  On UN*X systems, we also prefer
# versions of recvmsg() that conform to the Single UNIX Specification,
# so that we can check whether a datagram received with recvmsg() was
# truncated when received due to the buffer being too small.
#
# On Windows, getaddrinfo() is in the ws2_32 library.

# On most UN*X systems, they're available in the system library.
#
# Under Solaris, we need to link with libsocket and libnsl to get
# getaddrinfo() and getnameinfo() and, if we have libxnet, we need to
# link with libxnet before libsocket to get a version of recvmsg()
# that conforms to the Single UNIX Specification.
#
# We use getaddrinfo() because we want a portable thread-safe way
# of getting information for a host name or port; there exist _r
# versions of gethostbyname() and getservbyname() on some platforms,
# but not on all platforms.
#
# NOTE: if you hand check_library_exists as its last argument a variable
# that's been set, it skips the test, so we need different variables.
#
set(PCAP_LINK_LIBRARIES "")
set(LIBS "")
set(LIBS_STATIC "")
set(REQUIRES_PRIVATE "")
set(LIBS_PRIVATE "")
include(CheckLibraryExists)
if(WIN32)
    #
    # We need winsock2.h and ws2tcpip.h.
    #
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES ws2_32)
    check_symbol_exists(getaddrinfo "winsock2.h;ws2tcpip.h" LIBWS2_32_HAS_GETADDRINFO)
    cmake_pop_check_state()
    if(LIBWS2_32_HAS_GETADDRINFO)
        set(PCAP_LINK_LIBRARIES ws2_32 ${PCAP_LINK_LIBRARIES})
    else(LIBWS2_32_HAS_GETADDRINFO)
        message(FATAL_ERROR "getaddrinfo is required, but wasn't found")
    endif(LIBWS2_32_HAS_GETADDRINFO)
else(WIN32)
    #
    # UN*X.  First try the system libraries, then try the libraries
    # for Solaris and possibly other systems that picked up the
    # System V library split.
    #
    check_function_exists(getaddrinfo STDLIBS_HAVE_GETADDRINFO)
    if(NOT STDLIBS_HAVE_GETADDRINFO)
        #
        # Not found in the standard system libraries.
        # Try libsocket, which requires libnsl.
        #
        cmake_push_check_state()
        set(CMAKE_REQUIRED_LIBRARIES nsl)
        check_library_exists(socket getaddrinfo "" LIBSOCKET_HAS_GETADDRINFO)
        cmake_pop_check_state()
        if(LIBSOCKET_HAS_GETADDRINFO)
            #
            # OK, we found it in libsocket.
            #
            set(PCAP_LINK_LIBRARIES socket nsl ${PCAP_LINK_LIBRARIES})
            set(LIBS "-lsocket -lnsl ${LIBS}")
            set(LIBS_STATIC "-lsocket -lnsl ${LIBS_STATIC}")
            set(LIBS_PRIVATE "-lsocket -lnsl ${LIBS_PRIVATE}")
        else(LIBSOCKET_HAS_GETADDRINFO)
            check_library_exists(network getaddrinfo "" LIBNETWORK_HAS_GETADDRINFO)
            if(LIBNETWORK_HAS_GETADDRINFO)
                #
                # OK, we found it in libnetwork (Haiku).
                #
                set(PCAP_LINK_LIBRARIES network ${PCAP_LINK_LIBRARIES})
                set(LIBS "-lnetwork ${LIBS}")
                set(LIBS_STATIC "-lnetwork ${LIBS_STATIC}")
                set(LIBS_PRIVATE "-lnetwork ${LIBS_PRIVATE}")
            else(LIBNETWORK_HAS_GETADDRINFO)
                #
                # We didn't find it.
                #
                message(FATAL_ERROR "getaddrinfo is required, but wasn't found")
            endif(LIBNETWORK_HAS_GETADDRINFO)
        endif(LIBSOCKET_HAS_GETADDRINFO)

        #
        # OK, do we have recvmsg() in libxnet?
        # We also link with libsocket and libnsl.
        #
        cmake_push_check_state()
        set(CMAKE_REQUIRED_LIBRARIES socket nsl)
        check_library_exists(xnet recvmsg "" LIBXNET_HAS_RECVMSG)
        cmake_pop_check_state()
        if(LIBXNET_HAS_RECVMSG)
            #
            # Yes - link with it as well.
            #
            set(PCAP_LINK_LIBRARIES xnet ${PCAP_LINK_LIBRARIES})
            set(LIBSC "-lxnet ${LIBS_LIBS}")
            set(LIBS_STATIC "-lxnet ${LIBS_STATIC}")
            set(LIBS_PRIVATE "-lxnet ${LIBS_PRIVATE}")
        endif(LIBXNET_HAS_RECVMSG)
    endif(NOT STDLIBS_HAVE_GETADDRINFO)

    # DLPI needs putmsg under HPUX so test for -lstr while we're at it
    check_function_exists(putmsg STDLIBS_HAVE_PUTMSG)
    if(NOT STDLIBS_HAVE_PUTMSG)
        check_library_exists(str putmsg "" LIBSTR_HAS_PUTMSG)
        if(LIBSTR_HAS_PUTMSG)
            set(PCAP_LINK_LIBRARIES str ${PCAP_LINK_LIBRARIES})
            set(LIBS "-lstr ${LIBS}")
            set(LIBS_STATIC "-lstr ${LIBS_STATIC}")
            set(LIBS_PRIVATE "-lstr ${LIBS_PRIVATE}")
        endif(LIBSTR_HAS_PUTMSG)
    endif(NOT STDLIBS_HAVE_PUTMSG)

    # Haiku has getpass in libbsd
    check_function_exists(getpass STDLIBS_HAVE_GETPASS)
    if(NOT STDLIBS_HAVE_GETPASS)
        check_library_exists(bsd getpass "" LIBBSD_HAS_GETPASS)
        if(LIBBSD_HAS_GETPASS)
            set(PCAP_LINK_LIBRARIES bsd ${PCAP_LINK_LIBRARIES})
        endif(LIBBSD_HAS_GETPASS)
    endif(NOT STDLIBS_HAVE_GETPASS)
endif(WIN32)

#
# Check for reentrant versions of getnetbyname_r(), as provided by
# Linux (glibc), Solaris/IRIX, and AIX (with three different APIs!).
# If we don't find one, we just use getnetbyname(), which uses
# thread-specific data on many platforms, but doesn't use it on
# NetBSD or OpenBSD, and may not use it on older versions of other
# platforms.
#
# Only do the check if we have a declaration of getnetbyname_r();
# without it, we can't check which API it has.  (We assume that
# if there's a declaration, it has a prototype, so that the API
# can be checked.)
#
cmake_push_check_state()
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LINK_LIBRARIES})
check_symbol_exists(getnetbyname_r netdb.h NETDB_H_DECLARES_GETNETBYNAME_R)
if(NETDB_H_DECLARES_GETNETBYNAME_R)
    check_c_source_compiles(
"#include <netdb.h>

int
main(void)
{
    struct netent netent_buf;
    char buf[1024];
    struct netent *resultp;
    int h_errnoval;

    return getnetbyname_r((const char *)0, &netent_buf, buf, sizeof buf, &resultp, &h_errnoval);
}
"
        HAVE_LINUX_GETNETBYNAME_R)
    if(NOT HAVE_LINUX_GETNETBYNAME_R)
        check_c_source_compiles(
"#include <netdb.h>

int
main(void)
{
    struct netent netent_buf;
    char buf[1024];

    return getnetbyname_r((const char *)0, &netent_buf, buf, (int)sizeof buf) != NULL;
}
"
            HAVE_SOLARIS_IRIX_GETNETBYNAME_R)
        if(NOT HAVE_SOLARIS_IRIX_GETNETBYNAME_R)
            check_c_source_compiles(
"#include <netdb.h>

int
main(void)
{
    struct netent netent_buf;
    struct netent_data net_data;

    return getnetbyname_r((const char *)0, &netent_buf, &net_data);
}
"
                HAVE_AIX_GETNETBYNAME_R)
        endif(NOT HAVE_SOLARIS_IRIX_GETNETBYNAME_R)
    endif(NOT HAVE_LINUX_GETNETBYNAME_R)
endif(NETDB_H_DECLARES_GETNETBYNAME_R)
cmake_pop_check_state()

#
# Check for reentrant versions of getprotobyname_r(), as provided by
# Linux (glibc), Solaris/IRIX, and AIX (with three different APIs!).
# If we don't find one, we just use getprotobyname(), which uses
# thread-specific data on many platforms, but doesn't use it on
# NetBSD or OpenBSD, and may not use it on older versions of other
# platforms.
#
# Only do the check if we have a declaration of getprotobyname_r();
# without it, we can't check which API it has.  (We assume that
# if there's a declaration, it has a prototype, so that the API
# can be checked.)
#
cmake_push_check_state()
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LINK_LIBRARIES})
check_symbol_exists(getprotobyname_r netdb.h NETDB_H_DECLARES_GETPROTOBYNAME_R)
if(NETDB_H_DECLARES_GETPROTOBYNAME_R)
    check_c_source_compiles(
"#include <netdb.h>

int
main(void)
{
    struct protoent protoent_buf;
    char buf[1024];
    struct protoent *resultp;

    return getprotobyname_r((const char *)0, &protoent_buf, buf, sizeof buf, &resultp);
}
"
        HAVE_LINUX_GETPROTOBYNAME_R)
    if(NOT HAVE_LINUX_GETPROTOBYNAME_R)
        check_c_source_compiles(
"#include <netdb.h>

int
main(void)
{
    struct protoent protoent_buf;
    char buf[1024];

    return getprotobyname_r((const char *)0, &protoent_buf, buf, (int)sizeof buf) != NULL;
}
"
            HAVE_SOLARIS_IRIX_GETPROTOBYNAME_R)
        if(NOT HAVE_SOLARIS_IRIX_GETPROTOBYNAME_R)
            check_c_source_compiles(
"#include <netdb.h>

int
main(void)
{
    struct protoent protoent_buf;
    struct protoent_data proto_data;

    return getprotobyname_r((const char *)0, &protoent_buf, &proto_data);
}
"
                HAVE_AIX_GETPROTOBYNAME_R)
        endif(NOT HAVE_SOLARIS_IRIX_GETPROTOBYNAME_R)
    endif(NOT HAVE_LINUX_GETPROTOBYNAME_R)
endif(NETDB_H_DECLARES_GETPROTOBYNAME_R)
cmake_pop_check_state()

#
# Data types.
#
# XXX - there's no check_type() macro that's like check_type_size()
# except that it only checks for the existence of the structure type,
# so we use check_type_size() and ignore the size.
#
cmake_push_check_state()
if(WIN32)
    set(CMAKE_EXTRA_INCLUDE_FILES winsock2.h)
else(WIN32)
    set(CMAKE_EXTRA_INCLUDE_FILES unistd.h sys/socket.h)
endif(WIN32)
check_type_size("struct sockaddr_storage" STRUCT_SOCKADDR_STORAGE)
check_type_size("socklen_t" SOCKLEN_T)
cmake_pop_check_state()

#
# Structure fields.
#
if(WIN32)
    check_struct_has_member("struct sockaddr" sa_len winsock2.h HAVE_STRUCT_SOCKADDR_SA_LEN)
else(WIN32)
    check_struct_has_member("struct sockaddr" sa_len sys/socket.h HAVE_STRUCT_SOCKADDR_SA_LEN)
endif(WIN32)

#
# Do we have ffs(), and is it declared in <strings.h>?
#
check_function_exists(ffs HAVE_FFS)
if(HAVE_FFS)
    #
    # OK, we have ffs().  Is it declared in <strings.h>?
    #
    # This test fails if we don't have <strings.h> or if we do
    # but it doesn't declare ffs().
    #
    check_symbol_exists(ffs strings.h STRINGS_H_DECLARES_FFS)
endif()

#
# This requires the libraries that we require, as ether_hostton might be
# in one of those libraries.  That means we have to do this after
# we check for those libraries.
#
# You are in a twisty little maze of UN*Xes, all different.
# Some might not have ether_hostton().
# Some might have it and declare it in <net/ethernet.h>.
# Some might have it and declare it in <netinet/ether.h>
# Some might have it and declare it in <sys/ethernet.h>.
# Some might have it and declare it in <arpa/inet.h>.
# Some might have it and declare it in <netinet/if_ether.h>.
# Some might have it and not declare it in any header file.
#
# Before you is a C compiler.
#
cmake_push_check_state()
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LINK_LIBRARIES})
check_function_exists(ether_hostton HAVE_ETHER_HOSTTON)
if(HAVE_ETHER_HOSTTON)
    #
    # OK, we have ether_hostton().  Is it declared in <net/ethernet.h>?
    #
    # This test fails if we don't have <net/ethernet.h> or if we do
    # but it doesn't declare ether_hostton().
    #
    check_symbol_exists(ether_hostton net/ethernet.h NET_ETHERNET_H_DECLARES_ETHER_HOSTTON)
    if(NET_ETHERNET_H_DECLARES_ETHER_HOSTTON)
        #
        # Yes - we have it declared.
        #
        set(HAVE_DECL_ETHER_HOSTTON TRUE)
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_HOSTTON)
        #
        # No - how about <netinet/ether.h>, as on Linux?
        #
        # This test fails if we don't have <netinet/ether.h>
        # or if we do but it doesn't declare ether_hostton().
        #
        check_symbol_exists(ether_hostton netinet/ether.h NETINET_ETHER_H_DECLARES_ETHER_HOSTTON)
        if(NETINET_ETHER_H_DECLARES_ETHER_HOSTTON)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_HOSTTON TRUE)
        endif()
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_HOSTTON)
        #
        # No - how about <sys/ethernet.h>, as on Solaris 10 and later?
        #
        # This test fails if we don't have <sys/ethernet.h>
        # or if we do but it doesn't declare ether_hostton().
        #
        check_symbol_exists(ether_hostton sys/ethernet.h SYS_ETHERNET_H_DECLARES_ETHER_HOSTTON)
        if(SYS_ETHERNET_H_DECLARES_ETHER_HOSTTON)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_HOSTTON TRUE)
        endif()
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_HOSTTON)
        #
        # No, how about <arpa/inet.h>, as on AIX?
        #
        # This test fails if we don't have <arpa/inet.h>
        # or if we do but it doesn't declare ether_hostton().
        #
        check_symbol_exists(ether_hostton arpa/inet.h ARPA_INET_H_DECLARES_ETHER_HOSTTON)
        if(ARPA_INET_H_DECLARES_ETHER_HOSTTON)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_HOSTTON TRUE)
        endif()
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_HOSTTON)
        #
        # No, how about <netinet/if_ether.h>?
        # On some platforms, it requires <net/if.h> and
        # <netinet/in.h>, and we always include it with
        # both of them, so test it with both of them.
        #
        # This test fails if we don't have <netinet/if_ether.h>
        # and the headers we include before it, or if we do but
        # <netinet/if_ether.h> doesn't declare ether_hostton().
        #
        check_symbol_exists(ether_hostton "sys/types.h;sys/socket.h;net/if.h;netinet/in.h;netinet/if_ether.h" NETINET_IF_ETHER_H_DECLARES_ETHER_HOSTTON)
        if(NETINET_IF_ETHER_H_DECLARES_ETHER_HOSTTON)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_HOSTTON TRUE)
        endif()
    endif()
    #
    # After all that, is ether_hostton() declared?
    #
    if(NOT HAVE_DECL_ETHER_HOSTTON)
        #
        # No, we'll have to declare it ourselves.
        # Do we have "struct ether_addr" if we include <netinet/if_ether.h>?
        #
        # XXX - there's no check_type() macro that's like check_type_size()
        # except that it only checks for the existence of the structure type,
        # so we use check_type_size() and ignore the size.
        #
        cmake_push_check_state()
        set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h sys/socket.h net/if.h netinet/in.h netinet/if_ether.h)
        check_type_size("struct ether_addr" STRUCT_ETHER_ADDR)
        cmake_pop_check_state()
    endif()
endif()
cmake_pop_check_state()

#
# Large file support on UN*X, a/k/a LFS.
#
if(NOT WIN32)
  include(FindLFS)
  if(LFS_FOUND)
    #
    # Add the required #defines.
    #
    add_definitions(${LFS_DEFINITIONS})
  endif()

  #
  # Check for fseeko as well.
  #
  include(FindFseeko)
  if(FSEEKO_FOUND)
    set(HAVE_FSEEKO ON)

    #
    # Add the required #defines.
    #
    add_definitions(${FSEEKO_DEFINITIONS})
  endif()
endif()

if(INET6)
    message(STATUS "Support IPv6")
endif(INET6)

#
# Pthreads.
# We might need them, because some libraries we use might use them,
# but we don't necessarily need them.
# That's only on UN*X; on Windows, if they use threads, we assume
# they're native Windows threads.
#
if(NOT WIN32)
  set(CMAKE_THREAD_PREFER_PTHREAD ON)
  find_package(Threads)
  if(NOT CMAKE_USE_PTHREADS_INIT)
    #
    # If it's not pthreads, we won't use it; we use it for libraries
    # that require it.
    #
    set(CMAKE_THREAD_LIBS_INIT "")
  endif(NOT CMAKE_USE_PTHREADS_INIT)
endif(NOT WIN32)

if(ENABLE_PROFILING)
    if(NOT MSVC)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
    endif()
endif()

#
# Based on
#
#    https://github.com/commonmark/cmark/blob/master/FindAsan.cmake
#
# The MIT License (MIT)
#
# Copyright (c) 2013 Matthew Arsenault
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# Test if the each of the sanitizers in the ENABLE_SANITIZERS list are
# supported by the compiler, and, if so, adds the appropriate flags to
# CMAKE_C_FLAGS, CMAKE_CXX_FLAGS, and SANITIZER_FLAGS.  If not, it fails.
#
# Do this last, in the hope that it will prevent configuration on Linux
# from somehow deciding it doesn't need -lpthread when building rpcapd
# (it does require it, but somehow, in some mysterious fashion that no
# obvious CMake debugging flag reveals, it doesn't realize that if we
# turn sanitizer stuff on).
#
set(SANITIZER_FLAGS "")
foreach(sanitizer IN LISTS ENABLE_SANITIZERS)
    # Set -Werror to catch "argument unused during compilation" warnings

    message(STATUS "Checking sanitizer ${sanitizer}")
    set(sanitizer_variable "sanitize_${sanitizer}")
    set(CMAKE_REQUIRED_FLAGS "-Werror -fsanitize=${sanitizer}")
    check_c_compiler_flag("-fsanitize=${sanitizer}" ${sanitizer_variable})
    if(${${sanitizer_variable}})
        set(SANITIZER_FLAGS "${SANITIZER_FLAGS} -fsanitize=${sanitizer}")
        message(STATUS "${sanitizer} sanitizer supported using -fsanitizer=${sanitizer}")
    else()
        #
        # Try the versions supported prior to Clang 3.2.
        # If the sanitizer is "address", try -fsanitize-address.
        # If it's "undefined", try -fcatch-undefined-behavior.
        # Otherwise, give up.
        #
        set(sanitizer_variable "OLD_${sanitizer_variable}")
        if ("${sanitizer}" STREQUAL "address")
            set(CMAKE_REQUIRED_FLAGS "-Werror -fsanitize-address")
            check_c_compiler_flag("-fsanitize-address" ${sanitizer_variable})
            if(${${sanitizer_variable}})
                set(SANITIZER_FLAGS "${SANITIZER_FLAGS} -fsanitize-address")
                message(STATUS "${sanitizer} sanitizer supported using -fsanitize-address")
            else()
                message(FATAL_ERROR "${sanitizer} isn't a supported sanitizer")
            endif()
        elseif("${sanitizer}" STREQUAL "undefined")
            set(CMAKE_REQUIRED_FLAGS "-Werror -fcatch-undefined-behavior")
            check_c_compiler_flag("-fcatch-undefined-behavior" ${sanitizer_variable})
            if(${${sanitizer_variable}})
                set(SANITIZER_FLAGS "${SANITIZER_FLAGS} -fcatch-undefined-behavior")
                message(STATUS "${sanitizer} sanitizer supported using catch-undefined-behavior")
            else()
                message(FATAL_ERROR "${sanitizer} isn't a supported sanitizer")
            endif()
        else()
            message(FATAL_ERROR "${sanitizer} isn't a supported sanitizer")
        endif()
    endif()

    unset(CMAKE_REQUIRED_FLAGS)
endforeach()

if(NOT "${SANITIZER_FLAGS}" STREQUAL "")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O1 -g ${SANITIZER_FLAGS} -fno-omit-frame-pointer -fno-optimize-sibling-calls")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O1 -g ${SANITIZER_FLAGS} -fno-omit-frame-pointer -fno-optimize-sibling-calls")
endif()

#
# OpenSSL/libressl.
#
find_package(OpenSSL)
if(OPENSSL_FOUND)
  #
  # We have OpenSSL.
  #
  include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
  set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${OPENSSL_LIBRARIES})

  #
  # The find_package() module CMake provides for OpenSSL uses does not
  # give us a defined indication of whether it found OpenSSL with
  # pkg-config or not.  We need to know that as, if it was found with
  # pkg-config, we should set the Requires.private value in libpcap.pc
  # to include its package name, openssl, otherwise we should add the
  # names for the static libraries to Libs.private.
  #
  # On UN*X, FindOpenSSL happens to use pkg-config to find OpenSSL, but
  # it doesn't appear to be documented as doing so; therefore, we don't
  # assume that, if we got here, we have pkg-config.
  #
  # So we use pkg_get_link_info() to run pkg-config ourselves, both
  # because FindOpenSSL doesn't set the OPENSSL_LDFLAGS or
  # OPENSSL_STATIC_LDFLAGS variables and because, for reasons explained
  # in the comment before the pkg_get_link_info() macro, even if it did,
  # it wouldn't be what we want anyway.
  #
  if (PKG_CONFIG_EXECUTABLE)
    pkg_get_link_info(OPENSSL openssl)
    if (OPENSSL_FOUND_WITH_PKG_CONFIG)
      #
      # pkg-config failed; assume that means that there is no openssl
      # package for it to find.  Just add OPENSSL_LIBRARIES to
      # LIBS_PRIVATE AND LIBS_STATIC, as that's the
      # best we can do. XXX - need list of -l and -L flags to add....
      #
      set(LIBS "${LIBS} ${OPENSSL_LIBS}")
      set(LIBS_STATIC "${LIBS_STATIC} ${OPENSSL_LIBS_STATIC}")
      set(REQUIRES_PRIVATE "${REQUIRES_PRIVATE} ${OPENSSL_PACKAGE_NAME}")
    endif()
  else()
    # Get it from OPENSSL_LIBRARIES
    foreach(_lib IN LISTS OPENSSL_LIBRARIES)
      #
      # Get the directory in which the library resides.
      #
      get_filename_component(_lib_directory "${_lib}" DIRECTORY)

      #
      # Is the library directory in CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES?
      # (See comment above on why we use that.)
      #
      list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${_lib_directory}" _lib_index)
      if(_lib_index EQUAL -1)
        #
        # No, so add a -L flag to get the linker to search in that
        # directory.
        #
        set(LIBS "${LIBS} -L${_lib_directory}")
        set(LIBS_STATIC "${LIBS_STATIC} -L${_lib_directory}")
        set(LIBS_PRIVATE "${LIBS_PRIVATE} -L${_lib_directory}")
      endif()

      #
      # Get the file name of the library, without the extension.
      #
      get_filename_component(_lib_filename "${_lib}" NAME_WE)

      #
      # Strip off the "lib" prefix to get the library name, and
      # add a -l flag based on that.
      #
      string(REGEX REPLACE "^lib" "" _library_name "${_lib_filename}")
      set(LIBS "${LIBS} -l${_library_name}")
      set(LIBS_STATIC "${LIBS_STATIC} -l${_library_name}")
      set(LIBS_PRIVATE "${LIBS_PRIVATE} -l${_library_name}")
    endforeach()
  endif()
  set(HAVE_OPENSSL YES)
endif(OPENSSL_FOUND)

#
# Additional linker flags.
#
set(LINKER_FLAGS "${SANITIZER_FLAGS}")
if(ENABLE_PROFILING)
    if(MSVC)
        set(LINKER_FLAGS " /PROFILE")
    else()
        set(LINKER_FLAGS " -pg")
    endif()
endif()

######################################
# Input files
######################################

set(PROJECT_SOURCE_LIST_C
    bpf_dump.c
    bpf_filter.c
    bpf_image.c
    etherent.c
    fmtutils.c
    gencode.c
    nametoaddr.c
    optimize.c
    pcap-common.c
    pcap-usb-linux-common.c
    pcap-util.c
    pcap.c
    savefile.c
    sf-pcapng.c
    sf-pcap.c
)

if(WIN32)
    #
    # We add the character set conversion routines; they're Windows-only
    # for now.
    #
    # We assume we don't have asprintf(), and provide an implementation
    # that uses _vscprintf() to determine how big the string needs to be.
    #
    set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C}
        charconv.c missing/win_asprintf.c)
else()
    if(NOT HAVE_ASPRINTF)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} missing/asprintf.c)
    endif()
    if(NOT HAVE_STRLCAT)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} missing/strlcat.c)
    endif(NOT HAVE_STRLCAT)
    if(NOT HAVE_STRLCPY)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} missing/strlcpy.c)
    endif(NOT HAVE_STRLCPY)
    if(NOT HAVE_STRTOK_R)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} missing/strtok_r.c)
    endif(NOT HAVE_STRTOK_R)
endif(WIN32)

#
# Determine the main pcap-XXX.c file to use, and the libraries with
# which we need to link libpcap, if any.
#
if(WIN32)
    #
    # Windows.
    #
    # Has the user explicitly specified a capture type?
    #
    if(PCAP_TYPE STREQUAL "")
        #
        # The user didn't explicitly specify a capture mechanism.
        # Check whether we have packet.dll.
        #
        if(HAVE_PACKET32)
            #
            # We have packet.dll.
            # Set the capture type to NPF.
            #
            set(PCAP_TYPE npf)
        else()
            #
            # We don't have any capture type we know about, so just use
            # the null capture type, and only support reading (and writing)
            # capture files.
            #
            set(PCAP_TYPE null)
        endif()
    endif()
else()
    #
    # UN*X.
    #
    # Figure out what type of packet capture mechanism we have, and
    # what libraries we'd need to link libpcap with, if any.
    #

    #
    # Has the user explicitly specified a capture type?
    #
    if(PCAP_TYPE STREQUAL "")
        #
        # Check for a bunch of headers for various packet capture mechanisms.
        #
        check_include_files("sys/types.h;net/bpf.h" HAVE_NET_BPF_H)
        if(HAVE_NET_BPF_H)
            #
            # Does it define BIOCSETIF?
            # I.e., is it a header for an LBL/BSD-style capture
            # mechanism, or is it just a header for a BPF filter
            # engine?  Some versions of Arch Linux, for example,
            # have a net/bpf.h that doesn't define BIOCSETIF;
            # as it's a Linux, it should use packet sockets,
            # instead.
            #
            # We need:
            #
            #  sys/types.h, because FreeBSD 10's net/bpf.h
            #  requires that various BSD-style integer types
            #  be defined;
            #
            #  sys/time.h, because AIX 5.2 and 5.3's net/bpf.h
            #  doesn't include it but does use struct timeval
            #  in ioctl definitions;
            #
            #  sys/ioctl.h and, if we have it, sys/ioccom.h,
            #  because net/bpf.h defines ioctls;
            #
            #  net/if.h, because it defines some structures
            #  used in ioctls defined by net/bpf.h;
            #
            #  sys/socket.h, because OpenBSD 5.9's net/bpf.h
            #  defines some structure fields as being
            #  struct sockaddrs;
            #
            # and net/bpf.h doesn't necessarily include all
            # of those headers itself.
            #
            if(HAVE_SYS_IOCCOM_H)
                check_symbol_exists(BIOCSETIF "sys/types.h;sys/time.h;sys/ioctl.h;sys/socket.h;sys/ioccom.h;net/bpf.h;net/if.h" BPF_H_DEFINES_BIOCSETIF)
            else(HAVE_SYS_IOCCOM_H)
                check_symbol_exists(BIOCSETIF "sys/types.h;sys/time.h;sys/ioctl.h;sys/socket.h;net/bpf.h;net/if.h" BPF_H_DEFINES_BIOCSETIF)
            endif(HAVE_SYS_IOCCOM_H)
        endif(HAVE_NET_BPF_H)
        check_include_file(net/pfilt.h HAVE_NET_PFILT_H)
        check_include_file(net/enet.h HAVE_NET_ENET_H)
        check_include_file(net/nit.h HAVE_NET_NIT_H)
        check_include_file(sys/net/nit.h HAVE_SYS_NET_NIT_H)
        check_include_file(linux/socket.h HAVE_LINUX_SOCKET_H)
        check_include_file(net/raw.h HAVE_NET_RAW_H)
        check_include_file(sys/dlpi.h HAVE_SYS_DLPI_H)
        check_include_file(config/HaikuConfig.h HAVE_CONFIG_HAIKUCONFIG_H)

        if(BPF_H_DEFINES_BIOCSETIF)
            #
            # BPF.
            # Check this before DLPI, so that we pick BPF on
            # Solaris 11 and later.
            #
            set(PCAP_TYPE bpf)
        elseif(HAVE_LINUX_SOCKET_H)
            #
            # No prizes for guessing this one.
            #
            set(PCAP_TYPE linux)
        elseif(HAVE_NET_PFILT_H)
            #
            # DEC OSF/1, Digital UNIX, Tru64 UNIX
            #
            set(PCAP_TYPE pf)
        elseif(HAVE_NET_ENET_H)
            #
            # Stanford Enetfilter.
            #
            set(PCAP_TYPE enet)
        elseif(HAVE_NET_NIT_H)
            #
            # SunOS 4.x STREAMS NIT.
            #
            set(PCAP_TYPE snit)
        elseif(HAVE_SYS_NET_NIT_H)
            #
            # Pre-SunOS 4.x non-STREAMS NIT.
            #
            set(PCAP_TYPE nit)
        elseif(HAVE_NET_RAW_H)
            #
            # IRIX snoop.
            #
            set(PCAP_TYPE snoop)
        elseif(HAVE_SYS_DLPI_H)
            #
            # DLPI on pre-Solaris 11 SunOS 5, HP-UX, possibly others.
            #
            set(PCAP_TYPE dlpi)
        elseif(HAVE_CONFIG_HAIKUCONFIG_H)
            #
            # Haiku.
            #
            set(PCAP_TYPE haiku)
        else()
            #
            # Nothing we support.
            #
            set(PCAP_TYPE null)
            message(WARNING
"cannot determine packet capture interface
(see the INSTALL.md file for more info)")
        endif()
    endif()
endif(WIN32)
message(STATUS "Packet capture mechanism type: ${PCAP_TYPE}")

find_package(PkgConfig QUIET)

#
# Do capture-mechanism-dependent tests.
#
if(WIN32)
    if(PCAP_TYPE STREQUAL "npf")
        #
        # Link with packet.dll before Winsock2.
        #
        set(PCAP_LINK_LIBRARIES ${Packet_LIBRARIES} ${PCAP_LINK_LIBRARIES})
    elseif(PCAP_TYPE STREQUAL "null")
    else()
        message(FATAL_ERROR "${PCAP_TYPE} is not a valid pcap type")
    endif()
else(WIN32)
    if(PCAP_TYPE STREQUAL "dlpi")
        #
        # Needed for common functions used by pcap-[dlpi,libdlpi].c
        #
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} dlpisubs.c)

        #
        # Checks for some header files.
        #
        check_include_file(sys/bufmod.h HAVE_SYS_BUFMOD_H)
        check_include_file(sys/dlpi_ext.h HAVE_SYS_DLPI_EXT_H)

        #
        # Checks to see if Solaris has the public libdlpi(3LIB) library.
        # Note: The existence of /usr/include/libdlpi.h does not mean it is the
        # public libdlpi(3LIB) version. Before libdlpi was made public, a
        # private version also existed, which did not have the same APIs.
        # Due to a gcc bug, the default search path for 32-bit libraries does
        # not include /lib, we add it explicitly here.
        # [http://bugs.opensolaris.org/view_bug.do?bug_id=6619485].
        # Also, due to the bug above applications that link to libpcap with
        # libdlpi will have to add "-L/lib" option to "configure".
        #
        cmake_push_check_state()
        set(CMAKE_REQUIRED_FLAGS "-L/lib")
        set(CMAKE_REQUIRED_LIBRARIES dlpi)
        check_function_exists(dlpi_walk HAVE_LIBDLPI)
        cmake_pop_check_state()
        if(HAVE_LIBDLPI)
            #
            # XXX - add -L/lib
            #
            set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} dlpi)
            set(LIBS "${LIBS} -ldlpi")
            set(LIBS_STATIC "${LIBS_STATIC} -ldlpi")
            set(LIBS_PRIVATE "${LIBS_PRIVATE} -ldlpi")
            set(PCAP_TYPE libdlpi)
        endif()

        #
        # This check is for Solaris with DLPI support for passive modes.
        # See dlpi(7P) for more details.
        #
        # XXX - there's no check_type() macro that's like check_type_size()
        # except that it only checks for the existence of the structure type,
        # so we use check_type_size() and ignore the size.
        #
        cmake_push_check_state()
        set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h sys/dlpi.h)
        check_type_size(dl_passive_req_t DL_PASSIVE_REQ_T)
        cmake_pop_check_state()
    elseif(PCAP_TYPE STREQUAL "linux")
        #
        # Do we have the wireless extensions?
        # linux/wireless.h requires sys/socket.h.
        #
        check_include_files("sys/socket.h;linux/wireless.h" HAVE_LINUX_WIRELESS_H)

        #
        # Do we have libnl?
        # We only want version 3.  Version 2 was, apparently,
        # short-lived, and version 1 is source and binary
        # incompatible with version 3, and it appears that,
        # these days, everybody's using version 3.  We're
        # not supporting older versions of the Linux kernel;
        # let's drop support for older versions of libnl, too.
        #
        if(BUILD_WITH_LIBNL)
            pkg_check_modules(LIBNL libnl-genl-3.0)
            if(LIBNL_FOUND)
                set(PCAP_LINK_LIBRARIES ${LIBNL_LIBRARIES} ${PCAP_LINK_LIBRARIES})

                #
                # Get raw link flags from pkg-config.
                #
                pkg_get_link_info(LIBNL libnl-genl-3.0)
                set(LIBS "${LIBNL_LIBS} ${LIBS}")
                set(LIBS_STATIC "${LIBNL_LIBS_STATIC} ${LIBS_STATIC}")
                set(REQUIRES_PRIVATE "${LIBNL_PACKAGE_NAME} ${REQUIRES_PRIVATE}")
            else()
                cmake_push_check_state()
                set(CMAKE_REQUIRED_LIBRARIES nl-3)
                check_function_exists(nl_socket_alloc HAVE_LIBNL)
                cmake_pop_check_state()
                if(HAVE_LIBNL)
                    #
                    # Yes, we have libnl 3.x.
                    #
                    set(PCAP_LINK_LIBRARIES nl-genl-3 nl-3 ${PCAP_LINK_LIBRARIES})
                    include_directories("/usr/include/libnl3")
                    set(LIBS "-lnl-genl-3 -lnl-3 ${LIBS}")
                    set(LIBS_STATIC "-lnl-genl-3 -lnl-3 ${LIBS_STATIC}")
                    set(LIBS_PRIVATE "-lnl-genl-3 -lnl-3 ${LIBS_PRIVATE}")
                endif()
            endif()
        else()
            unset(HAVE_LIBNL CACHE) # check_function_exists stores results in cache
        endif()

        check_struct_has_member("struct tpacket_auxdata" tp_vlan_tci linux/if_packet.h HAVE_STRUCT_TPACKET_AUXDATA_TP_VLAN_TCI)
    elseif(PCAP_TYPE STREQUAL "bpf")
        #
        # Check whether we have the *BSD-style ioctls.
        #
        check_include_files("sys/types.h;net/if_media.h" HAVE_NET_IF_MEDIA_H)

        #
        # Check whether we have struct BPF_TIMEVAL.
        #
        # XXX - there's no check_type() macro that's like check_type_size()
        # except that it only checks for the existence of the structure type,
        # so we use check_type_size() and ignore the size.
        #
        cmake_push_check_state()
        if(HAVE_SYS_IOCCOM_H)
            set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h sys/ioccom.h net/bpf.h)
            check_type_size("struct BPF_TIMEVAL" STRUCT_BPF_TIMEVAL)
        else()
            set(CMAKE_EXTRA_INCLUDE_FILES  sys/types.h net/bpf.h)
            check_type_size("struct BPF_TIMEVAL" STRUCT_BPF_TIMEVAL)
        endif()
        cmake_pop_check_state()
    elseif(PCAP_TYPE STREQUAL "haiku")
        #
        # Check for some headers just in case.
        #
        check_include_files("net/if.h;net/if_dl.h;net/if_types.h" HAVE_NET_IF_TYPES_H)
        set(PCAP_SRC pcap-${PCAP_TYPE}.cpp)
    elseif(PCAP_TYPE STREQUAL "null")
    else()
        message(FATAL_ERROR "${PCAP_TYPE} is not a valid pcap type")
    endif()
endif(WIN32)

if(NOT DEFINED PCAP_SRC)
set(PCAP_SRC pcap-${PCAP_TYPE}.c)
endif()

set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} ${PCAP_SRC})

#
# Now figure out how we get a list of interfaces and addresses,
# if we support capturing.  Don't bother if we don't support
# capturing.
#
if(NOT WIN32)
    #
    # UN*X - figure out what type of interface list mechanism we
    # have.
    #
    # If the capture type is null, that means we can't capture,
    # so we can't open any capture devices, so we won't return
    # any interfaces.
    #
    if(NOT PCAP_TYPE STREQUAL "null")
        cmake_push_check_state()
        set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LINK_LIBRARIES})
        check_function_exists(getifaddrs HAVE_GETIFADDRS)
        cmake_pop_check_state()
        if(NOT HAVE_GETIFADDRS)
            #
            # It's not in the libraries that, at this point, we've
            # found we need to link libpcap with.
            #
            # It's in libsocket on Solaris and possibly other OSes;
            # as long as we're not linking with libxnet, check there.
            #
            # NOTE: if you hand check_library_exists as its last
            # argument a variable that's been set, it skips the test,
            # so we need different variables.
            #
            if(NOT LIBXNET_HAS_GETHOSTBYNAME)
                check_library_exists(socket getifaddrs "" SOCKET_HAS_GETIFADDRS)
                if(SOCKET_HAS_GETIFADDRS)
                    set(PCAP_LINK_LIBRARIES socket ${PCAP_LINK_LIBRARIES})
                    set(LIBS "-lsocket ${LIBS}")
                    set(LIBS_STATIC "-lsocket ${LIBS_STATIC}")
                    set(LIBS_PRIVATE "-lsocket ${LIBS_PRIVATE}")
                    set(HAVE_GETIFADDRS TRUE)
                endif()
            endif()
        endif()
        if(HAVE_GETIFADDRS)
            #
            # We have "getifaddrs()"; make sure we have <ifaddrs.h>
            # as well, just in case some platform is really weird.
            # It may require that sys/types.h be included first,
            # so include it first.
            #
            check_include_files("sys/types.h;ifaddrs.h" HAVE_IFADDRS_H)
            if(HAVE_IFADDRS_H)
                #
                # We have the header, so we use "getifaddrs()" to
                # get the list of interfaces.
                #
                set(FINDALLDEVS_TYPE getad)
            else()
                #
                # We don't have the header - give up.
                # XXX - we could also fall back on some other
                # mechanism, but, for now, this'll catch this
                # problem so that we can at least try to figure
                # out something to do on systems with "getifaddrs()"
                # but without "ifaddrs.h", if there is something
                # we can do on those systems.
                #
                message(FATAL_ERROR "Your system has getifaddrs() but doesn't have a usable <ifaddrs.h>.")
            endif()
        else()
            #
            # Well, we don't have "getifaddrs()", at least not with the
            # libraries with which we've decided we need to link
            # libpcap with, so we have to use some other mechanism.
            #
            # Note that this may happen on Solaris, which has
            # getifaddrs(), but in -lsocket, not in -lxnet, so we
            # won't find it if we link with -lxnet, which we want
            # to do for other reasons.
            #
            # For now, we use either the SIOCGIFCONF ioctl or the
            # SIOCGLIFCONF ioctl, preferring the latter if we have
            # it; the latter is a Solarisism that first appeared
            # in Solaris 8.  (Solaris's getifaddrs() appears to
            # be built atop SIOCGLIFCONF; using it directly
            # avoids a not-all-that-useful middleman.)
            #
            try_compile(HAVE_SIOCGLIFCONF ${CMAKE_CURRENT_BINARY_DIR} "${pcap_SOURCE_DIR}/cmake/have_siocglifconf.c" )
            if(HAVE_SIOCGLIFCONF)
                set(FINDALLDEVS_TYPE glifc)
            else()
                set(FINDALLDEVS_TYPE gifc)
            endif()
        endif()
        message(STATUS "Find-interfaces mechanism type: ${FINDALLDEVS_TYPE}")
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} fad-${FINDALLDEVS_TYPE}.c)
    endif()
endif()

# Check for hardware timestamp support.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    check_include_file(linux/net_tstamp.h HAVE_LINUX_NET_TSTAMP_H)
endif()

#
# Check for additional native sniffing capabilities.
#

#
# Various Linux-specific mechanisms.
#
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Check for usbmon USB sniffing support.
    if(NOT DISABLE_LINUX_USBMON)
        set(PCAP_SUPPORT_LINUX_USBMON TRUE)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-usb-linux.c)
        #
        # Do we have a version of <linux/compiler.h> available?
        # If so, we might need it for <linux/usbdevice_fs.h>.
        #
        check_include_files("linux/compiler.h" HAVE_LINUX_COMPILER_H)
        if(HAVE_LINUX_COMPILER_H)
            #
            # Yes - include it when testing for <linux/usbdevice_fs.h>.
            #
            check_include_files("linux/compiler.h;linux/usbdevice_fs.h" HAVE_LINUX_USBDEVICE_FS_H)
        else(HAVE_LINUX_COMPILER_H)
            check_include_files("linux/usbdevice_fs.h" HAVE_LINUX_USBDEVICE_FS_H)
        endif(HAVE_LINUX_COMPILER_H)
        if(HAVE_LINUX_USBDEVICE_FS_H)
            #
            # OK, does it define bRequestType?  Older versions of the kernel
            # define fields with names like "requesttype, "request", and
            # "value", rather than "bRequestType", "bRequest", and
            # "wValue".
            #
            if(HAVE_LINUX_COMPILER_H)
                check_struct_has_member("struct usbdevfs_ctrltransfer" bRequestType "linux/compiler.h;linux/usbdevice_fs.h" HAVE_STRUCT_USBDEVFS_CTRLTRANSFER_BREQUESTTYPE)
            else(HAVE_LINUX_COMPILER_H)
                check_struct_has_member("struct usbdevfs_ctrltransfer" bRequestType "linux/usbdevice_fs.h" HAVE_STRUCT_USBDEVFS_CTRLTRANSFER_BREQUESTTYPE)
            endif(HAVE_LINUX_COMPILER_H)
        endif()
    endif()

    #
    # Check for netfilter sniffing support.
    #
    # Life's too short to deal with trying to get this to compile
    # if you don't get the right types defined with
    # __KERNEL_STRICT_NAMES getting defined by some other include.
    #
    # Check whether the includes Just Work.  If not, don't turn on
    # netfilter support.
    #
    check_c_source_compiles(
"#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/types.h>

#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netfilter/nfnetlink_queue.h>

int
main(void)
{
    return 0;
}
"
        PCAP_SUPPORT_NETFILTER)
    if(PCAP_SUPPORT_NETFILTER)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-netfilter-linux.c)
    endif(PCAP_SUPPORT_NETFILTER)
endif()

# Check for netmap sniffing support.
if(NOT DISABLE_NETMAP)
    #
    # Check whether net/netmap_user.h is usable if NETMAP_WITH_LIBS is
    # defined; it's not usable on DragonFly BSD 4.6 if NETMAP_WITH_LIBS
    # is defined, for example, as it includes a non-existent malloc.h
    # header.
    #
    check_c_source_compiles(
"#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

int
main(void)
{
    return 0;
}
"
        PCAP_SUPPORT_NETMAP)
    if(PCAP_SUPPORT_NETMAP)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-netmap.c)
    endif(PCAP_SUPPORT_NETMAP)
endif()

# Check for DPDK sniffing support
if(NOT DISABLE_DPDK)
    find_package(dpdk)
    if(dpdk_FOUND)
        #
        # We call rte_eth_dev_count_avail(), and older versions of DPDK
        # didn't have it, so check for it.
        #
        cmake_push_check_state()
        set(CMAKE_REQUIRED_INCLUDES ${dpdk_INCLUDE_DIRS})
        set(CMAKE_REQUIRED_LIBRARIES ${dpdk_LIBRARIES})
        check_function_exists(rte_eth_dev_count_avail HAVE_RTE_ETH_DEV_COUNT_AVAIL)
        cmake_pop_check_state()
        if(HAVE_RTE_ETH_DEV_COUNT_AVAIL)
            set(DPDK_C_FLAGS "-march=native")
            set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} ${DPDK_C_FLAGS})
            include_directories(AFTER ${dpdk_INCLUDE_DIRS})
            link_directories(AFTER ${dpdk_LIBRARIES})
            set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${dpdk_LIBRARIES})
            set(LIBS "${LIBS} ${dpdk_LIBS}")
            set(LIBS_STATIC "${LIBS_STATIC} ${dpdk_LIBS_STATIC}")
            set(REQUIRES_PRIVATE "${REQUIRES_PRIVATE} ${dpdk_PACKAGE_NAME}")
            set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-dpdk.c)
            set(PCAP_SUPPORT_DPDK TRUE)

            #
            # Check whether the rte_ether.h file defines
            # struct ether_addr or struct rte_ether_addr.
            #
            # ("API compatibility?  That's for losers!")
            #
            cmake_push_check_state()
            set(CMAKE_REQUIRED_INCLUDES ${dpdk_INCLUDE_DIRS})
            set(CMAKE_EXTRA_INCLUDE_FILES rte_ether.h)
            check_type_size("struct rte_ether_addr" STRUCT_RTE_ETHER_ADDR)
            cmake_pop_check_state()
        endif()
    else()
      message(WARNING,
"We couldn't find DPDK with pkg-config.  If you want DPDK support,
make sure that pkg-config is installed, that DPDK 18.02.2 or later is
installed, and that DPDK provides a .pc file.")
    endif()
endif()

# Check for Bluetooth sniffing support
if(NOT DISABLE_BLUETOOTH)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        check_include_file(bluetooth/bluetooth.h HAVE_BLUETOOTH_BLUETOOTH_H)
        if(HAVE_BLUETOOTH_BLUETOOTH_H)
            set(PCAP_SUPPORT_BT TRUE)
            set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-bt-linux.c)
            #
            # OK, does struct sockaddr_hci have an hci_channel
            # member?
            #
            check_struct_has_member("struct sockaddr_hci" hci_channel "bluetooth/bluetooth.h;bluetooth/hci.h" HAVE_STRUCT_SOCKADDR_HCI_HCI_CHANNEL)
            if(HAVE_STRUCT_SOCKADDR_HCI_HCI_CHANNEL)
                #
                # OK, is HCI_CHANNEL_MONITOR defined?
                #
               check_c_source_compiles(
"#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

int
main(void)
{
    u_int i = HCI_CHANNEL_MONITOR;
    return 0;
}
"
                   PCAP_SUPPORT_BT_MONITOR)
               if(PCAP_SUPPORT_BT_MONITOR)
                   #
                   # Yes, so we can also support Bluetooth monitor
                   # sniffing.
                   #
                   set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-bt-monitor-linux.c)
               endif(PCAP_SUPPORT_BT_MONITOR)
            endif(HAVE_STRUCT_SOCKADDR_HCI_HCI_CHANNEL)
        endif(HAVE_BLUETOOTH_BLUETOOTH_H)
    endif()
else()
    unset(PCAP_SUPPORT_BT_MONITOR CACHE)
endif()

# Check for D-Bus sniffing support
if(NOT DISABLE_DBUS)
    #
    # We don't support D-Bus sniffing on macOS; see
    #
    # https://bugs.freedesktop.org/show_bug.cgi?id=74029
    #
    if(APPLE)
        message(FATAL_ERROR "Due to freedesktop.org bug 74029, D-Bus capture support is not available on macOS")
    endif(APPLE)
    pkg_check_modules(DBUS dbus-1)
    if(DBUS_FOUND)
        set(PCAP_SUPPORT_DBUS TRUE)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-dbus.c)
        include_directories(${DBUS_INCLUDE_DIRS})

        #
        # This "helpfully" supplies DBUS_LIBRARIES as a bunch of
        # library names - not paths - and DBUS_LIBRARY_DIRS as
        # a bunch of directories.
        #
        # CMake *really* doesn't like the notion of specifying "here are
        # the directories in which to look for libraries" except in
        # find_library() calls; it *really* prefers using full paths to
        # library files, rather than library names.
        #
        # Find the libraries and add their full paths.
        #
        set(DBUS_LIBRARY_FULLPATHS)
        foreach(_lib IN LISTS DBUS_LIBRARIES)
            #
            # Try to find this library, so we get its full path.
            #
            find_library(_libfullpath ${_lib} HINTS ${DBUS_LIBRARY_DIRS})
            list(APPEND DBUS_LIBRARY_FULLPATHS ${_libfullpath})
        endforeach()
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${DBUS_LIBRARY_FULLPATHS})

        #
        # Get library information for DPDK.
        #
        pkg_get_link_info(DBUS dbus-1)
        set(LIBS "${LIBS} ${DBUS_LIBS}")
        set(LIBS_STATIC "${LIBS_STATIC} ${DBUS_LIBS_STATIC}")
        set(REQUIRES_PRIVATE "${REQUIRES_PRIVATE} ${DBUS_PACKAGE_NAME}")
    endif(DBUS_FOUND)
endif(NOT DISABLE_DBUS)

# Check for RDMA sniffing support
if(NOT DISABLE_RDMA)
    pkg_check_modules(LIBIBVERBS libibverbs)
    if(LIBIBVERBS_FOUND)
        #
        # pkg-config found it; remember its pkg-config name.
        #
        set(LIBIBVERBS_REQUIRES_PRIVATE ${LIBIBVERBS_PACKAGE_NAME})

        #
        # Get static linking information for it.
        #
        pkg_get_link_info(LIBIBVERBS libibverbs)
    else()
        #
        # pkg-config didn't find it; try to look for it ourselves
        #
        check_library_exists(ibverbs ibv_get_device_list "" LIBIBVERBS_HAS_IBV_GET_DEVICE_LIST)
        if(LIBIBVERBS_HAS_IBV_GET_DEVICE_LIST)
            set(LIBIBVERBS_FOUND TRUE)
            set(LIBIBVERBS_LIBRARIES ibverbs)
            # XXX - at least on Ubuntu 20.04, there are many more
            # libraries needed; is there any platform where
            # libibverbs is available but where pkg-config
            # isn't available or libibverbs doesn't use it?
            # If not, we should only use pkg-config for it.
            set(LIBIBVERBS_STATIC_LIBRARIES ibverbs)
            set(LIBIBVERBS_LIBS -libverbs)
            set(LIBIBVERBS_LIBS_STATIC -libverbs)
            set(LIBIBVERBS_LIBS_PRIVATE -libverbs)
        endif()
    endif()
    if(LIBIBVERBS_FOUND)
        #
        # For unknown reasons, check_include_file() doesn't just attempt
        # to compile a test program that includes the header in
        # question, it also attempts to link it.
        #
        # For unknown reasons, at least some of the static inline
        # functions defined in infiniband/verbs.h are not inlined by the
        # Sun^WOracle Studio C compiler, so the compiler generates code
        # for them as part of the object code resulting from compiling
        # the test program. At lest some of those functions call
        # routines in -libverbs, so, in order to keep the compile and
        # link from failing, even though the header file exists and is
        # usable, we need to link with -libverbs.
        #
        cmake_push_check_state()
        set(CMAKE_REQUIRED_LIBRARIES ${LIBIBVERBS_LIBRARIES})
        check_include_file(infiniband/verbs.h HAVE_INFINIBAND_VERBS_H)
        if(HAVE_INFINIBAND_VERBS_H)
            check_symbol_exists(ibv_create_flow infiniband/verbs.h PCAP_SUPPORT_RDMASNIFF)
            if(PCAP_SUPPORT_RDMASNIFF)
                set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-rdmasniff.c)
                set(PCAP_LINK_LIBRARIES ${LIBIBVERBS_LIBRARIES} ${PCAP_LINK_LIBRARIES})
                set(LIBS "${LIBIBVERBS_LIBS} ${LIBS}")
                set(LIBS_STATIC "${LIBIBVERBS_LIBS_STATIC} ${LIBS_STATIC}")
                set(LIBS_PRIVATE "${LIBIBVERBS_LIBS_PRIVATE} ${LIBS_PRIVATE}")
                set(REQUIRES_PRIVATE "${REQUIRES_PRIVATE} ${LIBIBVERBS_PACKAGE_NAME}")
            endif(PCAP_SUPPORT_RDMASNIFF)
        endif(HAVE_INFINIBAND_VERBS_H)
        cmake_pop_check_state()
    endif(LIBIBVERBS_FOUND)
endif(NOT DISABLE_RDMA)

#
# Check for sniffing capabilities using third-party APIs.
#

# Check for Endace DAG card support.
if(NOT DISABLE_DAG)
    #
    # Try to find the DAG header file and library.
    #
    find_package(DAG)

    #
    # Did we succeed?
    #
    if(DAG_FOUND)
        #
        # Yes.
        # Check for various DAG API functions.
        #
        cmake_push_check_state()
        set(CMAKE_REQUIRED_INCLUDES ${DAG_INCLUDE_DIRS})
        set(CMAKE_REQUIRED_LIBRARIES ${DAG_LIBRARIES})
        check_function_exists(dag_attach_stream HAVE_DAG_STREAMS_API)
        if(NOT HAVE_DAG_STREAMS_API)
            message(FATAL_ERROR "DAG library lacks streams support")
        endif()
        check_function_exists(dag_attach_stream64 HAVE_DAG_LARGE_STREAMS_API)
        check_function_exists(dag_get_erf_types HAVE_DAG_GET_ERF_TYPES)
        check_function_exists(dag_get_stream_erf_types HAVE_DAG_GET_STREAM_ERF_TYPES)
        cmake_pop_check_state()

        include_directories(AFTER ${DAG_INCLUDE_DIRS})
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-dag.c)
        set(HAVE_DAG_API TRUE)
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${DAG_LIBRARIES})
        set(LIBS "${LIBS} ${DAG_LIBS}")
        set(LIBS_STATIC "${LIBS_STATIC} ${DAG_LIBS_STATIC}")
        set(LIBS_PRIVATE "${LIBS_PRIVATE} ${DAG_LIBS_PRIVATE}")

        if(HAVE_DAG_LARGE_STREAMS_API)
            get_filename_component(DAG_LIBRARY_DIR ${DAG_LIBRARY} PATH)
            check_library_exists(vdag vdag_set_device_info ${DAG_LIBRARY_DIR} HAVE_DAG_VDAG)
            if(HAVE_DAG_VDAG)
                set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
                set(LIBS "${LIBS} ${CMAKE_THREAD_LIBS_INIT}")
                set(LIBS_STATIC "${LIBS_STATIC} ${CMAKE_THREAD_LIBS_INIT}")
                set(LIBS_PRIVATE "${LIBS_PRIVATE} ${CMAKE_THREAD_LIBS_INIT}")
            endif()
        endif()
    endif()
endif()

# Check for Septel card support.
set(PROJECT_EXTERNAL_OBJECT_LIST "")
if(NOT DISABLE_SEPTEL)
    #
    # Do we have the msg.h header?
    #
    set(SEPTEL_INCLUDE_DIRS "${SEPTEL_ROOT}/INC")
    cmake_push_check_state()
    set(CMAKE_REQUIRED_INCLUDES ${SEPTEL_INCLUDE_DIRS})
    check_include_file(msg.h HAVE_INC_MSG_H)
    cmake_pop_check_state()
    if(HAVE_INC_MSG_H)
        #
        # Yes.
        #
        include_directories(AFTER ${SEPTEL_INCLUDE_DIRS})
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-septel.c)
        set(PROJECT_EXTERNAL_OBJECT_LIST ${PROJECT_EXTERNAL_OBJECT_LIST} "${SEPTEL_ROOT}/asciibin.o ${SEPTEL_ROOT}/bit2byte.o ${SEPTEL_ROOT}/confirm.o ${SEPTEL_ROOT}/fmtmsg.o ${SEPTEL_ROOT}/gct_unix.o ${SEPTEL_ROOT}/hqueue.o ${SEPTEL_ROOT}/ident.o ${SEPTEL_ROOT}/mem.o ${SEPTEL_ROOT}/pack.o ${SEPTEL_ROOT}/parse.o ${SEPTEL_ROOT}/pool.o ${SEPTEL_ROOT}/sdlsig.o ${SEPTEL_ROOT}/strtonum.o ${SEPTEL_ROOT}/timer.o ${SEPTEL_ROOT}/trace.o")
        set(HAVE_SEPTEL_API TRUE)
    endif()
endif()

# Check for Myricom SNF support.
if(NOT DISABLE_SNF)
    #
    # Try to find the SNF header file and library.
    #
    find_package(SNF)

    #
    # Did we succeed?
    #
    if(SNF_FOUND)
        #
        # Yes.
        #
        include_directories(AFTER ${SNF_INCLUDE_DIRS})
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-snf.c)
        set(HAVE_SNF_API TRUE)
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${SNF_LIBRARIES})
        set(LIBS "${LIBS_STATIC} ${SNF_LIBS}")
        set(LIBS_STATIC "${LIBS_STATIC} ${SNF_LIBS_STATIC}")
        set(LIBS_PRIVATE "${LIBS_PRIVATE} ${SNF_LIBS_PRIVATE}")
    endif()
endif()

# Check for Riverbed AirPcap support.
if(NOT DISABLE_AIRPCAP)
    #
    # Try to find the AirPcap header file and library.
    #
    find_package(AirPcap)

    #
    # Did we succeed?
    #
    if(AirPcap_FOUND)
        #
        # Yes.
        #
        include_directories(AFTER ${AirPcap_INCLUDE_DIRS})
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-airpcap.c)
        set(HAVE_AIRPCAP_API TRUE)
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${AirPcap_LIBRARIES})
    endif()
endif()

# Check for Riverbed TurboCap support.
if(NOT DISABLE_TC)
    #
    # Try to find the TurboCap header file and library.
    #
    find_package(TC)

    #
    # Did we succeed?
    #
    if(TC_FOUND)
        #
        # Yes.
        #
        include_directories(AFTER ${TC_INCLUDE_DIRS})
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-tc.c)
        set(HAVE_TC_API TRUE)
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${TC_LIBRARIES} ${CMAKE_USE_PTHREADS_INIT} stdc++)
    endif()
endif()

#
# Remote capture support.
#

if(ENABLE_REMOTE)
    #
    # Check for various members of struct msghdr.
    # We need to include ftmacros.h on some platforms, to make sure we
    # get the POSIX/Single USER Specification version of struct msghdr,
    # which has those members, rather than the backwards-compatible
    # version, which doesn't.  That's not a system header file, and
    # at least some versions of CMake include it as <ftmacros.h>, which
    # won't check the current directory, so we add the top-level
    # source directory to the list of include directories when we do
    # the check.
    #
    cmake_push_check_state()
    set(CMAKE_REQUIRED_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR})
    check_struct_has_member("struct msghdr" msg_control "ftmacros.h;sys/socket.h" HAVE_STRUCT_MSGHDR_MSG_CONTROL)
    check_struct_has_member("struct msghdr" msg_flags "ftmacros.h;sys/socket.h" HAVE_STRUCT_MSGHDR_MSG_FLAGS)
    cmake_pop_check_state()
    set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C}
        pcap-new.c pcap-rpcap.c rpcap-protocol.c sockutils.c sslutils.c)
endif(ENABLE_REMOTE)

###################################################################
#   Warning options
###################################################################

#
# Check and add warning options if we have a .devel file.
#
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.devel OR EXISTS ${CMAKE_BINARY_DIR}/.devel)
    #
    # Warning options.
    #
    if(MSVC AND NOT ${CMAKE_C_COMPILER} MATCHES "clang*")
        #
        # MSVC, with Microsoft's front end and code generator.
        # "MSVC" is also set for Microsoft's compiler with a Clang
        # front end and their code generator ("Clang/C2"), so we
        # check for clang.exe and treat that differently.
        #
        check_and_add_compiler_option(-Wall)
        #
        # Disable some pointless warnings that /Wall turns on.
        #
        # Unfortunately, MSVC does not appear to have an equivalent
        # to "__attribute__((unused))" to mark a particular function
        # parameter as being known to be unused, so that the compiler
        # won't warn about it (for example, the function might have
        # that parameter because a pointer to it is being used, and
        # the signature of that function includes that parameter).
        # C++ lets you give a parameter a type but no name, but C
        # doesn't have that.
        #
        check_and_add_compiler_option(-wd4100)
        #
        # In theory, we care whether somebody uses f() rather than
        # f(void) to declare a function with no arguments, but, in
        # practice, there are places in the Windows header files
        # that appear to do that, so we squelch that warning.
        #
        check_and_add_compiler_option(-wd4255)
        #
        # Windows FD_SET() generates this, so we suppress it.
        #
        check_and_add_compiler_option(-wd4548)
        #
        # Perhaps testing something #defined to be 0 with #ifdef is an
        # error, and it should be tested with #if, but perhaps it's
        # not, and Microsoft does that in its headers, so we squelch
        # that warning.
        #
        check_and_add_compiler_option(-wd4574)
        #
        # The Windows headers also test not-defined values in #if, so
        # we don't want warnings about that, either.
        #
        check_and_add_compiler_option(-wd4668)
        #
        # We do *not* care whether some function is, or isn't, going to be
        # expanded inline.
        #
        check_and_add_compiler_option(-wd4710)
        check_and_add_compiler_option(-wd4711)
        #
        # We do *not* care whether we're adding padding bytes after
        # structure members.
        #
        check_and_add_compiler_option(-wd4820)
        #
        # We do *not* care about every single place the compiler would
        # have inserted Spectre mitigation if only we had told it to
        # do so with /Qspectre.  Maybe it's worth it, as that's in
        # Bison-generated code that we don't control.
        #
        # XXX - add /Qspectre if that is really worth doing.
        #
        check_and_add_compiler_option(-wd5045)

        #
        # Treat all (remaining) warnings as errors.
        #
        check_and_add_compiler_option(-WX)
    else()
        #
        # Other compilers, including MSVC with a Clang front end and
        # Microsoft's code generator.  We currently treat them as if
        # they might support GCC-style -W options.
        #
        check_and_add_compiler_option(-Wall)
        check_and_add_compiler_option(-Wcomma)
        # Warns about safeguards added in case the enums are extended
        # check_and_add_compiler_option(-Wcovered-switch-default)
        check_and_add_compiler_option(-Wdocumentation)
        check_and_add_compiler_option(-Wformat-nonliteral)
        check_and_add_compiler_option(-Wmissing-noreturn)
        check_and_add_compiler_option(-Wmissing-prototypes)
        check_and_add_compiler_option(-Wmissing-variable-declarations)
        check_and_add_compiler_option(-Wpointer-arith)
        check_and_add_compiler_option(-Wpointer-sign)
        check_and_add_compiler_option(-Wshadow)
        check_and_add_compiler_option(-Wsign-compare)
        check_and_add_compiler_option(-Wshorten-64-to-32)
        check_and_add_compiler_option(-Wstrict-prototypes)
        check_and_add_compiler_option(-Wunreachable-code)
        check_and_add_compiler_option(-Wunused-parameter)
        check_and_add_compiler_option(-Wused-but-marked-unused)
    endif()
endif()

#
# Suppress some warnings we get with MSVC even without /Wall.
#
if(MSVC AND NOT ${CMAKE_C_COMPILER} MATCHES "clang*")
    #
    # Yes, we have some functions that never return but that
    # have a non-void return type.  That's because, on some
    # platforms, they *do* return values but, on other
    # platforms, including Windows, they just fail and
    # longjmp out by calling bpf_error().
    #
    check_and_add_compiler_option(-wd4646)
endif()

file(GLOB PROJECT_SOURCE_LIST_H
    *.h
    pcap/*.h
)

#
# Try to have the compiler default to hiding symbols, so that only
# symbols explicitly exported with PCAP_API will be visible outside
# (shared) libraries.
#
# Not necessary with MSVC, as that's the default.
#
# XXX - we don't use ADD_COMPILER_EXPORT_FLAGS, because, as of CMake
# 2.8.12.2, it doesn't know about Sun C/Oracle Studio, and, as of
# CMake 2.8.6, it only sets the C++ compiler flags, rather than
# allowing an arbitrary variable to be set with the "hide symbols
# not explicitly exported" flag.
#
if(NOT MSVC)
    if(CMAKE_C_COMPILER_ID MATCHES "SunPro")
        #
        # Sun C/Oracle Studio.
        #
        check_and_add_compiler_option(-xldscope=hidden)
    else()
        #
        # Try this for all other compilers; it's what GCC uses,
        # and a number of other compilers, such as Clang and Intel C,
        # use it as well.
        #
        check_and_add_compiler_option(-fvisibility=hidden)
    endif()
endif(NOT MSVC)

#
# Extra compiler options for the build matrix scripts to request -Werror or
# its equivalent if required.  The CMake variable name cannot be CFLAGS
# because that is already used for a different purpose in CMake.  Example
# usage: cmake -DEXTRA_CFLAGS='-Wall -Wextra -Werror' ...
#
if(NOT "${EXTRA_CFLAGS}" STREQUAL "")
    foreach(_extra_cflag ${EXTRA_CFLAGS})
        check_and_add_compiler_option("${_extra_cflag}")
    endforeach(_extra_cflag)
    message(STATUS "Added extra compile options (${EXTRA_CFLAGS})")
endif()

#
# Flex/Lex and YACC/Berkeley YACC/Bison.
# From a mail message to the CMake mailing list by Andy Cedilnik of
# Kitware.
#

#
# Try to find Flex, a Windows version of Flex, or Lex.
#
find_program(LEX_EXECUTABLE NAMES flex win_flex lex)
if(LEX_EXECUTABLE STREQUAL "LEX_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "Neither flex nor win_flex nor lex was found.")
endif()
message(STATUS "Lexical analyzer generator: ${LEX_EXECUTABLE}")

#
# Make sure {f}lex supports the -P, --header-file, and --nounput flags
# and supports processing our scanner.l.
#
if(WIN32)
    set(NULL_DEVICE "NUL:")
else()
    set(NULL_DEVICE "/dev/null")
endif()
execute_process(COMMAND ${LEX_EXECUTABLE} -P pcap_ --header-file=${NULL_DEVICE} --nounput -t ${pcap_SOURCE_DIR}/scanner.l
    OUTPUT_QUIET RESULT_VARIABLE EXIT_STATUS)
if(NOT EXIT_STATUS EQUAL 0)
    message(FATAL_ERROR "${LEX_EXECUTABLE} is insufficient to compile libpcap.
libpcap requires Flex 2.5.31 or later, or a compatible version of lex.
If a suitable version of Lex/Flex is available as a non-standard command
and/or not in the PATH, you can specify it using the LEX environment
variable. That said, on some systems the error can mean that Flex/Lex is
actually acceptable, but m4 is not. Likewise, if a suitable version of
m4 (such as GNU M4) is available but has not been detected, you can
specify it using the M4 environment variable.")
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/scanner.c ${CMAKE_CURRENT_BINARY_DIR}/scanner.h
    SOURCE ${pcap_SOURCE_DIR}/scanner.l
    COMMAND ${LEX_EXECUTABLE} -P pcap_ --header-file=scanner.h --nounput -o${CMAKE_CURRENT_BINARY_DIR}/scanner.c ${pcap_SOURCE_DIR}/scanner.l
    DEPENDS ${pcap_SOURCE_DIR}/scanner.l
)

#
# Since scanner.c does not exist yet when cmake is run, mark
# it as generated.
#
# Since scanner.c includes grammar.h, mark that as a dependency.
#
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/scanner.c PROPERTIES
    GENERATED TRUE
    OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/grammar.h
)

#
# Add scanner.c to the list of sources.
#
#set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} ${CMAKE_CURRENT_BINARY_DIR}/scanner.c)

#
# Try to find YACC or Bison.
#
find_program(YACC_EXECUTABLE NAMES bison win_bison byacc yacc)
if(YACC_EXECUTABLE STREQUAL "YACC_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "Neither bison nor win_bison nor byacc nor yacc was found.")
endif()

if(YACC_EXECUTABLE MATCHES "byacc" OR YACC_EXECUTABLE MATCHES "yacc")
    #
    # Make sure this is Berkeley YACC, not AT&T YACC;
    # the latter doesn't support reentrant parsers.
    # Run it with "-V"; that succeeds and reports the
    # version number with Berkeley YACC, but will
    # (probably) fail with various vendor flavors
    # of AT&T YACC.
    #
    # Hopefully this also eliminates any versions
    # of Berkeley YACC that don't support reentrant
    # parsers, if there are any.
    #
    execute_process(COMMAND ${YACC_EXECUTABLE} -V OUTPUT_QUIET
        RESULT_VARIABLE EXIT_STATUS)
    if(NOT EXIT_STATUS EQUAL 0)
        message(FATAL_ERROR "${YACC_EXECUTABLE} is insufficient to compile libpcap.
libpcap requires Bison, a newer version of Berkeley YACC with support
for reentrant parsers, or another YACC compatible with them.")
    endif()
    #
    # Berkeley YACC doesn't support "%define api.pure", so use
    # "%pure-parser".
    #
    set(REENTRANT_PARSER "%pure-parser")
else()
    #
    # Bison prior to 2.4(.1) doesn't support "%define api.pure", so use
    # "%pure-parser".
    #
    execute_process(COMMAND ${YACC_EXECUTABLE} -V OUTPUT_VARIABLE bison_full_version)
    string(REGEX MATCH "[1-9][0-9]*[.][0-9]+" bison_major_minor ${bison_full_version})
    if (bison_major_minor VERSION_LESS "2.4")
        set(REENTRANT_PARSER "%pure-parser")
    else()
        set(REENTRANT_PARSER "%define api.pure")
    endif()
endif()

message(STATUS "Parser generator: ${YACC_EXECUTABLE}")

#
# Create custom command for the scanner.
#
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/grammar.c ${CMAKE_CURRENT_BINARY_DIR}/grammar.h
    SOURCE ${pcap_BINARY_DIR}/grammar.y
    COMMAND ${YACC_EXECUTABLE} -p pcap_ -o ${CMAKE_CURRENT_BINARY_DIR}/grammar.c -d ${pcap_BINARY_DIR}/grammar.y
    DEPENDS ${pcap_BINARY_DIR}/grammar.y
)

#
# Since grammar.c does not exists yet when cmake is run, mark
# it as generated.
#
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/grammar.c PROPERTIES
    GENERATED TRUE
    OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/scanner.h
)

#
# Add grammar.c to the list of sources.
#
#set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} ${CMAKE_CURRENT_BINARY_DIR}/grammar.c)

#
# Assume, by default, no support for shared libraries and V7/BSD
# convention for man pages (devices in section 4, file formats in
# section 5, miscellaneous info in section 7, administrative commands
# and daemons in section 8).  Individual cases can override this.
# Individual cases can override this.
#
set(MAN_DEVICES 4)
set(MAN_FILE_FORMATS 5)
set(MAN_MISC_INFO 7)
set(MAN_ADMIN_COMMANDS 8)
if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
    # Workaround to enable certain features
    set(_SUN TRUE)
    if(PCAP_TYPE STREQUAL "bpf")
        #
        # If we're using BPF, we need libodm and libcfg, as
        # we use them to load the BPF module.
        #
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} odm cfg)
        set(LIBS "${LIBS} -lodm -lcfg")
        set(LIBS_STATIC "${LIBS_STATIC} -lodm -lcfg")
        set(LIBS_PRIVATE "${LIBS_PRIVATE} -lodm -lcfg")
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
    if(CMAKE_SYSTEM_VERSION MATCHES "[A-Z.]*9\.[0-9]*")
        #
        # HP-UX 9.x.
        #
        set(HAVE_HPUX9 TRUE)
    elseif(CMAKE_SYSTEM_VERSION MATCHES "[A-Z.]*10\.0")
        #
        # HP-UX 10.0.
        #
    elseif(CMAKE_SYSTEM_VERSION MATCHES "[A-Z.]*10\.1")
        #
        # HP-UX 10.1.
        #
    else()
        #
        # HP-UX 10.20 and later.
        #
        set(HAVE_HPUX10_20_OR_LATER TRUE)
    endif()

    #
    # Use System V conventions for man pages.
    #
    set(MAN_ADMIN_COMMANDS 1m)
    set(MAN_FILE_FORMATS 4)
    set(MAN_MISC_INFO 5)
elseif(CMAKE_SYSTEM_NAME STREQUAL "IRIX" OR CMAKE_SYSTEM_NAME STREQUAL "IRIX64")
    #
    # Use IRIX conventions for man pages; they're the same as the
    # System V conventions, except that they use section 8 for
    # administrative commands and daemons.
    #
    set(MAN_FILE_FORMATS 4)
    set(MAN_MISC_INFO 5)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OSF1")
    #
    # DEC OSF/1, a/k/a Digital UNIX, a/k/a Tru64 UNIX.
    # Use Tru64 UNIX conventions for man pages; they're the same as the
    # System V conventions except that they use section 8 for
    # administrative commands and daemons.
    #
    set(MAN_FILE_FORMATS 4)
    set(MAN_MISC_INFO 5)
    set(MAN_DEVICES 7)
elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS" AND CMAKE_SYSTEM_VERSION MATCHES "5[.][0-9.]*")
    #
    # SunOS 5.x.
    #
    set(HAVE_SOLARIS TRUE)
    #
    # Make sure errno is thread-safe, in case we're called in
    # a multithreaded program.  We don't guarantee that two
    # threads can use the *same* pcap_t safely, but the
    # current version does guarantee that you can use different
    # pcap_t's in different threads, and even that pcap_compile()
    # is thread-safe (it wasn't thread-safe in some older versions).
    #
    add_definitions(-D_TS_ERRNO)

    if(CMAKE_SYSTEM_VERSION STREQUAL "5.12")
    else()
        #
        # Use System V conventions for man pages.
        #
        set(MAN_ADMIN_COMMANDS 1m)
        set(MAN_FILE_FORMATS 4)
        set(MAN_MISC_INFO 5)
        set(MAN_DEVICES 7D)
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Haiku")
    #
    # Haiku needs _BSD_SOURCE for the _IO* macros because it doesn't use them.
    #
    add_definitions(-D_BSD_SOURCE)
endif()

source_group("Source Files" FILES ${PROJECT_SOURCE_LIST_C})
source_group("Header Files" FILES ${PROJECT_SOURCE_LIST_H})

if(WIN32)
    #
    # Add pcap-dll.rc to the list of sources.
    #
    set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} ${pcap_SOURCE_DIR}/pcap-dll.rc)
endif(WIN32)

#
# Add subdirectories after we've set various variables, so they pick up
# pick up those variables.
#
if(ENABLE_REMOTE)
    add_subdirectory(rpcapd)
endif(ENABLE_REMOTE)
add_subdirectory(testprogs)

######################################
# Register targets
######################################

#
# Special target to serialize the building of the generated source.
#
# See
#
#  https://public.kitware.com/pipermail/cmake/2013-August/055510.html
#
add_custom_target(SerializeTarget
    DEPENDS
    ${CMAKE_CURRENT_BINARY_DIR}/grammar.c
    ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
)

set_source_files_properties(${PROJECT_EXTERNAL_OBJECT_LIST} PROPERTIES
    EXTERNAL_OBJECT TRUE)

if(BUILD_SHARED_LIBS)
    add_library(${LIBRARY_NAME} SHARED
        ${PROJECT_SOURCE_LIST_C}
        ${CMAKE_CURRENT_BINARY_DIR}/grammar.c
        ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
        ${PROJECT_EXTERNAL_OBJECT_LIST}
    )
    add_dependencies(${LIBRARY_NAME} SerializeTarget)
    set_target_properties(${LIBRARY_NAME} PROPERTIES
        COMPILE_DEFINITIONS BUILDING_PCAP)
    #
    # No matter what the library is called - it might be called "wpcap"
    # in a Windows build - the symbol to define to indicate that we're
    # building the library, rather than a program using the library,
    # and thus that we're exporting functions defined in our public
    # header files, rather than importing those functions, is
    # pcap_EXPORTS.
    #
    set_target_properties(${LIBRARY_NAME} PROPERTIES
        DEFINE_SYMBOL pcap_EXPORTS)
    if(NOT "${LINKER_FLAGS}" STREQUAL "")
        set_target_properties(${LIBRARY_NAME} PROPERTIES
            LINK_FLAGS "${LINKER_FLAGS}")
    endif()
endif(BUILD_SHARED_LIBS)

add_library(${LIBRARY_NAME}_static STATIC
    ${PROJECT_SOURCE_LIST_C}
    ${CMAKE_CURRENT_BINARY_DIR}/grammar.c
    ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
    ${PROJECT_EXTERNAL_OBJECT_LIST}
)
add_dependencies(${LIBRARY_NAME}_static SerializeTarget)
set_target_properties(${LIBRARY_NAME}_static PROPERTIES
    COMPILE_DEFINITIONS BUILDING_PCAP)

if(WIN32)
    if(BUILD_SHARED_LIBS)
        set_target_properties(${LIBRARY_NAME} PROPERTIES
            VERSION ${PACKAGE_VERSION_NOSUFFIX} # only MAJOR and MINOR are needed
        )
    endif(BUILD_SHARED_LIBS)
    if(MSVC)
        # XXX For DLLs, the TARGET_PDB_FILE generator expression can be used to locate
        # its PDB file's output directory for installation.
        # cmake doesn't offer a generator expression for PDB files generated by the
        # compiler (static libraries).
        # So instead of considering any possible output there is (there are many),
        # this will search for the PDB file in the compiler's initial output directory,
        # which is always ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles\wpcap_static.dir
        # regardless of architecture, build generator etc.
        # Quite hackish indeed.
        set(CMAKE_COMPILE_PDB_OUTPUT_DIRECTORY $<TARGET_FILE_DIR:${LIBRARY_NAME}_static>)
        set_target_properties(${LIBRARY_NAME}_static PROPERTIES
            COMPILE_PDB_NAME ${LIBRARY_NAME}_static
            OUTPUT_NAME "${LIBRARY_NAME}_static"
        )
    elseif(MINGW)
        #
        # For compatibility, build the shared library without the "lib" prefix on
        # MinGW as well.
        #
        set_target_properties(${LIBRARY_NAME} PROPERTIES
            PREFIX ""
            OUTPUT_NAME "${LIBRARY_NAME}"
        )
        set_target_properties(${LIBRARY_NAME}_static PROPERTIES
            OUTPUT_NAME "${LIBRARY_NAME}"
        )
    endif()
else(WIN32) # UN*X
    if(BUILD_SHARED_LIBS)
        if(APPLE)
            set_target_properties(${LIBRARY_NAME} PROPERTIES
                VERSION ${PACKAGE_VERSION}
                SOVERSION A
            )
        else(APPLE)
            set_target_properties(${LIBRARY_NAME} PROPERTIES
                VERSION ${PACKAGE_VERSION}
                SOVERSION ${PACKAGE_VERSION_MAJOR}
            )
        endif(APPLE)
    endif(BUILD_SHARED_LIBS)
    set_target_properties(${LIBRARY_NAME}_static PROPERTIES
        OUTPUT_NAME "${LIBRARY_NAME}"
    )
endif(WIN32)

if(BUILD_SHARED_LIBS)
    if(NOT C_ADDITIONAL_FLAGS STREQUAL "")
        set_target_properties(${LIBRARY_NAME} PROPERTIES COMPILE_FLAGS ${C_ADDITIONAL_FLAGS})
    endif()
    target_link_libraries(${LIBRARY_NAME} ${PCAP_LINK_LIBRARIES})
endif(BUILD_SHARED_LIBS)

if(NOT C_ADDITIONAL_FLAGS STREQUAL "")
    set_target_properties(${LIBRARY_NAME}_static PROPERTIES COMPILE_FLAGS ${C_ADDITIONAL_FLAGS})
endif()

#
# On macOS, build libpcap for the appropriate architectures, if
# CMAKE_OSX_ARCHITECTURES isn't set (if it is, let that control
# the architectures for which to build it).
#
if(APPLE AND "${CMAKE_OSX_ARCHITECTURES}" STREQUAL "")
    #
    # Get the major version of Darwin.
    #
    string(REGEX MATCH "^([0-9]+)" SYSTEM_VERSION_MAJOR "${CMAKE_SYSTEM_VERSION}")

    if(SYSTEM_VERSION_MAJOR LESS 8)
        #
        # Pre-Tiger.  Build only for 32-bit PowerPC.
        #
        set(OSX_LIBRARY_ARCHITECTURES "ppc")
    elseif(SYSTEM_VERSION_MAJOR EQUAL 8)
        #
        # Tiger.  Is this prior to, or with, Intel support?
        #
        # Get the minor version of Darwin.
        #
        string(REPLACE "${SYSTEM_VERSION_MAJOR}." "" SYSTEM_MINOR_AND_PATCH_VERSION ${CMAKE_SYSTEM_VERSION})
        string(REGEX MATCH "^([0-9]+)" SYSTEM_VERSION_MINOR "${SYSTEM_MINOR_AND_PATCH_VERSION}")
        if(SYSTEM_VERSION_MINOR LESS 4)
            #
            # Prior to Intel support.  Build for 32-bit
            # PowerPC and 64-bit PowerPC, with 32-bit PowerPC
            # first.  (I'm guessing that's what Apple does.)
            #
            set(OSX_LIBRARY_ARCHITECTURES "ppc;ppc64")
        elseif(SYSTEM_VERSION_MINOR LESS 7)
            #
            # With Intel support but prior to x86-64 support.
            # Build for 32-bit PowerPC, 64-bit PowerPC, and 32-bit x86,
            # with 32-bit PowerPC first.
            # (I'm guessing that's what Apple does.)
            #
            set(OSX_LIBRARY_ARCHITECTURES "ppc;ppc64;i386")
        else()
            #
            # With Intel support including x86-64 support.
            # Build for 32-bit PowerPC, 64-bit PowerPC, 32-bit x86,
            # and x86-64, with 32-bit PowerPC first.
            # (I'm guessing that's what Apple does.)
            #
            set(OSX_LIBRARY_ARCHITECTURES "ppc;ppc64;i386;x86_64")
        endif()
    elseif(SYSTEM_VERSION_MAJOR EQUAL 9)
        #
        # Leopard.  Build for 32-bit PowerPC, 64-bit
        # PowerPC, 32-bit x86, and x86-64, with 32-bit PowerPC
        # first.  (That's what Apple does.)
        #
        set(OSX_LIBRARY_ARCHITECTURES "ppc;ppc64;i386;x86_64")
    elseif(SYSTEM_VERSION_MAJOR EQUAL 10)
        #
        # Snow Leopard.  Build for x86-64, 32-bit x86, and
        # 32-bit PowerPC, with x86-64 first.  (That's
        # what Apple does, even though Snow Leopard
        # doesn't run on PPC, so PPC libpcap runs under
        # Rosetta, and Rosetta doesn't support BPF
        # ioctls, so PPC programs can't do live
        # captures.)
        #
        set(OSX_LIBRARY_ARCHITECTURES "x86_64;i386;ppc")
    elseif(SYSTEM_VERSION_MAJOR GREATER 10 AND SYSTEM_VERSION_MAJOR LESS 19)
        #
        # Post-Snow Leopard, pre-Catalina.  Build for x86-64
        # and 32-bit x86, with x86-64 first.  (That's what Apple does)
        #
        # First, check whether we're building with OpenSSL.
        # If so, don't bother trying to build fat.
        #
        if(HAVE_OPENSSL)
          set(X86_32_BIT_SUPPORTED NO)
          set(OSX_LIBRARY_ARCHITECTURES "x86_64")
          message(WARNING "We're assuming the OpenSSL libraries are 64-bit only, so we're not compiling for 32-bit x86")
        else()
          #
          # Now, check whether we *can* build for i386.
          #
          cmake_push_check_state()
          set(CMAKE_REQUIRED_FLAGS "-arch i386")
          check_c_source_compiles(
"int
main(void)
{
    return 0;
}
"
                   X86_32_BIT_SUPPORTED)
          cmake_pop_check_state()
          if(X86_32_BIT_SUPPORTED)
              set(OSX_LIBRARY_ARCHITECTURES "x86_64;i386")
          else()
              set(OSX_LIBRARY_ARCHITECTURES "x86_64")
              #
              # We can't build fat; suggest that the user install the
              # /usr/include headers if they want to build fat.
              #
              if(SYSTEM_VERSION_MAJOR LESS 18)
                  #
                  # Pre-Mojave; the command-line tools should be sufficient to
                  # enable 32-bit x86 builds.
                  #
                  message(WARNING "Compiling for 32-bit x86 gives an error; try installing the command-line tools")
              else()
                  message(WARNING "Compiling for 32-bit x86 gives an error; try installing the command-line tools and, after that, installing the /usr/include headers from the /Library/Developer/CommandLineTools/Packages/macOS_SDK_headers_for_macOS_10.14.pkg package")
              endif()
          endif()
        endif()
    elseif(SYSTEM_VERSION_MAJOR EQUAL 19)
        #
        # Catalina.  Build libraries and executables
        # only for x86-64.  (That's what Apple does;
        # 32-bit x86 binaries are not supported on
        # Catalina.)
        #
        set(OSX_LIBRARY_ARCHITECTURES "x86_64")
    else()
        #
        # Post-Catalina.  Build libraries and
        # executables for x86-64 and ARM64.
        # (That's what Apple does, except they
        # build for arm64e, which may include
        # some of the pointer-checking extensions.)
        #
        # If we're building with libssl, make sure
        # we can build fat with it (i.e., that it
        # was built fat); if we can't, don't set
        # the target architectures, and just
        # build for the host we're on.
        #
        # Otherwise, just add both of them.
        #
        if(HAVE_OPENSSL)
          cmake_push_check_state()
          set(CMAKE_REQUIRED_FLAGS "-arch x86_64 -arch arm64")
          set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
          set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
          #
          # We must test whether this compiles and links, so
          # check_symbol_exists() isn't sufficient.
          #
          # SSL_library_init() may be a macro that's #defined
          # to be the real function to call, so we have to
          # include <openssl/ssl.h>, and check_function_exists()
          # isn't sufficient.
          #
          check_c_source_compiles(
"#include <openssl/ssl.h>
int
main(void)
{
    SSL_library_init();
    return 0;
}
"
              FAT_SSL_BUILDS_SUPPORTED)
          cmake_pop_check_state()
          if(FAT_SSL_BUILDS_SUPPORTED)
              set(OSX_LIBRARY_ARCHITECTURES "x86_64;arm64")
          endif()
        else()
            set(OSX_LIBRARY_ARCHITECTURES "x86_64;arm64")
        endif()
    endif()
    if(BUILD_SHARED_LIBS)
        set_target_properties(${LIBRARY_NAME} PROPERTIES
            OSX_ARCHITECTURES "${OSX_LIBRARY_ARCHITECTURES}")
    endif(BUILD_SHARED_LIBS)
    set_target_properties(${LIBRARY_NAME}_static PROPERTIES
        OSX_ARCHITECTURES "${OSX_LIBRARY_ARCHITECTURES}")
endif()

######################################
# Write out the config.h file
######################################

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

######################################
# Write out the grammar.y file
######################################

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/grammar.y.in ${CMAKE_CURRENT_BINARY_DIR}/grammar.y @ONLY)

######################################
# Install pcap library, include files, and man pages
######################################

#
# "Define GNU standard installation directories", which actually
# are also defined, to some degree, by autotools, and at least
# some of which are general UN*X conventions.
#
include(GNUInstallDirs)

set(LIBRARY_NAME_STATIC ${LIBRARY_NAME}_static)

function(install_manpage_symlink SOURCE TARGET MANDIR)
    if(MINGW)
        #
        # If we haven't found an ln executable with MinGW, we don't try
        # generating and installing the man pages, so if we get here,
        # we've found that executable.
        set(LINK_COMMAND "\"${LINK_EXECUTABLE}\" \"-s\" \"${SOURCE}\" \"${TARGET}\"")
    else(MINGW)
        set(LINK_COMMAND "\"${CMAKE_COMMAND}\" \"-E\" \"create_symlink\" \"${SOURCE}\" \"${TARGET}\"")
    endif(MINGW)

    install(CODE
        "message(STATUS \"Symlinking: \$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/${MANDIR}/${SOURCE} to ${TARGET}\")
         execute_process(
            COMMAND \"${CMAKE_COMMAND}\" \"-E\" \"remove\" \"${TARGET}\"
            WORKING_DIRECTORY \$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/${MANDIR}
          )
         execute_process(
            COMMAND ${LINK_COMMAND}
            WORKING_DIRECTORY \$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/${MANDIR}
            RESULT_VARIABLE EXIT_STATUS
          )
          if(NOT EXIT_STATUS EQUAL 0)
              message(FATAL_ERROR \"Could not create symbolic link from ${CMAKE_INSTALL_PREFIX}/${MANDIR}/${SOURCE} to ${TARGET}\")
          endif()
          set(CMAKE_INSTALL_MANIFEST_FILES \${CMAKE_INSTALL_MANIFEST_FILES} ${CMAKE_INSTALL_PREFIX}/${MANDIR}/${TARGET})")
endfunction(install_manpage_symlink)

set(MAN1_NOEXPAND pcap-config.1)
set(MAN3PCAP_EXPAND
    pcap.3pcap.in
    pcap_compile.3pcap.in
    pcap_datalink.3pcap.in
    pcap_dump_open.3pcap.in
    pcap_get_tstamp_precision.3pcap.in
    pcap_list_datalinks.3pcap.in
    pcap_list_tstamp_types.3pcap.in
    pcap_open_dead.3pcap.in
    pcap_open_offline.3pcap.in
    pcap_set_immediate_mode.3pcap.in
    pcap_set_tstamp_precision.3pcap.in
    pcap_set_tstamp_type.3pcap.in
)
set(MAN3PCAP_NOEXPAND
    pcap_activate.3pcap
    pcap_breakloop.3pcap
    pcap_can_set_rfmon.3pcap
    pcap_close.3pcap
    pcap_create.3pcap
    pcap_datalink_name_to_val.3pcap
    pcap_datalink_val_to_name.3pcap
    pcap_dump.3pcap
    pcap_dump_close.3pcap
    pcap_dump_file.3pcap
    pcap_dump_flush.3pcap
    pcap_dump_ftell.3pcap
    pcap_file.3pcap
    pcap_fileno.3pcap
    pcap_findalldevs.3pcap
    pcap_freecode.3pcap
    pcap_get_required_select_timeout.3pcap
    pcap_get_selectable_fd.3pcap
    pcap_geterr.3pcap
    pcap_init.3pcap
    pcap_inject.3pcap
    pcap_is_swapped.3pcap
    pcap_lib_version.3pcap
    pcap_lookupdev.3pcap
    pcap_lookupnet.3pcap
    pcap_loop.3pcap
    pcap_major_version.3pcap
    pcap_next_ex.3pcap
    pcap_offline_filter.3pcap
    pcap_open_live.3pcap
    pcap_set_buffer_size.3pcap
    pcap_set_datalink.3pcap
    pcap_set_promisc.3pcap
    pcap_set_protocol_linux.3pcap
    pcap_set_rfmon.3pcap
    pcap_set_snaplen.3pcap
    pcap_set_timeout.3pcap
    pcap_setdirection.3pcap
    pcap_setfilter.3pcap
    pcap_setnonblock.3pcap
    pcap_snapshot.3pcap
    pcap_stats.3pcap
    pcap_statustostr.3pcap
    pcap_strerror.3pcap
    pcap_tstamp_type_name_to_val.3pcap
    pcap_tstamp_type_val_to_name.3pcap
)
set(MANFILE_EXPAND
    pcap-savefile.manfile.in
)
set(MANMISC_EXPAND
    pcap-filter.manmisc.in
    pcap-linktype.manmisc.in
    pcap-tstamp.manmisc.in
)

if(BUILD_SHARED_LIBS)
    set(LIBRARIES_TO_INSTALL "${LIBRARY_NAME}" "${LIBRARY_NAME_STATIC}")
else(BUILD_SHARED_LIBS)
    set(LIBRARIES_TO_INSTALL "${LIBRARY_NAME_STATIC}")
endif(BUILD_SHARED_LIBS)

if(WIN32 OR CYGWIN OR MSYS)
    #
    # XXX - according to the CMake documentation, WIN32 is set if
    # the target is Windows; would there ever be a case where
    # CYGWIN or MSYS are set but WIN32 *isn't* set?
    #
    if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
        #
        # Install 64-bit code built with MSVC in the x64 subdirectories,
        # as that's where it expects it to be.
        #
        install(TARGETS ${LIBRARIES_TO_INSTALL}
                RUNTIME DESTINATION bin/x64
                LIBRARY DESTINATION lib/x64
                ARCHIVE DESTINATION lib/x64)
        if(NOT MINGW)
            install(FILES $<TARGET_FILE_DIR:${LIBRARY_NAME_STATIC}>/${LIBRARY_NAME_STATIC}.pdb
                    DESTINATION bin/x64 OPTIONAL)
            if(BUILD_SHARED_LIBS)
                install(FILES $<TARGET_PDB_FILE:${LIBRARY_NAME}>
                        DESTINATION bin/x64 OPTIONAL)
            endif(BUILD_SHARED_LIBS)
        endif(NOT MINGW)
    else(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
        #
        # Install 32-bit code, and 64-bit code not built with MSVC
        # in the top-level directories, as those are where they
        # expect it to be.
        #
        install(TARGETS ${LIBRARIES_TO_INSTALL}
                RUNTIME DESTINATION bin
                LIBRARY DESTINATION lib
                ARCHIVE DESTINATION lib)
        if(MSVC)
            install(FILES $<TARGET_FILE_DIR:${LIBRARY_NAME_STATIC}>/${LIBRARY_NAME_STATIC}.pdb
                    DESTINATION bin OPTIONAL)
            if(BUILD_SHARED_LIBS)
                install(FILES $<TARGET_PDB_FILE:${LIBRARY_NAME}>
                        DESTINATION bin OPTIONAL)
            endif(BUILD_SHARED_LIBS)
        endif(MSVC)
    endif(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
else(WIN32 OR CYGWIN OR MSYS)
    install(TARGETS ${LIBRARIES_TO_INSTALL} DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})
endif(WIN32 OR CYGWIN OR MSYS)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/pcap/ DESTINATION include/pcap)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pcap.h DESTINATION include)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pcap-bpf.h DESTINATION include)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pcap-namedb.h DESTINATION include)

# On UN*X, and on Windows when not using MSVC, generate libpcap.pc and
# pcap-config and process man pages and arrange that they be installed.
if(NOT MSVC)
    set(prefix ${CMAKE_INSTALL_PREFIX})
    set(exec_prefix "\${prefix}")
    set(includedir "\${prefix}/include")
    set(libdir "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")

    #
    # If this is a platform where we need to have the .pc file and
    # pcap-config script supply an rpath option to specify the directory
    # in which the libpcap shared library is installed, and the install
    # prefix /usr (meaning we're not installing a system library),
    # provide the rpath option.
    #
    # (We must check CMAKE_INSTALL_PREFIX, as the library directory
    # isn't  necessarily /usr/lib in this case - for example, Linux
    # distributions for 64-bit platforms that also provide support for
    # binaries for a 32-bit version of the platform may put the 64-bit
    # libraries, the 32-bit libraries, or both in directories other than
    # /usr/lib.)
    #
    # In AIX, do we have to do this?
    #
    # In Darwin-based OSes, the full paths of the shared libraries with
    # which the program was linked are stored in the executable, so we
    # don't need to provide an rpath option.
    #
    # With the HP-UX linker, directories specified with -L are, by
    # default, added to the run-time search path, so we don't need to
    # supply them.
    #
    # For Tru64 UNIX, "-rpath" works with DEC's^WCompaq's^WHP's C
    # compiler for Alpha, but isn't documented as working with GCC, and
    # no GCC-compatible option is documented as working with the DEC
    # compiler.  If anybody needs this on Tru64/Alpha, they're welcome
    # to figure out a way to make it work.
    #
    # This must *not* depend on the compiler, as, on platforms where
    # there's a GCC-compatible compiler and a vendor compiler, we need
    # to work with both.
    #
    if(NOT CMAKE_INSTALL_PREFIX STREQUAL "/usr")
        if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
           CMAKE_SYSTEM_NAME STREQUAL "NetBSD" OR
           CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR
           CMAKE_SYSTEM_NAME STREQUAL "DragonFly BSD" OR
           CMAKE_SYSTEM_NAME STREQUAL "Linux")
            #
            # Platforms where the "native" C compiler is GCC or accepts
            # compatible command-line arguments, and the "native" linker
            # is the GNU linker or accepts compatible command-line
            # arguments.
            #
            set(RPATH "-Wl,-rpath,\${libdir}")
        elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS" AND CMAKE_SYSTEM_VERSION MATCHES "5[.][0-9.]*")
            #
            # SunOS 5.x.
            #
            # Sun/Oracle's linker, the GNU linker, and GNU-compatible
            # linkers all support -R.
            #
            set(RPATH "-Wl,-R,\${libdir}")
        else()
            #
            # No option needed to set the RPATH.
            #
            set(RPATH "")
        endif()
    endif()
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/pcap-config.in ${CMAKE_CURRENT_BINARY_DIR}/pcap-config @ONLY)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libpcap.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libpcap.pc @ONLY)
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/pcap-config DESTINATION bin)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libpcap.pc DESTINATION lib/pkgconfig)

    #
    # Man pages.
    #
    # For each section of the manual for which we have man pages
    # that require macro expansion, do the expansion.
    #
    # If this is MinGW, maybe we have a UN*X-style ln command and
    # maybe we don't.  (No, we do *NOT* require MSYS!)  If we don't
    # have it, don't do the man pages.
    #
    if(MINGW)
        find_program(LINK_EXECUTABLE ln)
    endif(MINGW)
    if(UNIX OR (MINGW AND LINK_EXECUTABLE))
        set(MAN1 "")
        foreach(MANPAGE ${MAN1_NOEXPAND})
            set(MAN1 ${MAN1} ${CMAKE_CURRENT_SOURCE_DIR}/${MANPAGE})
        endforeach(MANPAGE)
        install(FILES ${MAN1} DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

        set(MAN3PCAP "")
        foreach(MANPAGE ${MAN3PCAP_NOEXPAND})
            set(MAN3PCAP ${MAN3PCAP} ${CMAKE_CURRENT_SOURCE_DIR}/${MANPAGE})
        endforeach(MANPAGE)
        foreach(TEMPLATE_MANPAGE ${MAN3PCAP_EXPAND})
            string(REPLACE ".in" "" MANPAGE ${TEMPLATE_MANPAGE})
            configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${TEMPLATE_MANPAGE} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE} @ONLY)
            set(MAN3PCAP ${MAN3PCAP} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE})
        endforeach(TEMPLATE_MANPAGE)
        install(FILES ${MAN3PCAP} DESTINATION ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_datalink_val_to_name.3pcap pcap_datalink_val_to_description.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_datalink_val_to_name.3pcap pcap_datalink_val_to_description_or_dlt.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_dump_open.3pcap pcap_dump_fopen.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_findalldevs.3pcap pcap_freealldevs.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_geterr.3pcap pcap_perror.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_inject.3pcap pcap_sendpacket.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_list_datalinks.3pcap pcap_free_datalinks.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_list_tstamp_types.3pcap pcap_free_tstamp_types.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_loop.3pcap pcap_dispatch.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_major_version.3pcap pcap_minor_version.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_next_ex.3pcap pcap_next.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_open_dead.3pcap pcap_open_dead_with_tstamp_precision.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_open_offline.3pcap pcap_open_offline_with_tstamp_precision.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_open_offline.3pcap pcap_fopen_offline.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_open_offline.3pcap pcap_fopen_offline_with_tstamp_precision.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_tstamp_type_val_to_name.3pcap pcap_tstamp_type_val_to_description.3pcap ${CMAKE_INSTALL_MANDIR}/man3)
        install_manpage_symlink(pcap_setnonblock.3pcap pcap_getnonblock.3pcap ${CMAKE_INSTALL_MANDIR}/man3)

        set(MANFILE "")
        foreach(TEMPLATE_MANPAGE ${MANFILE_EXPAND})
            string(REPLACE ".manfile.in" ".${MAN_FILE_FORMATS}" MANPAGE ${TEMPLATE_MANPAGE})
            configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${TEMPLATE_MANPAGE} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE} @ONLY)
            set(MANFILE ${MANFILE} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE})
        endforeach(TEMPLATE_MANPAGE)
        install(FILES ${MANFILE} DESTINATION ${CMAKE_INSTALL_MANDIR}/man${MAN_FILE_FORMATS})

        set(MANMISC "")
        foreach(TEMPLATE_MANPAGE ${MANMISC_EXPAND})
            string(REPLACE ".manmisc.in" ".${MAN_MISC_INFO}" MANPAGE ${TEMPLATE_MANPAGE})
            configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${TEMPLATE_MANPAGE} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE} @ONLY)
            set(MANMISC ${MANMISC} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE})
        endforeach(TEMPLATE_MANPAGE)
        install(FILES ${MANMISC} DESTINATION ${CMAKE_INSTALL_MANDIR}/man${MAN_MISC_INFO})
    endif(UNIX OR (MINGW AND LINK_EXECUTABLE))
endif(NOT MSVC)

# uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
