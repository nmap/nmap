# CMakeLists.txt
#
# This file enables PCRE2 to be built with the CMake configuration and build
# tool. Download CMake in source or binary form from http://www.cmake.org/
# Converted to support PCRE2 from the original PCRE file, August 2014.
#
# Original listfile by Christian Ehrlicher <Ch.Ehrlicher@gmx.de>
# Refined and expanded by Daniel Richard G. <skunk@iSKUNK.ORG>
# 2007-09-14 mod by Sheri so 7.4 supported configuration options can be entered
# 2007-09-19 Adjusted by PH to retain previous default settings
# 2007-12-26 (a) On UNIX, use names libpcre instead of just pcre
#            (b) Ensure pcretest and pcregrep link with the local library,
#                not a previously-installed one.
#            (c) Add PCRE_SUPPORT_LIBREADLINE, PCRE_SUPPORT_LIBZ, and
#                PCRE_SUPPORT_LIBBZ2.
# 2008-01-20 Brought up to date to include several new features by Christian
#            Ehrlicher.
# 2008-01-22 Sheri added options for backward compatibility of library names
#            when building with minGW:
#            if "ON", NON_STANDARD_LIB_PREFIX causes shared libraries to
#            be built without "lib" as prefix. (The libraries will be named
#            pcre.dll, pcreposix.dll and pcrecpp.dll).
#            if "ON", NON_STANDARD_LIB_SUFFIX causes shared libraries to
#            be built with suffix of "-0.dll". (The libraries will be named
#            libpcre-0.dll, libpcreposix-0.dll and libpcrecpp-0.dll - same names
#            built by default with Configure and Make.
# 2008-01-23 PH removed the automatic build of pcredemo.
# 2008-04-22 PH modified READLINE support so it finds NCURSES when needed.
# 2008-07-03 PH updated for revised UCP property support (change of files)
# 2009-03-23 PH applied Steven Van Ingelgem's patch to change the name
#            CMAKE_BINARY_DIR to PROJECT_BINARY_DIR so that it works when PCRE
#            is included within another project.
# 2009-03-23 PH applied a modified version of Steven Van Ingelgem's patches to
#            add options to stop the building of pcregrep and the tests, and
#            to disable the final configuration report.
# 2009-04-11 PH applied Christian Ehrlicher's patch to show compiler flags that
#            are set by specifying a release type.
# 2010-01-02 PH added test for stdint.h
# 2010-03-02 PH added test for inttypes.h
# 2011-08-01 PH added PCREGREP_BUFSIZE
# 2011-08-22 PH added PCRE_SUPPORT_JIT
# 2011-09-06 PH modified WIN32 ADD_TEST line as suggested by Sergey Cherepanov
# 2011-09-06 PH added PCRE_SUPPORT_PCREGREP_JIT
# 2011-10-04 Sheri added support for including coff data in windows shared libraries
#            compiled with MINGW if pcre.rc and/or pcreposix.rc are placed in
#            the source dir by the user prior to building
# 2011-10-04 Sheri changed various add_test's to use exes' location built instead
#            of DEBUG location only (likely only matters in MSVC)
# 2011-10-04 Sheri added scripts to provide needed variables to RunTest and
#            RunGrepTest (used for UNIX and Msys)
# 2011-10-04 Sheri added scripts to provide needed variables and to execute
#            RunTest.bat in Win32 (for effortless testing with "make test")
# 2011-10-04 Sheri Increased minimum required cmake version
# 2012-01-06 PH removed pcre_info.c and added pcre_string_utils.c
# 2012-01-10 Zoltan Herczeg added libpcre16 support
# 2012-01-13 Stephen Kelly added out of source build support
# 2012-01-17 PH applied Stephen Kelly's patch to parse the version data out
#            of the configure.ac file
# 2012-02-26 PH added support for libedit
# 2012-09-06 PH added support for PCRE_EBCDIC_NL25
# 2012-09-08 ChPe added PCRE32 support
# 2012-10-23 PH added support for VALGRIND and GCOV
# 2012-12-08 PH added patch from Daniel Richard G to quash some MSVC warnings
# 2013-07-01 PH realized that the "support" for GCOV was a total nonsense and
#            so it has been removed.
# 2013-10-08 PH got rid of the "source" command, which is a bash-ism (use ".")
# 2013-11-05 PH added support for PARENS_NEST_LIMIT
# 2014-08-29 PH converted the file for PCRE2 (which has no C++).
# 2015-04-24 PH added support for PCRE2_DEBUG
# 2015-07-16 PH updated for new pcre2_find_bracket source module
# 2015-08-24 PH correct C_FLAGS setting (patch from Roy Ivy III)
# 2015-10=16 PH added support for never-backslash-C
# 2016-03-01 PH applied Chris Wilson's patch for MSVC static
# 2016-06-24 PH applied Chris Wilson's second patch, putting the first under
#            a new option instead of being unconditional.
# 2016-10-05 PH fixed a typo (PCRE should be PCRE2) in above patch
#            fix by David Gaussmann
# 2016-10-07 PH added PCREGREP_MAX_BUFSIZE
# 2017-03-11 PH turned HEAP_MATCH_RECURSE into a NO-OP for 10.30
# 2017-04-08 PH added HEAP_LIMIT
# 2017-06-15 ZH added SUPPORT_JIT_SEALLOC support
# 2018-06-19 PH added checks for stdint.h and inttypes.h (later removed)
# 2018-06-27 PH added Daniel's patch to increase the stack for MSVC
# 2018-11-14 PH removed unnecessary checks for stdint.h and inttypes.h
# 2018-11-16 PH added PCRE2GREP_SUPPORT_CALLOUT_FORK support and tidied
# 2019-02-16 PH hacked to avoid CMP0026 policy issue (see comments below)
# 2020-03-16 PH renamed dftables as pcre2_dftables (as elsewhere)
# 2020-03-24 PH changed CMAKE_MODULE_PATH definition to add, not replace
# 2020-04-08 Carlo added function check for secure_getenv, fixed strerror
# 2020-04-16 enh added check for __attribute__((uninitialized))
# 2020-04-25 PH applied patches from Uwe Korn to support pkg-config and
#            library versioning.
# 2020-04-25 Carlo added function check for mkostemp used in ProtExecAllocator
# 2020-04-28 PH added function check for memfd_create based on Carlo's patch
# 2020-05-25 PH added a check for Intel CET
# 2020-12-03 PH altered the definition of pcre2test as suggested by Daniel
# 2021-06-29 JWSB added the option to build static library with PIC.
# 2021-07-05 JWSB modified such both the static and shared library can be
#            build in one go.
# 2021-08-28 PH increased minimum version
# 2021-08-28 PH added test for realpath()
# 2022-12-10 PH added support for pcre2posix_test
# 2023-01-15 Carlo added C99 as the minimum required
# 2023-08-06 PH added support for setting variable length lookbehind maximum
# 2025-03-27 Theodore used standard CMake constructs to export the library's
#            targets.

################################################################################
# We have used `gersemi` for auto-formatting our CMake files.
# Applied to all CMake files using:
#    > pip3 install gersemi
#    > gersemi --in-place --line-length 120 --indent 2 \
#          --definitions cmake/*.cmake \
#          -- ./CMakeLists.txt ./cmake/*.cmake ./cmake/*.cmake.in
################################################################################

message(STATUS "Using CMake version ${CMAKE_VERSION} (${CMAKE_COMMAND})")

# Increased minimum to 3.15 to allow use of string(REPEAT).
cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
project(PCRE2 C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(CMAKE_C_VISIBILITY_PRESET hidden)

# Solaris-specific fix for "CMAKE_C_VISIBILITY_PRESET": this feature was only
# recently added to CMake for the `cc` compiler (Oracle Developer Studio). The
# CMake version from OpenCSW and Oracle's package repository is too old and
# requires this fix.
if(
  CMAKE_SYSTEM_NAME STREQUAL "SunOS"
  AND CMAKE_VERSION VERSION_LESS 3.31
  AND CMAKE_C_COMPILER_ID STREQUAL "SunPro"
  AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 5.15
)
  set(CMAKE_C_COMPILE_OPTIONS_VISIBILITY "-fvisibility=")
endif()

# The following policies have been set in the PCRE2 CMake file in the past.
# Since we specify a minimum of CMake 3.15, these are no longer required.
# cmake_policy(SET CMP0063 NEW)
# cmake_policy(SET CMP0026 OLD)
# cmake_policy(SET CMP0074 NEW)

# For our modules in cmake/. This uses list(APPEND) rather than set() to allow
# setting CMAKE_MODULE_PATH on the command line.
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

# external packages
find_package(BZip2)
find_package(ZLIB)

# Configuration checks

include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckIncludeFile)
include(CheckTypeSize)
include(CMakePackageConfigHelpers)
include(CMakePushCheckState)
include(GNUInstallDirs) # for CMAKE_INSTALL_LIBDIR
include(PCRE2CheckVscript)
include(PCRE2UseSystemExtensions)
include(PCRE2WarningAsError)

check_include_file(assert.h HAVE_ASSERT_H)
check_include_file(dirent.h HAVE_DIRENT_H)
check_include_file(sys/stat.h HAVE_SYS_STAT_H)
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(unistd.h HAVE_UNISTD_H)
check_include_file(windows.h HAVE_WINDOWS_H)

# Check whether any system-wide extensions need to be enabled, in order for
# OS functionality to be exposed.
pcre2_use_system_extensions()

cmake_push_check_state(RESET)
# Somewhat awkward code to propagate the _GNU_SOURCE definition (added to
# COMPILE_DEFINITIONS by pcre2_use_system_extensions()).
get_directory_property(_pcre2_compile_definitions COMPILE_DEFINITIONS)
if(DEFINED _pcre2_compile_definitions)
  set(CMAKE_REQUIRED_DEFINITIONS "")
  foreach(_def IN LISTS _pcre2_compile_definitions)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D${_def}")
  endforeach()
endif()

check_symbol_exists(mkostemp stdlib.h HAVE_MKOSTEMP) # glibc 2.7
check_symbol_exists(memfd_create "sys/mman.h" HAVE_MEMFD_CREATE) # glibc 2.27
check_symbol_exists(secure_getenv "stdlib.h" HAVE_SECURE_GETENV) # glibc 2.17
cmake_pop_check_state()

check_c_source_compiles(
  [=[
  #include <stdlib.h>
  #include <limits.h>
  int main(int c, char *v[]) { char buf[PATH_MAX]; realpath(v[c], buf); return 0; }
  ]=]
  HAVE_REALPATH
)

# Many CMake tests use highly-dubious C source code which generates warnings
# (for example, calling a function with the wrong signature just to see whether
# the linker can find it). These couple of tests here though need to be compiled
# with -Werror to be effective.
cmake_push_check_state()
if(NOT DEFINED CMAKE_REQUIRED_FLAGS)
  set(CMAKE_REQUIRED_FLAGS "")
endif()
pcre2_warning_as_error(WARNING_AS_ERROR_FLAGS)
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${WARNING_AS_ERROR_FLAGS}")

check_c_source_compiles(
  "int main(void) { char buf[128] __attribute__((uninitialized)); (void)buf; return 0; }"
  HAVE_ATTRIBUTE_UNINITIALIZED
)

if(NOT MSVC)
  check_c_source_compiles(
    [=[
    extern __attribute__ ((visibility ("default"))) int f(void);
    int main(void) { return f(); }
    int f(void) { return 42; }
    ]=]
    HAVE_VISIBILITY
  )
endif()
if(CMAKE_C_COMPILE_OPTIONS_VISIBILITY AND NOT HAVE_VISIBILITY)
  # Hmm. We don't know of any way to set a symbol to have default visibility, other
  # than the common "__attribute__((visibility("default")))". But CMake thinks that
  # the compiler supports CMAKE_C_VISIBILITY_PRESET. The build is likely to fail to
  # generate a usable shared library.
  message(
    WARNING
    "C compiler uses the visibility flag ${CMAKE_C_COMPILE_OPTIONS_VISIBILITY}. We did not detect support for __attribute__((visibility(\"default\"))). We do not know how to set a symbol to have default visibility."
  )
elseif(HAVE_VISIBILITY AND NOT CMAKE_C_COMPILE_OPTIONS_VISIBILITY)
  # Here, the build may well work, but it's possible that CMake isn't correctly
  # suppressing the visibility of private symbols.
  message(
    WARNING
    "C compiler appears to support __attribute__((visibility(\"default\"))). However, CMake is not using a visibility flag. The visibility of private symbols may not be correct."
  )
endif()
if(HAVE_VISIBILITY)
  set(PCRE2_EXPORT [=[__attribute__ ((visibility ("default")))]=])
else()
  set(PCRE2_EXPORT)
endif()
cmake_pop_check_state()

check_c_source_compiles("int main(void) { __assume(1); return 0; }" HAVE_BUILTIN_ASSUME)

check_c_source_compiles(
  [=[
  #include <stddef.h>
  int main(void) { int a,b; size_t m; __builtin_mul_overflow(a,b,&m); return 0; }
  ]=]
  HAVE_BUILTIN_MUL_OVERFLOW
)

check_c_source_compiles(
  "int main(int c, char *v[]) { if (c) __builtin_unreachable(); return (int)(*v[0]); }"
  HAVE_BUILTIN_UNREACHABLE
)

# Detect support for linker scripts.

pcre2_check_vscript(HAVE_VSCRIPT VSCRIPT_FLAG)

# Check whether Intel CET is enabled, and if so, adjust compiler flags. This
# code was written by PH, trying to imitate the logic from the autotools
# configuration.

check_c_source_compiles(
  [=[
  #ifndef __CET__
  #error CET is not enabled
  #endif
  int main() { return 0; }
  ]=]
  INTEL_CET_ENABLED
)

if(INTEL_CET_ENABLED)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mshstk")
endif()

# User-configurable options
#
# Note: CMakeSetup displays these in alphabetical order, regardless of
# the order we use here.

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries.")

option(BUILD_STATIC_LIBS "Build static libraries." ON)

option(PCRE2_BUILD_PCRE2_8 "Build 8 bit PCRE2 library" ON)

option(PCRE2_BUILD_PCRE2_16 "Build 16 bit PCRE2 library" OFF)

option(PCRE2_BUILD_PCRE2_32 "Build 32 bit PCRE2 library" OFF)

option(PCRE2_STATIC_PIC "Build the static library with the option position independent code enabled." OFF)

set(PCRE2_DEBUG "IfDebugBuild" CACHE STRING "Include debugging code")
set_property(CACHE PCRE2_DEBUG PROPERTY STRINGS "IfDebugBuild" "ON" "OFF")

option(PCRE2_DISABLE_PERCENT_ZT "Disable the use of %zu and %td (rarely needed)" OFF)

set(
  PCRE2_EBCDIC
  OFF
  CACHE BOOL
  "Use EBCDIC coding instead of ASCII. (This is rarely used outside of mainframe systems.)"
)

set(PCRE2_EBCDIC_NL25 OFF CACHE BOOL "Use 0x25 as EBCDIC NL character instead of 0x15; implies EBCDIC.")

set(
  PCRE2_EBCDIC_IGNORING_COMPILER
  OFF
  CACHE BOOL
  "Force EBCDIC 1047 using numeric literals rather than C character literals; implies EBCDIC."
)

option(PCRE2_REBUILD_CHARTABLES "Rebuild char tables" OFF)

set(
  PCRE2_LINK_SIZE
  "2"
  CACHE STRING
  "Internal link size (2, 3 or 4 allowed). See LINK_SIZE in config.h.in for details."
)

set(
  PCRE2_PARENS_NEST_LIMIT
  "250"
  CACHE STRING
  "Default nested parentheses limit. See PARENS_NEST_LIMIT in config.h.in for details."
)

set(
  PCRE2_HEAP_LIMIT
  "20000000"
  CACHE STRING
  "Default limit on heap memory (kibibytes). See HEAP_LIMIT in config.h.in for details."
)

set(PCRE2_MAX_VARLOOKBEHIND "255" CACHE STRING "Default limit on variable lookbehinds.")

set(
  PCRE2_MATCH_LIMIT
  "10000000"
  CACHE STRING
  "Default limit on internal looping. See MATCH_LIMIT in config.h.in for details."
)

set(
  PCRE2_MATCH_LIMIT_DEPTH
  "MATCH_LIMIT"
  CACHE STRING
  "Default limit on internal depth of search. See MATCH_LIMIT_DEPTH in config.h.in for details."
)

set(
  PCRE2GREP_BUFSIZE
  "20480"
  CACHE STRING
  "Buffer starting size parameter for pcre2grep. See PCRE2GREP_BUFSIZE in config.h.in for details."
)

set(
  PCRE2GREP_MAX_BUFSIZE
  "1048576"
  CACHE STRING
  "Buffer maximum size parameter for pcre2grep. See PCRE2GREP_MAX_BUFSIZE in config.h.in for details."
)

set(PCRE2_NEWLINE "LF" CACHE STRING "What to recognize as a newline (one of CR, LF, CRLF, ANY, ANYCRLF, NUL).")

set(PCRE2_HEAP_MATCH_RECURSE OFF CACHE BOOL "Obsolete option: do not use")
mark_as_advanced(PCRE2_HEAP_MATCH_RECURSE)

set(PCRE2_SUPPORT_JIT OFF CACHE BOOL "Enable support for Just-in-time compiling.")

if(${CMAKE_SYSTEM_NAME} MATCHES Linux|NetBSD)
  set(PCRE2_SUPPORT_JIT_SEALLOC OFF CACHE BOOL "Enable SELinux compatible execmem allocator in JIT (experimental).")
else()
  set(PCRE2_SUPPORT_JIT_SEALLOC IGNORE)
endif()

set(PCRE2GREP_SUPPORT_JIT ON CACHE BOOL "Enable use of Just-in-time compiling in pcre2grep.")

set(PCRE2GREP_SUPPORT_CALLOUT ON CACHE BOOL "Enable callout string support in pcre2grep.")

set(PCRE2GREP_SUPPORT_CALLOUT_FORK ON CACHE BOOL "Enable callout string fork support in pcre2grep.")

set(PCRE2_SUPPORT_UNICODE ON CACHE BOOL "Enable support for Unicode and UTF-8/UTF-16/UTF-32 encoding.")

set(
  PCRE2_SUPPORT_BSR_ANYCRLF
  OFF
  CACHE BOOL
  "ON=Backslash-R matches only LF CR and CRLF, OFF=Backslash-R matches all Unicode Linebreaks"
)

set(PCRE2_NEVER_BACKSLASH_C OFF CACHE BOOL "If ON, backslash-C (upper case C) is locked out.")

set(PCRE2_SUPPORT_VALGRIND OFF CACHE BOOL "Enable Valgrind support.")

option(PCRE2_SHOW_REPORT "Show the final configuration report" ON)
option(PCRE2_BUILD_PCRE2GREP "Build pcre2grep" ON)
option(PCRE2_BUILD_TESTS "Build the tests" ON)

set(
  PCRE2_INSTALL_CMAKEDIR
  "${CMAKE_INSTALL_LIBDIR}/cmake/pcre2"
  CACHE STRING
  "Path used during CMake install for placing PCRE2's CMake config files, relative to the installation root (prefix)"
)

if(MINGW)
  option(
    NON_STANDARD_LIB_PREFIX
    "ON=Shared libraries built in mingw will be named pcre2.dll, etc., instead of libpcre2.dll, etc."
    OFF
  )

  option(
    NON_STANDARD_LIB_SUFFIX
    "ON=Shared libraries built in mingw will be named libpcre2-0.dll, etc., instead of libpcre2.dll, etc."
    OFF
  )
endif()

if(MSVC)
  option(INSTALL_MSVC_PDB "ON=Install .pdb files built by MSVC, if generated" OFF)
endif()

if(HAVE_VSCRIPT)
  option(PCRE2_SYMVERS "Enable library symbol versioning" ON)
endif()

# bzip2 lib
if(BZIP2_FOUND)
  option(PCRE2_SUPPORT_LIBBZ2 "Enable support for linking pcre2grep with libbz2." ON)
endif()

# zlib
if(ZLIB_FOUND)
  option(PCRE2_SUPPORT_LIBZ "Enable support for linking pcre2grep with libz." ON)
endif()

# editline lib
if(EDITLINE_FOUND)
  option(PCRE2_SUPPORT_LIBEDIT "Enable support for linking pcre2test with libedit." OFF)
endif()

# readline lib
if(READLINE_FOUND)
  option(PCRE2_SUPPORT_LIBREADLINE "Enable support for linking pcre2test with libreadline." ON)
endif()

# Prepare build configuration

include_directories(${PROJECT_BINARY_DIR}/interface ${PROJECT_BINARY_DIR}/src ${PROJECT_SOURCE_DIR}/src)

if(NOT BUILD_SHARED_LIBS AND NOT BUILD_STATIC_LIBS)
  message(FATAL_ERROR "At least one of BUILD_SHARED_LIBS or BUILD_STATIC_LIBS must be enabled.")
endif()

if(NOT PCRE2_BUILD_PCRE2_8 AND NOT PCRE2_BUILD_PCRE2_16 AND NOT PCRE2_BUILD_PCRE2_32)
  message(
    FATAL_ERROR
    "At least one of PCRE2_BUILD_PCRE2_8, PCRE2_BUILD_PCRE2_16 or PCRE2_BUILD_PCRE2_32 must be enabled"
  )
endif()

if(PCRE2_BUILD_PCRE2_8)
  set(SUPPORT_PCRE2_8 1)
endif()

if(PCRE2_BUILD_PCRE2_16)
  set(SUPPORT_PCRE2_16 1)
endif()

if(PCRE2_BUILD_PCRE2_32)
  set(SUPPORT_PCRE2_32 1)
endif()

if(PCRE2_BUILD_PCRE2GREP AND NOT PCRE2_BUILD_PCRE2_8)
  message(STATUS "** PCRE2_BUILD_PCRE2_8 must be enabled for the pcre2grep program")
  set(PCRE2_BUILD_PCRE2GREP OFF)
endif()

if(PCRE2_SUPPORT_LIBBZ2)
  if(BZIP2_FOUND)
    include_directories(${BZIP2_INCLUDE_DIR})
  else()
    message(
      FATAL_ERROR
      " libbz2 not found. Set BZIP2_INCLUDE_DIR to a compatible header\n"
      " or set BZip2_ROOT to a full bzip2 installed tree, as needed."
    )
  endif()
endif()

if(PCRE2_SUPPORT_LIBZ)
  if(ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIR})
  else()
    message(
      FATAL_ERROR
      " zlib not found. Set ZLIB_INCLUDE_DIR to a compatible header\n"
      " or set ZLIB_ROOT to a full zlib installed tree, as needed."
    )
  endif()
endif()

if(PCRE2_SUPPORT_LIBEDIT)
  if(EDITLINE_FOUND)
    include_directories(${EDITLINE_INCLUDE_DIR})
  else()
    message(
      FATAL_ERROR
      " libedit not found. Set EDITLINE_INCLUDE_DIR to a compatible header\n"
      " or set Editline_ROOT to a full libedit installed tree, as needed."
    )
  endif()
endif()

if(PCRE2_SUPPORT_LIBREADLINE)
  if(READLINE_FOUND)
    include_directories(${READLINE_INCLUDE_DIR})
  else()
    message(
      FATAL_ERROR
      " libreadline not found. Set READLINE_INCLUDE_DIR to a compatible header\n"
      " or set Readline_ROOT to a full libreadline installed tree, as needed."
    )
  endif()
endif()

if(PCRE2_SUPPORT_LIBREADLINE AND PCRE2_SUPPORT_LIBEDIT)
  if(READLINE_FOUND)
    message(
      FATAL_ERROR
      " Only one of the readline compatible libraries can be enabled.\n"
      " Disable libreadline with -DPCRE2_SUPPORT_LIBREADLINE=OFF"
    )
  endif()
endif()

if(PCRE2_SUPPORT_BSR_ANYCRLF)
  set(BSR_ANYCRLF 1)
endif()

if(PCRE2_NEVER_BACKSLASH_C)
  set(NEVER_BACKSLASH_C 1)
endif()

if(PCRE2_SUPPORT_UNICODE)
  set(SUPPORT_UNICODE 1)
endif()

if(PCRE2_SUPPORT_JIT)
  set(SUPPORT_JIT 1)
  if(UNIX)
    find_package(Threads REQUIRED)
    if(CMAKE_USE_PTHREADS_INIT)
      set(REQUIRE_PTHREAD 1)
    endif()
  endif()
endif()

if(PCRE2_SUPPORT_JIT_SEALLOC)
  set(SLJIT_PROT_EXECUTABLE_ALLOCATOR 1)
endif()

if(PCRE2GREP_SUPPORT_JIT)
  set(SUPPORT_PCRE2GREP_JIT 1)
endif()

if(PCRE2GREP_SUPPORT_CALLOUT)
  set(SUPPORT_PCRE2GREP_CALLOUT 1)
  if(PCRE2GREP_SUPPORT_CALLOUT_FORK)
    set(SUPPORT_PCRE2GREP_CALLOUT_FORK 1)
  endif()
endif()

if(PCRE2_SUPPORT_VALGRIND)
  set(SUPPORT_VALGRIND 1)
endif()

if(PCRE2_DISABLE_PERCENT_ZT)
  set(DISABLE_PERCENT_ZT 1)
endif()

set(PCRE2TEST_LIBS)
set(PCRE2GREP_LIBS)

# This next one used to reference ${READLINE_LIBRARY})
# but I was advised to add the NCURSES test as well, along with
# some modifications to cmake/FindReadline.cmake which should
# make it possible to override the default if necessary. PH

if(PCRE2_SUPPORT_LIBREADLINE)
  set(SUPPORT_LIBREADLINE 1)
  list(APPEND PCRE2TEST_LIBS ${READLINE_LIBRARY})
  if(DEFINED NCURSES_LIBRARY)
    list(APPEND PCRE2TEST_LIBS ${NCURSES_LIBRARY})
  endif()
endif()

# libedit is a plug-compatible alternative to libreadline

if(PCRE2_SUPPORT_LIBEDIT)
  set(SUPPORT_LIBEDIT 1)
  list(APPEND PCRE2TEST_LIBS ${EDITLINE_LIBRARY})
endif()

if(PCRE2_SUPPORT_LIBZ)
  set(SUPPORT_LIBZ 1)
  list(APPEND PCRE2GREP_LIBS ${ZLIB_LIBRARIES})
endif()

if(PCRE2_SUPPORT_LIBBZ2)
  set(SUPPORT_LIBBZ2 1)
  list(APPEND PCRE2GREP_LIBS ${BZIP2_LIBRARIES})
endif()

set(NEWLINE_DEFAULT "")

if(PCRE2_NEWLINE STREQUAL "CR")
  set(NEWLINE_DEFAULT "1")
endif()
if(PCRE2_NEWLINE STREQUAL "LF")
  set(NEWLINE_DEFAULT "2")
endif()
if(PCRE2_NEWLINE STREQUAL "CRLF")
  set(NEWLINE_DEFAULT "3")
endif()
if(PCRE2_NEWLINE STREQUAL "ANY")
  set(NEWLINE_DEFAULT "4")
endif()
if(PCRE2_NEWLINE STREQUAL "ANYCRLF")
  set(NEWLINE_DEFAULT "5")
endif()
if(PCRE2_NEWLINE STREQUAL "NUL")
  set(NEWLINE_DEFAULT "6")
endif()

if(NEWLINE_DEFAULT STREQUAL "")
  message(
    FATAL_ERROR
    "The PCRE2_NEWLINE variable must be set to one of the following values: \"LF\", \"CR\", \"CRLF\", \"ANY\", \"ANYCRLF\"."
  )
endif()

set(REBUILD_CHARTABLES OFF)
if(PCRE2_REBUILD_CHARTABLES)
  set(REBUILD_CHARTABLES ON)
endif()

set(EBCDIC OFF)
if(PCRE2_EBCDIC)
  set(EBCDIC ON)
endif()

if(PCRE2_EBCDIC_NL25)
  set(EBCDIC ON)
  set(EBCDIC_NL25 ON)
endif()

if(PCRE2_EBCDIC_IGNORING_COMPILER)
  set(EBCDIC ON)
  set(EBCDIC_IGNORING_COMPILER ON)
endif()

# Make sure that if EBCDIC is set (without EBCDIC_IGNORING_COMPILER), then
# REBUILD_CHARTABLES is also enabled.
# Also check that UTF support is not requested, because PCRE2 cannot handle
# EBCDIC and UTF in the same build. To do so it would need to use different
# character constants depending on the mode.
# Also, EBCDIC cannot be used with 16-bit and 32-bit libraries.
if(EBCDIC)
  if(NOT EBCDIC_IGNORING_COMPILER)
    set(REBUILD_CHARTABLES ON)
  endif()
  if(PCRE2_SUPPORT_UNICODE)
    message(FATAL_ERROR "Support for EBCDIC and Unicode cannot be enabled at the same time")
  endif()
  if(PCRE2_BUILD_PCRE2_16 OR PCRE2_BUILD_PCRE2_32)
    message(FATAL_ERROR "EBCDIC support is available only for the 8-bit library")
  endif()
endif()

# Remove the Autotools-generated copy of config.h and pcre2.h. I sometimes switch
# between Autoconf and CMake, and the conflicting copies of config.h generate some
# very unintuitive build errors.
file(REMOVE ${PROJECT_SOURCE_DIR}/src/config.h)
file(REMOVE ${PROJECT_SOURCE_DIR}/src/pcre2.h)

# Output files

configure_file(src/config-cmake.h.in ${PROJECT_BINARY_DIR}/src/config.h @ONLY)

# Parse version numbers and date out of configure.ac

file(
  STRINGS
  ${PROJECT_SOURCE_DIR}/configure.ac
  configure_lines
  LIMIT_COUNT
    50 # Read only the first 50 lines of the file
)

set(
  SEARCHED_VARIABLES
  "pcre2_major"
  "pcre2_minor"
  "pcre2_prerelease"
  "pcre2_date"
  "libpcre2_posix_version"
  "libpcre2_8_version"
  "libpcre2_16_version"
  "libpcre2_32_version"
)
foreach(configure_line ${configure_lines})
  foreach(substitution_variable ${SEARCHED_VARIABLES})
    string(TOUPPER ${substitution_variable} substitution_variable_upper)
    if(NOT DEFINED ${substitution_variable_upper})
      if("${configure_line}" MATCHES "m4_define\\(${substitution_variable}, *\\[(.*)\\]")
        set(${substitution_variable_upper} "${CMAKE_MATCH_1}")
      endif()
    endif()
  endforeach()
endforeach()

macro(PARSE_LIB_VERSION variable_prefix)
  string(REPLACE ":" ";" ${variable_prefix}_VERSION_LIST ${${variable_prefix}_VERSION})
  list(GET ${variable_prefix}_VERSION_LIST 0 ${variable_prefix}_VERSION_CURRENT)
  list(GET ${variable_prefix}_VERSION_LIST 1 ${variable_prefix}_VERSION_REVISION)
  list(GET ${variable_prefix}_VERSION_LIST 2 ${variable_prefix}_VERSION_AGE)

  math(EXPR ${variable_prefix}_SOVERSION "${${variable_prefix}_VERSION_CURRENT} - ${${variable_prefix}_VERSION_AGE}")
  math(EXPR ${variable_prefix}_MACHO_COMPATIBILITY_VERSION "${${variable_prefix}_VERSION_CURRENT} + 1")
  math(EXPR ${variable_prefix}_MACHO_CURRENT_VERSION "${${variable_prefix}_VERSION_CURRENT} + 1")
  set(
    ${variable_prefix}_MACHO_CURRENT_VERSION
    "${${variable_prefix}_MACHO_CURRENT_VERSION}.${${variable_prefix}_VERSION_REVISION}}"
  )
  set(
    ${variable_prefix}_VERSION
    "${${variable_prefix}_SOVERSION}.${${variable_prefix}_VERSION_AGE}.${${variable_prefix}_VERSION_REVISION}"
  )
endmacro()

parse_lib_version(LIBPCRE2_POSIX)
parse_lib_version(LIBPCRE2_8)
parse_lib_version(LIBPCRE2_16)
parse_lib_version(LIBPCRE2_32)

configure_file(src/pcre2.h.in ${PROJECT_BINARY_DIR}/interface/pcre2.h @ONLY)
configure_file(src/pcre2posix.h ${PROJECT_BINARY_DIR}/interface/pcre2posix.h COPYONLY)

# Make sure to not link debug libs
# against release libs and vice versa
if(WIN32)
  set(CMAKE_DEBUG_POSTFIX "d")
endif()

# Character table generation

if(REBUILD_CHARTABLES)
  add_executable(pcre2_dftables src/pcre2_dftables.c)
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/src/pcre2_chartables.c
    COMMAND pcre2_dftables
    ARGS ${PROJECT_BINARY_DIR}/src/pcre2_chartables.c
    DEPENDS pcre2_dftables
    COMMENT "Generating character tables (pcre2_chartables.c) for current locale"
    VERBATIM
  )
elseif(NOT PCRE2_EBCDIC)
  configure_file(
    ${PROJECT_SOURCE_DIR}/src/pcre2_chartables.c.dist
    ${PROJECT_BINARY_DIR}/src/pcre2_chartables.c
    COPYONLY
  )
elseif(PCRE2_EBCDIC_NL25)
  configure_file(
    ${PROJECT_SOURCE_DIR}/src/pcre2_chartables.c.ebcdic-1047-nl25
    ${PROJECT_BINARY_DIR}/src/pcre2_chartables.c
    COPYONLY
  )
else()
  configure_file(
    ${PROJECT_SOURCE_DIR}/src/pcre2_chartables.c.ebcdic-1047-nl15
    ${PROJECT_BINARY_DIR}/src/pcre2_chartables.c
    COPYONLY
  )
endif()

# Source code

set(PCRE2_HEADERS ${PROJECT_BINARY_DIR}/interface/pcre2.h)

set(
  PCRE2_SOURCES
  src/pcre2_auto_possess.c
  ${PROJECT_BINARY_DIR}/src/pcre2_chartables.c
  src/pcre2_chkdint.c
  src/pcre2_compile.c
  src/pcre2_compile_cgroup.c
  src/pcre2_compile_class.c
  src/pcre2_config.c
  src/pcre2_context.c
  src/pcre2_convert.c
  src/pcre2_dfa_match.c
  src/pcre2_error.c
  src/pcre2_extuni.c
  src/pcre2_find_bracket.c
  src/pcre2_jit_compile.c
  src/pcre2_maketables.c
  src/pcre2_match.c
  src/pcre2_match_data.c
  src/pcre2_match_next.c
  src/pcre2_newline.c
  src/pcre2_ord2utf.c
  src/pcre2_pattern_info.c
  src/pcre2_script_run.c
  src/pcre2_serialize.c
  src/pcre2_string_utils.c
  src/pcre2_study.c
  src/pcre2_substitute.c
  src/pcre2_substring.c
  src/pcre2_tables.c
  src/pcre2_ucd.c
  src/pcre2_valid_utf.c
  src/pcre2_xclass.c
)

set(PCRE2POSIX_HEADERS ${PROJECT_BINARY_DIR}/interface/pcre2posix.h)
set(PCRE2POSIX_SOURCES src/pcre2posix.c)

if(MINGW AND BUILD_SHARED_LIBS)
  if(EXISTS ${PROJECT_SOURCE_DIR}/pcre2.rc)
    add_custom_command(
      OUTPUT ${PROJECT_SOURCE_DIR}/pcre2.o PRE-LINK
      COMMAND windres
      ARGS pcre2.rc pcre2.o
      WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
      COMMENT "Using pcre2 coff info in mingw build"
    )
    list(APPEND PCRE2_SOURCES ${PROJECT_SOURCE_DIR}/pcre2.o)
  endif()

  if(EXISTS ${PROJECT_SOURCE_DIR}/pcre2posix.rc)
    add_custom_command(
      OUTPUT ${PROJECT_SOURCE_DIR}/pcre2posix.o PRE-LINK
      COMMAND windres
      ARGS pcre2posix.rc pcre2posix.o
      WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
      COMMENT "Using pcre2posix coff info in mingw build"
    )
    list(APPEND PCRE2POSIX_SOURCES ${PROJECT_SOURCE_DIR}/pcre2posix.o)
  endif()
endif()

if(MSVC AND BUILD_SHARED_LIBS)
  if(EXISTS ${PROJECT_SOURCE_DIR}/pcre2.rc)
    list(APPEND PCRE2_SOURCES pcre2.rc)
  endif()

  if(EXISTS ${PROJECT_SOURCE_DIR}/pcre2posix.rc)
    list(APPEND PCRE2POSIX_SOURCES pcre2posix.rc)
  endif()
endif()

# Build setup

add_compile_definitions(HAVE_CONFIG_H)

if(PCRE2_DEBUG STREQUAL "IfDebugBuild")
  add_compile_definitions("$<$<CONFIG:Debug>:PCRE2_DEBUG>")
elseif(PCRE2_DEBUG)
  add_compile_definitions("PCRE2_DEBUG")
endif()

if(MSVC)
  add_compile_definitions(_CRT_SECURE_NO_DEPRECATE _CRT_SECURE_NO_WARNINGS)
endif()

set(TARGETS)
set(DLL_PDB_FILES)
set(DLL_PDB_DEBUG_FILES)

# 8-bit library

if(PCRE2_BUILD_PCRE2_8)
  if(BUILD_STATIC_LIBS)
    add_library(pcre2-8-static STATIC ${PCRE2_HEADERS} ${PCRE2_SOURCES})
    set_target_properties(
      pcre2-8-static
      PROPERTIES
        COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=8
        MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_8_MACHO_COMPATIBILITY_VERSION}"
        MACHO_CURRENT_VERSION "${LIBPCRE2_8_MACHO_CURRENT_VERSION}"
        VERSION ${LIBPCRE2_8_VERSION}
        SOVERSION ${LIBPCRE2_8_SOVERSION}
    )
    target_compile_definitions(pcre2-8-static PUBLIC PCRE2_STATIC)
    target_include_directories(
      pcre2-8-static
      PUBLIC "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/interface>" "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
    if(REQUIRE_PTHREAD)
      target_link_libraries(pcre2-8-static Threads::Threads)
    endif()
    list(APPEND TARGETS pcre2-8-static)
    add_library(pcre2-posix-static STATIC ${PCRE2POSIX_HEADERS} ${PCRE2POSIX_SOURCES})
    set_target_properties(
      pcre2-posix-static
      PROPERTIES
        COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=8
        MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_POSIX_MACHO_COMPATIBILITY_VERSION}"
        MACHO_CURRENT_VERSION "${LIBPCRE2_POSIX_MACHO_CURRENT_VERSION}"
        VERSION ${LIBPCRE2_POSIX_VERSION}
        SOVERSION ${LIBPCRE2_POSIX_SOVERSION}
    )
    target_link_libraries(pcre2-posix-static pcre2-8-static)
    target_include_directories(
      pcre2-posix-static
      PUBLIC "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/interface>" "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
    list(APPEND TARGETS pcre2-posix-static)

    if(MSVC)
      set_target_properties(pcre2-8-static PROPERTIES OUTPUT_NAME pcre2-8-static)
      set_target_properties(pcre2-posix-static PROPERTIES OUTPUT_NAME pcre2-posix-static)
    else()
      set_target_properties(pcre2-8-static PROPERTIES OUTPUT_NAME pcre2-8)
      set_target_properties(pcre2-posix-static PROPERTIES OUTPUT_NAME pcre2-posix)
    endif()
    if(PCRE2_STATIC_PIC)
      set_target_properties(pcre2-8-static pcre2-posix-static PROPERTIES POSITION_INDEPENDENT_CODE 1)
    endif()
  endif()

  if(BUILD_SHARED_LIBS)
    add_library(pcre2-8-shared SHARED ${PCRE2_HEADERS} ${PCRE2_SOURCES})
    target_include_directories(
      pcre2-8-shared
      PUBLIC "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/interface>" "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
    set_target_properties(
      pcre2-8-shared
      PROPERTIES
        COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=8
        MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_8_MACHO_COMPATIBILITY_VERSION}"
        MACHO_CURRENT_VERSION "${LIBPCRE2_8_MACHO_CURRENT_VERSION}"
        VERSION ${LIBPCRE2_8_VERSION}
        SOVERSION ${LIBPCRE2_8_SOVERSION}
        OUTPUT_NAME pcre2-8
    )
    if(REQUIRE_PTHREAD)
      target_link_libraries(pcre2-8-shared Threads::Threads)
    endif()
    if(HAVE_VSCRIPT AND PCRE2_SYMVERS)
      target_link_options(pcre2-8-shared PRIVATE -Wl,${VSCRIPT_FLAG},${PROJECT_SOURCE_DIR}/src/libpcre2-8.sym)
      set_target_properties(pcre2-8-shared PROPERTIES LINK_DEPENDS ${PROJECT_SOURCE_DIR}/src/libpcre2-8.sym)
    endif()
    list(APPEND TARGETS pcre2-8-shared)
    list(APPEND DLL_PDB_FILES $<TARGET_PDB_FILE_DIR:pcre2-8-shared>/pcre2-8.pdb)
    list(APPEND DLL_PDB_DEBUG_FILES $<TARGET_PDB_FILE_DIR:pcre2-8-shared>/pcre2-8d.pdb)

    add_library(pcre2-posix-shared SHARED ${PCRE2POSIX_HEADERS} ${PCRE2POSIX_SOURCES})
    target_include_directories(
      pcre2-posix-shared
      PUBLIC "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/interface>" "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
    set_target_properties(
      pcre2-posix-shared
      PROPERTIES
        COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=8
        MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_POSIX_MACHO_COMPATIBILITY_VERSION}"
        MACHO_CURRENT_VERSION "${LIBPCRE2_POSIX_MACHO_CURRENT_VERSION}"
        VERSION ${LIBPCRE2_POSIX_VERSION}
        SOVERSION ${LIBPCRE2_POSIX_SOVERSION}
        OUTPUT_NAME pcre2-posix
    )
    if(HAVE_VSCRIPT AND PCRE2_SYMVERS)
      target_link_options(pcre2-posix-shared PRIVATE -Wl,${VSCRIPT_FLAG},${PROJECT_SOURCE_DIR}/src/libpcre2-posix.sym)
      set_target_properties(pcre2-posix-shared PROPERTIES LINK_DEPENDS ${PROJECT_SOURCE_DIR}/src/libpcre2-posix.sym)
    endif()
    target_compile_definitions(pcre2-posix-shared PUBLIC PCRE2POSIX_SHARED)
    target_link_libraries(pcre2-posix-shared pcre2-8-shared)
    list(APPEND TARGETS pcre2-posix-shared)
    list(APPEND DLL_PDB_FILES $<TARGET_PDB_FILE_DIR:pcre2-posix-shared>/pcre2-posix.pdb)
    list(APPEND DLL_PDB_DEBUG_FILES $<TARGET_PDB_FILE_DIR:pcre2-posix-shared>/pcre2-posixd.pdb)

    if(MINGW)
      if(NON_STANDARD_LIB_PREFIX)
        set_target_properties(pcre2-8-shared pcre2-posix-shared PROPERTIES PREFIX "")
      endif()
      if(NON_STANDARD_LIB_SUFFIX)
        set_target_properties(pcre2-8-shared pcre2-posix-shared PROPERTIES SUFFIX "-0.dll")
      endif()
    endif()
  endif()

  if(BUILD_STATIC_LIBS)
    add_library(pcre2-8 ALIAS pcre2-8-static)
    add_library(pcre2-posix ALIAS pcre2-posix-static)
  else()
    add_library(pcre2-8 ALIAS pcre2-8-shared)
    add_library(pcre2-posix ALIAS pcre2-posix-shared)
  endif()
endif()

# 16-bit library

if(PCRE2_BUILD_PCRE2_16)
  if(BUILD_STATIC_LIBS)
    add_library(pcre2-16-static STATIC ${PCRE2_HEADERS} ${PCRE2_SOURCES})
    target_include_directories(
      pcre2-16-static
      PUBLIC "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/interface>" "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
    set_target_properties(
      pcre2-16-static
      PROPERTIES
        COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=16
        MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_32_MACHO_COMPATIBILITY_VERSION}"
        MACHO_CURRENT_VERSION "${LIBPCRE2_32_MACHO_CURRENT_VERSION}"
        VERSION ${LIBPCRE2_16_VERSION}
        SOVERSION ${LIBPCRE2_16_SOVERSION}
    )
    target_compile_definitions(pcre2-16-static PUBLIC PCRE2_STATIC)
    if(REQUIRE_PTHREAD)
      target_link_libraries(pcre2-16-static Threads::Threads)
    endif()
    list(APPEND TARGETS pcre2-16-static)

    if(MSVC)
      set_target_properties(pcre2-16-static PROPERTIES OUTPUT_NAME pcre2-16-static)
    else()
      set_target_properties(pcre2-16-static PROPERTIES OUTPUT_NAME pcre2-16)
    endif()
    if(PCRE2_STATIC_PIC)
      set_target_properties(pcre2-16-static PROPERTIES POSITION_INDEPENDENT_CODE 1)
    endif()
  endif()

  if(BUILD_SHARED_LIBS)
    add_library(pcre2-16-shared SHARED ${PCRE2_HEADERS} ${PCRE2_SOURCES})
    target_include_directories(
      pcre2-16-shared
      PUBLIC "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/interface>" "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
    set_target_properties(
      pcre2-16-shared
      PROPERTIES
        COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=16
        MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_32_MACHO_COMPATIBILITY_VERSION}"
        MACHO_CURRENT_VERSION "${LIBPCRE2_32_MACHO_CURRENT_VERSION}"
        VERSION ${LIBPCRE2_16_VERSION}
        SOVERSION ${LIBPCRE2_16_SOVERSION}
        OUTPUT_NAME pcre2-16
    )
    if(REQUIRE_PTHREAD)
      target_link_libraries(pcre2-16-shared Threads::Threads)
    endif()
    if(HAVE_VSCRIPT AND PCRE2_SYMVERS)
      target_link_options(pcre2-16-shared PRIVATE -Wl,${VSCRIPT_FLAG},${PROJECT_SOURCE_DIR}/src/libpcre2-16.sym)
      set_target_properties(pcre2-16-shared PROPERTIES LINK_DEPENDS ${PROJECT_SOURCE_DIR}/src/libpcre2-16.sym)
    endif()
    list(APPEND TARGETS pcre2-16-shared)
    list(APPEND DLL_PDB_FILES $<TARGET_PDB_FILE_DIR:pcre2-16-shared>/pcre2-16.pdb)
    list(APPEND DLL_PDB_DEBUG_FILES $<TARGET_PDB_FILE_DIR:pcre2-16-shared>/pcre2-16d.pdb)

    if(MINGW)
      if(NON_STANDARD_LIB_PREFIX)
        set_target_properties(pcre2-16-shared PROPERTIES PREFIX "")
      endif()
      if(NON_STANDARD_LIB_SUFFIX)
        set_target_properties(pcre2-16-shared PROPERTIES SUFFIX "-0.dll")
      endif()
    endif()
  endif()

  if(BUILD_STATIC_LIBS)
    add_library(pcre2-16 ALIAS pcre2-16-static)
  else()
    add_library(pcre2-16 ALIAS pcre2-16-shared)
  endif()
endif()

# 32-bit library

if(PCRE2_BUILD_PCRE2_32)
  if(BUILD_STATIC_LIBS)
    add_library(pcre2-32-static STATIC ${PCRE2_HEADERS} ${PCRE2_SOURCES})
    target_include_directories(
      pcre2-32-static
      PUBLIC "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/interface>" "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
    set_target_properties(
      pcre2-32-static
      PROPERTIES
        COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=32
        MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_32_MACHO_COMPATIBILITY_VERSION}"
        MACHO_CURRENT_VERSION "${LIBPCRE2_32_MACHO_CURRENT_VERSION}"
        VERSION ${LIBPCRE2_32_VERSION}
        SOVERSION ${LIBPCRE2_32_SOVERSION}
    )
    target_compile_definitions(pcre2-32-static PUBLIC PCRE2_STATIC)
    if(REQUIRE_PTHREAD)
      target_link_libraries(pcre2-32-static Threads::Threads)
    endif()
    list(APPEND TARGETS pcre2-32-static)

    if(MSVC)
      set_target_properties(pcre2-32-static PROPERTIES OUTPUT_NAME pcre2-32-static)
    else()
      set_target_properties(pcre2-32-static PROPERTIES OUTPUT_NAME pcre2-32)
    endif()
    if(PCRE2_STATIC_PIC)
      set_target_properties(pcre2-32-static PROPERTIES POSITION_INDEPENDENT_CODE 1)
    endif()
  endif()

  if(BUILD_SHARED_LIBS)
    add_library(pcre2-32-shared SHARED ${PCRE2_HEADERS} ${PCRE2_SOURCES})
    target_include_directories(
      pcre2-32-shared
      PUBLIC "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/interface>" "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
    set_target_properties(
      pcre2-32-shared
      PROPERTIES
        COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=32
        MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_32_MACHO_COMPATIBILITY_VERSION}"
        MACHO_CURRENT_VERSION "${LIBPCRE2_32_MACHO_CURRENT_VERSION}"
        VERSION ${LIBPCRE2_32_VERSION}
        SOVERSION ${LIBPCRE2_32_SOVERSION}
        OUTPUT_NAME pcre2-32
    )
    if(REQUIRE_PTHREAD)
      target_link_libraries(pcre2-32-shared Threads::Threads)
    endif()
    if(HAVE_VSCRIPT AND PCRE2_SYMVERS)
      target_link_options(pcre2-32-shared PRIVATE -Wl,${VSCRIPT_FLAG},${PROJECT_SOURCE_DIR}/src/libpcre2-32.sym)
      set_target_properties(pcre2-32-shared PROPERTIES LINK_DEPENDS ${PROJECT_SOURCE_DIR}/src/libpcre2-32.sym)
    endif()
    list(APPEND TARGETS pcre2-32-shared)
    list(APPEND DLL_PDB_FILES $<TARGET_PDB_FILE_DIR:pcre2-32-shared>/pcre2-32.pdb)
    list(APPEND DLL_PDB_DEBUG_FILES $<TARGET_PDB_FILE_DIR:pcre2-32-shared>/pcre2-32d.pdb)

    if(MINGW)
      if(NON_STANDARD_LIB_PREFIX)
        set_target_properties(pcre2-32-shared PROPERTIES PREFIX "")
      endif()
      if(NON_STANDARD_LIB_SUFFIX)
        set_target_properties(pcre2-32-shared PROPERTIES SUFFIX "-0.dll")
      endif()
    endif()
  endif()

  if(BUILD_STATIC_LIBS)
    add_library(pcre2-32 ALIAS pcre2-32-static)
  else()
    add_library(pcre2-32 ALIAS pcre2-32-shared)
  endif()
endif()

# Generate pkg-config files

set(PACKAGE_VERSION "${PCRE2_MAJOR}.${PCRE2_MINOR}")
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix "\${prefix}")
set(libdir "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
set(includedir "\${prefix}/include")

set(LIB_POSTFIX "")
if(WIN32 AND (CMAKE_BUILD_TYPE MATCHES Debug))
  set(LIB_POSTFIX ${CMAKE_DEBUG_POSTFIX})
endif()

set(PCRE2_STATIC_CFLAG "")
if(NOT BUILD_SHARED_LIBS)
  set(PCRE2_STATIC_CFLAG "-DPCRE2_STATIC")
endif()

set(PCRE2POSIX_CFLAG "")
if(BUILD_SHARED_LIBS)
  set(PCRE2POSIX_CFLAG "-DPCRE2POSIX_SHARED")
endif()

set(PTHREAD_CFLAGS "")
set(PTHREAD_LIBS "")
if(REQUIRE_PTHREAD)
  set(PTHREAD_CFLAGS "$<TARGET_PROPERTY:Threads::Threads,INTERFACE_COMPILE_OPTIONS>")
  set(PTHREAD_LIBS "$<TARGET_PROPERTY:Threads::Threads,INTERFACE_LINK_LIBRARIES>")
endif()

if(PCRE2_BUILD_PCRE2_8)
  set(enable_pcre2_8 "yes")
else()
  set(enable_pcre2_8 "no")
endif()

if(PCRE2_BUILD_PCRE2_16)
  set(enable_pcre2_16 "yes")
else()
  set(enable_pcre2_16 "no")
endif()

if(PCRE2_BUILD_PCRE2_32)
  set(enable_pcre2_32 "yes")
else()
  set(enable_pcre2_32 "no")
endif()

configure_file(pcre2-config.in pcre2-config @ONLY NEWLINE_STYLE LF)

# Executables

if(PCRE2_BUILD_PCRE2GREP)
  add_executable(pcre2grep src/pcre2grep.c)
  set_property(TARGET pcre2grep PROPERTY COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=8)
  list(APPEND TARGETS pcre2grep)
  target_link_libraries(pcre2grep pcre2-posix ${PCRE2GREP_LIBS})
endif()

# Testing

if(PCRE2_BUILD_TESTS)
  enable_testing()

  set(PCRE2TEST_SOURCES src/pcre2test.c)

  set(PCRE2TEST_LINKER_FLAGS "")
  if(MSVC)
    # This is needed to avoid a stack overflow error in the standard tests. The
    # flag should be indicated with a forward-slash instead of a hyphen, but
    # then CMake treats it as a file path.
    set(PCRE2TEST_LINKER_FLAGS -STACK:2500000)
  endif()

  add_executable(pcre2test ${PCRE2TEST_SOURCES})
  list(APPEND TARGETS pcre2test)
  if(PCRE2_BUILD_PCRE2_8)
    list(APPEND PCRE2TEST_LIBS pcre2-posix pcre2-8)
  endif()
  if(PCRE2_BUILD_PCRE2_16)
    list(APPEND PCRE2TEST_LIBS pcre2-16)
  endif()
  if(PCRE2_BUILD_PCRE2_32)
    list(APPEND PCRE2TEST_LIBS pcre2-32)
  endif()
  target_link_libraries(pcre2test ${PCRE2TEST_LIBS} ${PCRE2TEST_LINKER_FLAGS})

  if(PCRE2_BUILD_PCRE2_8)
    add_executable(pcre2posix_test src/pcre2posix_test.c)
    target_link_libraries(pcre2posix_test pcre2-posix pcre2-8)
  endif()

  if(PCRE2_SUPPORT_JIT)
    add_executable(pcre2_jit_test src/pcre2_jit_test.c)
    set(PCRE2_JIT_TEST_LIBS)
    if(PCRE2_BUILD_PCRE2_8)
      list(APPEND PCRE2_JIT_TEST_LIBS pcre2-8)
    endif()
    if(PCRE2_BUILD_PCRE2_16)
      list(APPEND PCRE2_JIT_TEST_LIBS pcre2-16)
    endif()
    if(PCRE2_BUILD_PCRE2_32)
      list(APPEND PCRE2_JIT_TEST_LIBS pcre2-32)
    endif()
    target_link_libraries(pcre2_jit_test ${PCRE2_JIT_TEST_LIBS})
  endif()

  # =================================================
  # Write out a CTest configuration file
  #
  file(
    WRITE
    ${PROJECT_BINARY_DIR}/CTestCustom.ctest
    "# This is a generated file.
MESSAGE(\"When testing is complete, review test output in the
\\\"${PROJECT_BINARY_DIR}/Testing/Temporary\\\" folder.\")
MESSAGE(\" \")
"
  )

  file(
    WRITE
    ${PROJECT_BINARY_DIR}/pcre2_test.sh
    "#! /bin/sh
# This is a generated file.
srcdir=${PROJECT_SOURCE_DIR}
pcre2test=${PROJECT_BINARY_DIR}/pcre2test
test -z \"$CMAKE_CONFIG_TYPE\" || pcre2test=${PROJECT_BINARY_DIR}/$CMAKE_CONFIG_TYPE/pcre2test
. ${PROJECT_SOURCE_DIR}/RunTest
if test \"$?\" != \"0\"; then exit 1; fi
# End
"
  )

  if(UNIX)
    add_test(pcre2_test sh ${PROJECT_BINARY_DIR}/pcre2_test.sh)
  endif()

  if(PCRE2_BUILD_PCRE2GREP)
    file(
      WRITE
      ${PROJECT_BINARY_DIR}/pcre2_grep_test.sh
      "#! /bin/sh
# This is a generated file.
srcdir=${PROJECT_SOURCE_DIR}
pcre2grep=${PROJECT_BINARY_DIR}/pcre2grep
test -z \"$CMAKE_CONFIG_TYPE\" || pcre2grep=${PROJECT_BINARY_DIR}/$CMAKE_CONFIG_TYPE/pcre2grep
pcre2test=${PROJECT_BINARY_DIR}/pcre2test
test -z \"$CMAKE_CONFIG_TYPE\" || pcre2test=${PROJECT_BINARY_DIR}/$CMAKE_CONFIG_TYPE/pcre2test
. ${PROJECT_SOURCE_DIR}/RunGrepTest
if test \"$?\" != \"0\"; then exit 1; fi
# End
"
    )

    if(UNIX)
      add_test(pcre2_grep_test sh ${PROJECT_BINARY_DIR}/pcre2_grep_test.sh)

      if(PCRE2_EBCDIC)
        # The grep tests currently fail in EBCDIC mode because the test data
        # files are in ASCII. This could be fixed properly, but for now, we
        # have very few EBCDIC users and the pcre2grep utility is hardly even
        # part of the official project artifacts.
        set_property(TEST pcre2_grep_test PROPERTY WILL_FAIL TRUE)
      endif()
    endif()
  endif()

  if(WIN32)
    # Provide environment for executing the bat file version of RunTest
    file(TO_NATIVE_PATH ${PROJECT_SOURCE_DIR} winsrc)
    file(TO_NATIVE_PATH ${PROJECT_BINARY_DIR} winbin)

    file(
      WRITE
      ${PROJECT_BINARY_DIR}/pcre2_test.bat
      "\@REM This is a generated file.
\@echo off
setlocal
SET srcdir=\"${winsrc}\"
SET pcre2test=\"${winbin}\\pcre2test.exe\"
if not [%CMAKE_CONFIG_TYPE%]==[] SET pcre2test=\"${winbin}\\%CMAKE_CONFIG_TYPE%\\pcre2test.exe\"
call %srcdir%\\RunTest.bat
if errorlevel 1 exit /b 1
echo RunTest.bat tests successfully completed
"
    )

    add_test(NAME pcre2_test_bat COMMAND pcre2_test.bat)
    set_tests_properties(pcre2_test_bat PROPERTIES PASS_REGULAR_EXPRESSION "RunTest\\.bat tests successfully completed")

    if(PCRE2_BUILD_PCRE2GREP)
      file(
        WRITE
        ${PROJECT_BINARY_DIR}/pcre2_grep_test.bat
        "\@REM This is a generated file.
\@echo off
setlocal
SET srcdir=\"${winsrc}\"
SET pcre2test=\"${winbin}\\pcre2test.exe\"
if not [%CMAKE_CONFIG_TYPE%]==[] SET pcre2test=\"${winbin}\\%CMAKE_CONFIG_TYPE%\\pcre2test.exe\"
SET pcre2grep=\"${winbin}\\pcre2grep.exe\"
if not [%CMAKE_CONFIG_TYPE%]==[] SET pcre2grep=\"${winbin}\\%CMAKE_CONFIG_TYPE%\\pcre2grep.exe\"
call %srcdir%\\RunGrepTest.bat
if errorlevel 1 exit /b 1
echo RunGrepTest.bat tests successfully completed
"
      )

      add_test(NAME pcre2_grep_test_bat COMMAND pcre2_grep_test.bat)
      set_tests_properties(
        pcre2_grep_test_bat
        PROPERTIES PASS_REGULAR_EXPRESSION "RunGrepTest\\.bat tests successfully completed"
      )
    endif()

    if(DEFINED ENV{OSTYPE})
      if("$ENV{OSTYPE}" STREQUAL "msys")
        set(MSYS2 TRUE)
      endif()
    endif()
    if(MSYS2)
      # Both the sh and bat file versions of RunTest are run if make test is used
      # in msys
      add_test(pcre2_test_sh sh.exe ${PROJECT_BINARY_DIR}/pcre2_test.sh)
      if(PCRE2_BUILD_PCRE2GREP)
        add_test(pcre2_grep_test sh.exe ${PROJECT_BINARY_DIR}/pcre2_grep_test.sh)
      endif()
    endif()
  endif()

  # Changed to accommodate testing whichever location was just built

  if(PCRE2_SUPPORT_JIT)
    add_test(pcre2_jit_test pcre2_jit_test)
  endif()

  if(PCRE2_BUILD_PCRE2_8)
    add_test(pcre2posix_test pcre2posix_test)
  endif()
endif()

# Installation

set(CMAKE_INSTALL_ALWAYS 1)

install(
  TARGETS ${TARGETS}
  EXPORT pcre2-targets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(EXPORT pcre2-targets DESTINATION ${PCRE2_INSTALL_CMAKEDIR} NAMESPACE pcre2::)
install(FILES ${pkg_config_files} DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(
  FILES "${PROJECT_BINARY_DIR}/pcre2-config"
  DESTINATION ${CMAKE_INSTALL_BINDIR}
  # Set 0755 permissions
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

install(FILES ${PCRE2_HEADERS} ${PCRE2POSIX_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# CMake config files.
set(PCRE2_CONFIG_IN ${PROJECT_SOURCE_DIR}/cmake/pcre2-config.cmake.in)
set(PCRE2_CONFIG_OUT ${PROJECT_BINARY_DIR}/cmake/pcre2-config.cmake)
configure_package_config_file(${PCRE2_CONFIG_IN} ${PCRE2_CONFIG_OUT} INSTALL_DESTINATION ${PCRE2_INSTALL_CMAKEDIR})
set(PCRE2_CONFIG_VERSION_OUT ${PROJECT_BINARY_DIR}/cmake/pcre2-config-version.cmake)
write_basic_package_version_file(
  ${PCRE2_CONFIG_VERSION_OUT}
  VERSION ${PCRE2_MAJOR}.${PCRE2_MINOR}.0
  COMPATIBILITY SameMajorVersion
)
install(FILES ${PCRE2_CONFIG_OUT} ${PCRE2_CONFIG_VERSION_OUT} DESTINATION ${PCRE2_INSTALL_CMAKEDIR})

file(GLOB html ${PROJECT_SOURCE_DIR}/doc/html/*.html ${PROJECT_SOURCE_DIR}/doc/html/*.txt)
file(
  GLOB txts
  ${PROJECT_SOURCE_DIR}/doc/*.txt
  AUTHORS.md
  COPYING
  ChangeLog
  LICENCE.md
  NEWS
  README
  SECURITY.md
)
file(GLOB man1 ${PROJECT_SOURCE_DIR}/doc/*.1)
file(GLOB man3 ${PROJECT_SOURCE_DIR}/doc/*.3)

install(FILES ${man1} DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(FILES ${man3} DESTINATION ${CMAKE_INSTALL_MANDIR}/man3)
install(FILES ${txts} DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/pcre2)
install(FILES ${html} DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/pcre2/html)

if(MSVC AND INSTALL_MSVC_PDB)
  install(FILES ${DLL_PDB_FILES} DESTINATION ${CMAKE_INSTALL_BINDIR} CONFIGURATIONS RelWithDebInfo)
  install(FILES ${DLL_PDB_DEBUG_FILES} DESTINATION ${CMAKE_INSTALL_BINDIR} CONFIGURATIONS Debug)
endif()

# Help, only for nice output
if(BUILD_STATIC_LIBS)
  set(BUILD_STATIC_LIBS ON)
else()
  set(BUILD_STATIC_LIBS OFF)
endif()

if(PCRE2_HEAP_MATCH_RECURSE)
  message(WARNING "HEAP_MATCH_RECURSE is obsolete and does nothing.")
endif()

if(PCRE2_SHOW_REPORT)
  message(STATUS "")
  message(STATUS "")
  message(STATUS "PCRE2-${PCRE2_MAJOR}.${PCRE2_MINOR} configuration summary:")
  message(STATUS "")
  message(STATUS "  Install prefix .................... : ${CMAKE_INSTALL_PREFIX}")
  message(STATUS "  C compiler ........................ : ${CMAKE_C_COMPILER}")

  set(CFSP "")
  if(CMAKE_C_FLAGS)
    set(CFSP " ")
  endif()
  if(CMAKE_CONFIGURATION_TYPES)
    foreach(config IN LISTS CMAKE_CONFIGURATION_TYPES)
      string(TOUPPER "${config}" buildtype)
      string(LENGTH " (${config})" buildtypelen)
      math(EXPR dotslen "18 - ${buildtypelen}")
      string(REPEAT "." ${dotslen} dots)
      message(STATUS "  C compiler flags (${config}) ${dots} : ${CMAKE_C_FLAGS}${CFSP}${CMAKE_C_FLAGS_${buildtype}}")
    endforeach()
  else()
    string(TOUPPER "${CMAKE_BUILD_TYPE}" buildtype)
    if(buildtype STREQUAL "")
      set(CFBLD "")
    else()
      set(CFBLD "${CMAKE_C_FLAGS_${buildtype}}")
    endif()
    message(STATUS "  C compiler flags .................. : ${CMAKE_C_FLAGS}${CFSP}${CFBLD}")
  endif()

  message(STATUS "")
  if(CMAKE_CONFIGURATION_TYPES)
    message(STATUS "  Build configurations .............. : ${CMAKE_CONFIGURATION_TYPES}")
  else()
    message(STATUS "  Build type ........................ : ${CMAKE_BUILD_TYPE}")
  endif()
  message(STATUS "  Build 8 bit pcre2 library ......... : ${PCRE2_BUILD_PCRE2_8}")
  message(STATUS "  Build 16 bit pcre2 library ........ : ${PCRE2_BUILD_PCRE2_16}")
  message(STATUS "  Build 32 bit pcre2 library ........ : ${PCRE2_BUILD_PCRE2_32}")
  message(STATUS "  Include debugging code ............ : ${PCRE2_DEBUG}")
  message(STATUS "  Enable JIT compiling support ...... : ${PCRE2_SUPPORT_JIT}")
  message(STATUS "  Use SELinux allocator in JIT ...... : ${PCRE2_SUPPORT_JIT_SEALLOC}")
  message(STATUS "  Enable Unicode support ............ : ${PCRE2_SUPPORT_UNICODE}")
  message(STATUS "  Newline char/sequence ............. : ${PCRE2_NEWLINE}")
  message(STATUS "  \\R matches only ANYCRLF ........... : ${PCRE2_SUPPORT_BSR_ANYCRLF}")
  message(STATUS "  \\C is disabled .................... : ${PCRE2_NEVER_BACKSLASH_C}")

  if(NOT EBCDIC)
    set(EBCDIC_NL_CODE "n/a")
  elseif(EBCDIC_NL25)
    set(EBCDIC_NL_CODE "0x25")
  else()
    set(EBCDIC_NL_CODE "0x15")
  endif()
  message(STATUS "  EBCDIC coding ..................... : ${EBCDIC}")
  message(STATUS "  EBCDIC code for NL ................ : ${EBCDIC_NL_CODE}")
  message(STATUS "  EBCDIC coding ignoring compiler ... : ${PCRE2_EBCDIC_IGNORING_COMPILER}")
  message(STATUS "  Rebuild char tables ............... : ${REBUILD_CHARTABLES}")

  message(STATUS "  Internal link size ................ : ${PCRE2_LINK_SIZE}")
  message(STATUS "  Maximum variable lookbehind ....... : ${PCRE2_MAX_VARLOOKBEHIND}")
  message(STATUS "  Nested parentheses limit .......... : ${PCRE2_PARENS_NEST_LIMIT}")
  message(STATUS "  Heap limit ........................ : ${PCRE2_HEAP_LIMIT}")
  message(STATUS "  Match limit ....................... : ${PCRE2_MATCH_LIMIT}")
  message(STATUS "  Match depth limit ................. : ${PCRE2_MATCH_LIMIT_DEPTH}")
  message(STATUS "  Build shared libs ................. : ${BUILD_SHARED_LIBS}")
  if(NOT HAVE_VSCRIPT)
    message(STATUS "      with symbol versioning ........ : n/a")
  else()
    message(STATUS "      with symbol versioning ........ : ${PCRE2_SYMVERS}")
  endif()
  message(STATUS "  Build static libs ................. : ${BUILD_STATIC_LIBS}")
  message(STATUS "      with PIC enabled .............. : ${PCRE2_STATIC_PIC}")
  message(STATUS "  Build pcre2grep ................... : ${PCRE2_BUILD_PCRE2GREP}")
  message(STATUS "  Enable JIT in pcre2grep ........... : ${PCRE2GREP_SUPPORT_JIT}")
  message(STATUS "  Enable callouts in pcre2grep ...... : ${PCRE2GREP_SUPPORT_CALLOUT}")
  message(STATUS "  Enable callout fork in pcre2grep .. : ${PCRE2GREP_SUPPORT_CALLOUT_FORK}")
  message(STATUS "  Initial buffer size for pcre2grep . : ${PCRE2GREP_BUFSIZE}")
  message(STATUS "  Maximum buffer size for pcre2grep . : ${PCRE2GREP_MAX_BUFSIZE}")
  message(STATUS "  Build tests (implies pcre2test .... : ${PCRE2_BUILD_TESTS}")
  message(STATUS "               and pcre2grep)")
  if(ZLIB_FOUND)
    message(STATUS "  Link pcre2grep with libz .......... : ${PCRE2_SUPPORT_LIBZ}")
  else()
    message(STATUS "  Link pcre2grep with libz .......... : Library not found")
  endif()
  if(BZIP2_FOUND)
    message(STATUS "  Link pcre2grep with libbz2 ........ : ${PCRE2_SUPPORT_LIBBZ2}")
  else()
    message(STATUS "  Link pcre2grep with libbz2 ........ : Library not found")
  endif()
  if(EDITLINE_FOUND)
    message(STATUS "  Link pcre2test with libeditline ... : ${PCRE2_SUPPORT_LIBEDIT}")
  else()
    message(STATUS "  Link pcre2test with libeditline ... : Library not found")
  endif()
  if(READLINE_FOUND)
    message(STATUS "  Link pcre2test with libreadline ... : ${PCRE2_SUPPORT_LIBREADLINE}")
  else()
    message(STATUS "  Link pcre2test with libreadline ... : Library not found")
  endif()
  message(STATUS "  Enable Valgrind support ........... : ${PCRE2_SUPPORT_VALGRIND}")
  if(PCRE2_DISABLE_PERCENT_ZT)
    message(STATUS "  Use %zu and %td ................... : OFF")
  else()
    message(STATUS "  Use %zu and %td ................... : AUTO")
  endif()

  if(MINGW AND BUILD_SHARED_LIBS)
    message(STATUS "  Non-standard dll names (prefix) ... : ${NON_STANDARD_LIB_PREFIX}")
    message(STATUS "  Non-standard dll names (suffix) ... : ${NON_STANDARD_LIB_SUFFIX}")
  endif()

  if(MSVC)
    message(STATUS "  Install MSVC .pdb files ........... : ${INSTALL_MSVC_PDB}")
  endif()

  message(STATUS "")
endif()

# end CMakeLists.txt
