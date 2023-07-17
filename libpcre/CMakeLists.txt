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

# Increased minimum to 2.8.5 to support GNUInstallDirs.
# Increased minimum to 3.1 to support imported targets.
CMAKE_MINIMUM_REQUIRED(VERSION 3.1)
PROJECT(PCRE2 C)

# Set policy CMP0026 to avoid warnings for the use of LOCATION in
# GET_TARGET_PROPERTY. This should no longer be required.
# CMAKE_POLICY(SET CMP0026 OLD)

# With a recent cmake, you can provide a rootdir to look for non
# standard installed library dependencies, but to do so, the policy
# needs to be set to new (by uncommenting the following)
# CMAKE_POLICY(SET CMP0074 NEW)

# For FindReadline.cmake. This was changed to allow setting CMAKE_MODULE_PATH
# on the command line.
# SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

LIST(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src)

# Configuration checks

INCLUDE(CheckCSourceCompiles)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckIncludeFile)
INCLUDE(CheckTypeSize)
INCLUDE(GNUInstallDirs) # for CMAKE_INSTALL_LIBDIR

CHECK_INCLUDE_FILE(dirent.h     HAVE_DIRENT_H)
CHECK_INCLUDE_FILE(sys/stat.h   HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILE(sys/types.h  HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILE(unistd.h     HAVE_UNISTD_H)
CHECK_INCLUDE_FILE(windows.h    HAVE_WINDOWS_H)

CHECK_SYMBOL_EXISTS(bcopy         "strings.h"  HAVE_BCOPY)
CHECK_SYMBOL_EXISTS(memfd_create  "sys/mman.h" HAVE_MEMFD_CREATE)
CHECK_SYMBOL_EXISTS(memmove       "string.h"   HAVE_MEMMOVE)
CHECK_SYMBOL_EXISTS(secure_getenv "stdlib.h"   HAVE_SECURE_GETENV)
CHECK_SYMBOL_EXISTS(strerror      "string.h"   HAVE_STRERROR)

CHECK_C_SOURCE_COMPILES(
  "#include <stdlib.h>
   #include <limits.h>
   int main(int c, char *v[]) { char buf[PATH_MAX]; realpath(v[1], buf); return 0; }"
  HAVE_REALPATH
)

set(ORIG_CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS})
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -Werror")
CHECK_C_SOURCE_COMPILES(
  "int main() { char buf[128] __attribute__((uninitialized)); (void)buf; return 0; }"
  HAVE_ATTRIBUTE_UNINITIALIZED
)
set(CMAKE_REQUIRED_FLAGS ${ORIG_CMAKE_REQUIRED_FLAGS})

# Check whether Intel CET is enabled, and if so, adjust compiler flags. This
# code was written by PH, trying to imitate the logic from the autotools
# configuration.

CHECK_C_SOURCE_COMPILES(
  "#ifndef __CET__
   #error CET is not enabled
   #endif
   int main() { return 0; }"
  INTEL_CET_ENABLED
)

IF (INTEL_CET_ENABLED)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mshstk")
ENDIF(INTEL_CET_ENABLED)



# User-configurable options
#
# Note: CMakeSetup displays these in alphabetical order, regardless of
# the order we use here.

SET(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries.")

OPTION(BUILD_STATIC_LIBS "Build static libraries." ON)

OPTION(PCRE2_BUILD_PCRE2_8 "Build 8 bit PCRE2 library" ON)

OPTION(PCRE2_BUILD_PCRE2_16 "Build 16 bit PCRE2 library" OFF)

OPTION(PCRE2_BUILD_PCRE2_32 "Build 32 bit PCRE2 library" OFF)

OPTION(PCRE2_STATIC_PIC "Build the static library with the option position independent code enabled." OFF)

OPTION(PCRE2_DEBUG "Include debugging code" OFF)

OPTION(PCRE2_DISABLE_PERCENT_ZT "Disable the use of %zu and %td (rarely needed)" OFF)

SET(PCRE2_EBCDIC OFF CACHE BOOL
    "Use EBCDIC coding instead of ASCII. (This is rarely used outside of mainframe systems.)")

SET(PCRE2_EBCDIC_NL25 OFF CACHE BOOL
    "Use 0x25 as EBCDIC NL character instead of 0x15; implies EBCDIC.")

SET(PCRE2_LINK_SIZE "2" CACHE STRING
    "Internal link size (2, 3 or 4 allowed). See LINK_SIZE in config.h.in for details.")

SET(PCRE2_PARENS_NEST_LIMIT "250" CACHE STRING
    "Default nested parentheses limit. See PARENS_NEST_LIMIT in config.h.in for details.")

SET(PCRE2_HEAP_LIMIT "20000000" CACHE STRING
    "Default limit on heap memory (kibibytes). See HEAP_LIMIT in config.h.in for details.")

SET(PCRE2_MATCH_LIMIT "10000000" CACHE STRING
    "Default limit on internal looping. See MATCH_LIMIT in config.h.in for details.")

SET(PCRE2_MATCH_LIMIT_DEPTH "MATCH_LIMIT" CACHE STRING
    "Default limit on internal depth of search. See MATCH_LIMIT_DEPTH in config.h.in for details.")

SET(PCRE2_NEWLINE "LF" CACHE STRING
    "What to recognize as a newline (one of CR, LF, CRLF, ANY, ANYCRLF, NUL).")

SET(PCRE2_HEAP_MATCH_RECURSE OFF CACHE BOOL
    "Obsolete option: do not use")

SET(PCRE2_SUPPORT_UNICODE ON CACHE BOOL
    "Enable support for Unicode and UTF-8/UTF-16/UTF-32 encoding.")

SET(PCRE2_SUPPORT_BSR_ANYCRLF OFF CACHE BOOL
    "ON=Backslash-R matches only LF CR and CRLF, OFF=Backslash-R matches all Unicode Linebreaks")

SET(PCRE2_NEVER_BACKSLASH_C OFF CACHE BOOL
    "If ON, backslash-C (upper case C) is locked out.")

SET(PCRE2_SUPPORT_VALGRIND OFF CACHE BOOL
    "Enable Valgrind support.")

OPTION(PCRE2_SHOW_REPORT     "Show the final configuration report" ON)

IF (MINGW)
  OPTION(NON_STANDARD_LIB_PREFIX
         "ON=Shared libraries built in mingw will be named pcre2.dll, etc., instead of libpcre2.dll, etc."
         OFF)

  OPTION(NON_STANDARD_LIB_SUFFIX
         "ON=Shared libraries built in mingw will be named libpcre2-0.dll, etc., instead of libpcre2.dll, etc."
         OFF)
ENDIF(MINGW)

IF(MSVC)
  OPTION(PCRE2_STATIC_RUNTIME
	"ON=Compile against the static runtime (/MT)."
	OFF)
  OPTION(INSTALL_MSVC_PDB
         "ON=Install .pdb files built by MSVC, if generated"
         OFF)
ENDIF(MSVC)

# Prepare build configuration

IF(NOT BUILD_SHARED_LIBS AND NOT BUILD_STATIC_LIBS)
        MESSAGE(FATAL_ERROR "At least one of BUILD_SHARED_LIBS or BUILD_STATIC_LIBS must be enabled.")
ENDIF(NOT BUILD_SHARED_LIBS AND NOT BUILD_STATIC_LIBS)

IF(NOT PCRE2_BUILD_PCRE2_8 AND NOT PCRE2_BUILD_PCRE2_16 AND NOT PCRE2_BUILD_PCRE2_32)
        MESSAGE(FATAL_ERROR "At least one of PCRE2_BUILD_PCRE2_8, PCRE2_BUILD_PCRE2_16 or PCRE2_BUILD_PCRE2_32 must be enabled")
ENDIF(NOT PCRE2_BUILD_PCRE2_8 AND NOT PCRE2_BUILD_PCRE2_16 AND NOT PCRE2_BUILD_PCRE2_32)

IF(PCRE2_BUILD_PCRE2_8)
        SET(SUPPORT_PCRE2_8 1)
ENDIF(PCRE2_BUILD_PCRE2_8)

IF(PCRE2_BUILD_PCRE2_16)
        SET(SUPPORT_PCRE2_16 1)
ENDIF(PCRE2_BUILD_PCRE2_16)

IF(PCRE2_BUILD_PCRE2_32)
        SET(SUPPORT_PCRE2_32 1)
ENDIF(PCRE2_BUILD_PCRE2_32)

IF(PCRE2_SUPPORT_BSR_ANYCRLF)
        SET(BSR_ANYCRLF 1)
ENDIF(PCRE2_SUPPORT_BSR_ANYCRLF)

IF(PCRE2_NEVER_BACKSLASH_C)
        SET(NEVER_BACKSLASH_C 1)
ENDIF(PCRE2_NEVER_BACKSLASH_C)

IF(PCRE2_SUPPORT_UNICODE)
        SET(SUPPORT_UNICODE 1)
ENDIF(PCRE2_SUPPORT_UNICODE)

IF(PCRE2_SUPPORT_VALGRIND)
        SET(SUPPORT_VALGRIND 1)
ENDIF(PCRE2_SUPPORT_VALGRIND)

IF(PCRE2_DISABLE_PERCENT_ZT)
        SET(DISABLE_PERCENT_ZT 1)
ENDIF(PCRE2_DISABLE_PERCENT_ZT)

SET(NEWLINE_DEFAULT "")

IF(PCRE2_NEWLINE STREQUAL "CR")
        SET(NEWLINE_DEFAULT "1")
ENDIF(PCRE2_NEWLINE STREQUAL "CR")
IF(PCRE2_NEWLINE STREQUAL "LF")
        SET(NEWLINE_DEFAULT "2")
ENDIF(PCRE2_NEWLINE STREQUAL "LF")
IF(PCRE2_NEWLINE STREQUAL "CRLF")
        SET(NEWLINE_DEFAULT "3")
ENDIF(PCRE2_NEWLINE STREQUAL "CRLF")
IF(PCRE2_NEWLINE STREQUAL "ANY")
        SET(NEWLINE_DEFAULT "4")
ENDIF(PCRE2_NEWLINE STREQUAL "ANY")
IF(PCRE2_NEWLINE STREQUAL "ANYCRLF")
        SET(NEWLINE_DEFAULT "5")
ENDIF(PCRE2_NEWLINE STREQUAL "ANYCRLF")
IF(PCRE2_NEWLINE STREQUAL "NUL")
        SET(NEWLINE_DEFAULT "6")
ENDIF(PCRE2_NEWLINE STREQUAL "NUL")

IF(NEWLINE_DEFAULT STREQUAL "")
        MESSAGE(FATAL_ERROR "The PCRE2_NEWLINE variable must be set to one of the following values: \"LF\", \"CR\", \"CRLF\", \"ANY\", \"ANYCRLF\".")
ENDIF(NEWLINE_DEFAULT STREQUAL "")

IF(PCRE2_EBCDIC)
        SET(EBCDIC 1)
ENDIF(PCRE2_EBCDIC)

IF(PCRE2_EBCDIC_NL25)
        SET(EBCDIC 1)
        SET(EBCDIC_NL25 1)
ENDIF(PCRE2_EBCDIC_NL25)

# Output files

CONFIGURE_FILE(config-cmake.h.in
               ${PROJECT_BINARY_DIR}/config.h
               @ONLY)

# Parse version numbers and date out of configure.ac

file(STRINGS ${PROJECT_SOURCE_DIR}/configure.ac
  configure_lines
  LIMIT_COUNT 50 # Read only the first 50 lines of the file
)

set(SEARCHED_VARIABLES "pcre2_major" "pcre2_minor" "pcre2_prerelease" "pcre2_date"
  "libpcre2_posix_version" "libpcre2_8_version" "libpcre2_16_version" "libpcre2_32_version")
foreach(configure_line ${configure_lines})
    foreach(_substitution_variable ${SEARCHED_VARIABLES})
        string(TOUPPER ${_substitution_variable} _substitution_variable_upper)
        if (NOT ${_substitution_variable_upper})
            string(REGEX MATCH "m4_define\\(${_substitution_variable}, *\\[(.*)\\]" MATCHED_STRING ${configure_line})
            if (CMAKE_MATCH_1)
                set(${_substitution_variable_upper} ${CMAKE_MATCH_1})
            endif()
        endif()
    endforeach()
endforeach()

macro(PARSE_LIB_VERSION VARIABLE_PREFIX)
  string(REPLACE ":" ";" ${VARIABLE_PREFIX}_VERSION_LIST ${${VARIABLE_PREFIX}_VERSION})
  list(GET ${VARIABLE_PREFIX}_VERSION_LIST 0 ${VARIABLE_PREFIX}_VERSION_CURRENT)
  list(GET ${VARIABLE_PREFIX}_VERSION_LIST 1 ${VARIABLE_PREFIX}_VERSION_REVISION)
  list(GET ${VARIABLE_PREFIX}_VERSION_LIST 2 ${VARIABLE_PREFIX}_VERSION_AGE)

  math(EXPR ${VARIABLE_PREFIX}_SOVERSION "${${VARIABLE_PREFIX}_VERSION_CURRENT} - ${${VARIABLE_PREFIX}_VERSION_AGE}")
  math(EXPR ${VARIABLE_PREFIX}_MACHO_COMPATIBILITY_VERSION "${${VARIABLE_PREFIX}_VERSION_CURRENT} + 1")
  math(EXPR ${VARIABLE_PREFIX}_MACHO_CURRENT_VERSION "${${VARIABLE_PREFIX}_VERSION_CURRENT} + 1")
  set(${VARIABLE_PREFIX}_MACHO_CURRENT_VERSION "${${VARIABLE_PREFIX}_MACHO_CURRENT_VERSION}.${${VARIABLE_PREFIX}_VERSION_REVISION}}")
  set(${VARIABLE_PREFIX}_VERSION "${${VARIABLE_PREFIX}_SOVERSION}.${${VARIABLE_PREFIX}_VERSION_AGE}.${${VARIABLE_PREFIX}_VERSION_REVISION}")
endmacro()

PARSE_LIB_VERSION(LIBPCRE2_POSIX)
PARSE_LIB_VERSION(LIBPCRE2_8)
PARSE_LIB_VERSION(LIBPCRE2_16)
PARSE_LIB_VERSION(LIBPCRE2_32)

CONFIGURE_FILE(src/pcre2.h.in
               ${PROJECT_BINARY_DIR}/pcre2.h
               @ONLY)

# Make sure to not link debug libs
# against release libs and vice versa
IF(WIN32)
  SET(CMAKE_DEBUG_POSTFIX "d")
ENDIF(WIN32)

# Generate pkg-config files

SET(PACKAGE_VERSION "${PCRE2_MAJOR}.${PCRE2_MINOR}")
SET(prefix ${CMAKE_INSTALL_PREFIX})

SET(exec_prefix "\${prefix}")
SET(libdir "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
SET(includedir "\${prefix}/include")
IF(WIN32 AND (CMAKE_BUILD_TYPE MATCHES Debug))
  SET(LIB_POSTFIX ${CMAKE_DEBUG_POSTFIX})
ENDIF()

IF(PCRE2_BUILD_PCRE2_8)
  SET(enable_pcre2_8 "yes")
ELSE()
  SET(enable_pcre2_8 "no")
ENDIF()

IF(PCRE2_BUILD_PCRE2_16)
  SET(enable_pcre2_16 "yes")
ELSE()
  SET(enable_pcre2_16 "no")
ENDIF()

IF(PCRE2_BUILD_PCRE2_32)
  SET(enable_pcre2_32 "yes")
ELSE()
  SET(enable_pcre2_32 "no")
ENDIF()

CONFIGURE_FILE(pcre2-config.in pcre2-config @ONLY)

# Character table generation

OPTION(PCRE2_REBUILD_CHARTABLES "Rebuild char tables" OFF)
IF(PCRE2_REBUILD_CHARTABLES)
  ADD_EXECUTABLE(pcre2_dftables src/pcre2_dftables.c)
  ADD_CUSTOM_COMMAND(
    COMMENT "Generating character tables (pcre2_chartables.c) for current locale"
    DEPENDS pcre2_dftables
    COMMAND pcre2_dftables
    ARGS        ${PROJECT_BINARY_DIR}/pcre2_chartables.c
    OUTPUT      ${PROJECT_BINARY_DIR}/pcre2_chartables.c
  )
ELSE(PCRE2_REBUILD_CHARTABLES)
  CONFIGURE_FILE(${PROJECT_SOURCE_DIR}/src/pcre2_chartables.c.dist
                    ${PROJECT_BINARY_DIR}/pcre2_chartables.c
                    COPYONLY)
ENDIF(PCRE2_REBUILD_CHARTABLES)

# Source code

SET(PCRE2_HEADERS ${PROJECT_BINARY_DIR}/pcre2.h)

SET(PCRE2_SOURCES
  src/pcre2_auto_possess.c
  ${PROJECT_BINARY_DIR}/pcre2_chartables.c
  src/pcre2_compile.c
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

SET(PCRE2POSIX_HEADERS src/pcre2posix.h)
SET(PCRE2POSIX_SOURCES src/pcre2posix.c)

IF(MINGW AND BUILD_SHARED_LIBS)
  IF (EXISTS ${PROJECT_SOURCE_DIR}/pcre2.rc)
    ADD_CUSTOM_COMMAND(OUTPUT ${PROJECT_SOURCE_DIR}/pcre2.o
      PRE-LINK
      COMMAND windres ARGS pcre2.rc pcre2.o
      WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
      COMMENT Using pcre2 coff info in mingw build)
    SET(PCRE2_SOURCES ${PCRE2_SOURCES} ${PROJECT_SOURCE_DIR}/pcre2.o)
  ENDIF(EXISTS ${PROJECT_SOURCE_DIR}/pcre2.rc)

  IF (EXISTS ${PROJECT_SOURCE_DIR}/pcre2posix.rc)
    ADD_CUSTOM_COMMAND(OUTPUT ${PROJECT_SOURCE_DIR}/pcre2posix.o
      PRE-LINK
      COMMAND windres ARGS pcre2posix.rc pcre2posix.o
      WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
      COMMENT Using pcre2posix coff info in mingw build)
    SET(PCRE2POSIX_SOURCES ${PCRE2POSIX_SOURCES} ${PROJECT_SOURCE_DIR}/pcre2posix.o)
  ENDIF(EXISTS ${PROJECT_SOURCE_DIR}/pcre2posix.rc)
ENDIF(MINGW AND BUILD_SHARED_LIBS)

IF(MSVC AND BUILD_SHARED_LIBS)
  SET(dll_pdb_files ${PROJECT_BINARY_DIR}/pcre2-posix.pdb ${dll_pdb_files})
  SET(dll_pdb_debug_files ${PROJECT_BINARY_DIR}/pcre2-posixd.pdb ${dll_pdb_debug_files})
  IF (EXISTS ${PROJECT_SOURCE_DIR}/pcre2.rc)
    SET(PCRE2_SOURCES ${PCRE2_SOURCES} pcre2.rc)
  ENDIF(EXISTS ${PROJECT_SOURCE_DIR}/pcre2.rc)

  IF (EXISTS ${PROJECT_SOURCE_DIR}/pcre2posix.rc)
    SET(PCRE2POSIX_SOURCES ${PCRE2POSIX_SOURCES} pcre2posix.rc)
  ENDIF (EXISTS ${PROJECT_SOURCE_DIR}/pcre2posix.rc)
ENDIF(MSVC AND BUILD_SHARED_LIBS)

# Fix static compilation with MSVC: https://bugs.exim.org/show_bug.cgi?id=1681
# This code was taken from the CMake wiki, not from WebM.

IF(MSVC AND PCRE2_STATIC_RUNTIME)
  MESSAGE(STATUS "** MSVC and PCRE2_STATIC_RUNTIME: modifying compiler flags to use static runtime library")
  foreach(flag_var
          CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
          CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO)
    string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
  endforeach()
ENDIF(MSVC AND PCRE2_STATIC_RUNTIME)

# Build setup

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

IF(MSVC)
  ADD_DEFINITIONS(-D_CRT_SECURE_NO_DEPRECATE -D_CRT_SECURE_NO_WARNINGS)
ENDIF(MSVC)

SET(CMAKE_INCLUDE_CURRENT_DIR 1)

SET(targets)

# 8-bit library

IF(PCRE2_BUILD_PCRE2_8)
  IF(BUILD_STATIC_LIBS)
    ADD_LIBRARY(pcre2-8-static STATIC ${PCRE2_HEADERS} ${PCRE2_SOURCES} ${PROJECT_BINARY_DIR}/config.h)
    SET_TARGET_PROPERTIES(pcre2-8-static PROPERTIES
      COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=8
      MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_8_MACHO_COMPATIBILITY_VERSION}"
      MACHO_CURRENT_VERSION "${LIBPCRE2_8_MACHO_CURRENT_VERSION}"
      VERSION ${LIBPCRE2_8_VERSION}
      SOVERSION ${LIBPCRE2_8_SOVERSION})
    TARGET_COMPILE_DEFINITIONS(pcre2-8-static PUBLIC PCRE2_STATIC)
    TARGET_INCLUDE_DIRECTORIES(pcre2-8-static PUBLIC ${PROJECT_BINARY_DIR})
    IF(REQUIRE_PTHREAD)
        TARGET_LINK_LIBRARIES(pcre2-8-static Threads::Threads)
    ENDIF(REQUIRE_PTHREAD)
    SET(targets ${targets} pcre2-8-static)
    ADD_LIBRARY(pcre2-posix-static STATIC ${PCRE2POSIX_HEADERS} ${PCRE2POSIX_SOURCES})
    SET_TARGET_PROPERTIES(pcre2-posix-static PROPERTIES
      COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=8
      MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_POSIX_MACHO_COMPATIBILITY_VERSION}"
      MACHO_CURRENT_VERSION "${LIBPCRE2_POSIX_MACHO_CURRENT_VERSION}"
      VERSION ${LIBPCRE2_POSIX_VERSION}
      SOVERSION ${LIBPCRE2_POSIX_SOVERSION})
    TARGET_LINK_LIBRARIES(pcre2-posix-static pcre2-8-static)
    TARGET_COMPILE_DEFINITIONS(pcre2-posix-static PUBLIC PCRE2_STATIC)
    TARGET_INCLUDE_DIRECTORIES(pcre2-posix-static PUBLIC ${PROJECT_BINARY_DIR})
    SET(targets ${targets} pcre2-posix-static)

    IF(MSVC)
      SET_TARGET_PROPERTIES(pcre2-8-static PROPERTIES OUTPUT_NAME pcre2-8-static)
      SET_TARGET_PROPERTIES(pcre2-posix-static PROPERTIES OUTPUT_NAME pcre2-posix-static)
    ELSE(MSVC)
      SET_TARGET_PROPERTIES(pcre2-8-static PROPERTIES OUTPUT_NAME pcre2-8)
      SET_TARGET_PROPERTIES(pcre2-posix-static PROPERTIES OUTPUT_NAME pcre2-posix)
    ENDIF(MSVC)
    IF(PCRE2_STATIC_PIC)
      SET_TARGET_PROPERTIES(pcre2-8-static pcre2-posix-static PROPERTIES POSITION_INDEPENDENT_CODE 1)
    ENDIF(PCRE2_STATIC_PIC)
  ENDIF(BUILD_STATIC_LIBS)

  IF(BUILD_SHARED_LIBS)
    ADD_LIBRARY(pcre2-8-shared SHARED ${PCRE2_HEADERS} ${PCRE2_SOURCES} ${PROJECT_BINARY_DIR}/config.h)
    TARGET_INCLUDE_DIRECTORIES(pcre2-8-shared PUBLIC ${PROJECT_BINARY_DIR})
    SET_TARGET_PROPERTIES(pcre2-8-shared PROPERTIES
      COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=8
      MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_8_MACHO_COMPATIBILITY_VERSION}"
      MACHO_CURRENT_VERSION "${LIBPCRE2_8_MACHO_CURRENT_VERSION}"
      VERSION ${LIBPCRE2_8_VERSION}
      SOVERSION ${LIBPCRE2_8_SOVERSION}
      OUTPUT_NAME pcre2-8)
    IF(REQUIRE_PTHREAD)
        TARGET_LINK_LIBRARIES(pcre2-8-shared Threads::Threads)
    ENDIF(REQUIRE_PTHREAD)
    SET(targets ${targets} pcre2-8-shared)
    ADD_LIBRARY(pcre2-posix-shared SHARED ${PCRE2POSIX_HEADERS} ${PCRE2POSIX_SOURCES})
    TARGET_INCLUDE_DIRECTORIES(pcre2-posix-shared PUBLIC ${PROJECT_BINARY_DIR})
    SET_TARGET_PROPERTIES(pcre2-posix-shared PROPERTIES
      COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=8
      MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_POSIX_MACHO_COMPATIBILITY_VERSION}"
      MACHO_CURRENT_VERSION "${LIBPCRE2_POSIX_MACHO_CURRENT_VERSION}"
      VERSION ${LIBPCRE2_POSIX_VERSION}
      SOVERSION ${LIBPCRE2_POSIX_SOVERSION}
      OUTPUT_NAME pcre2-posix)
    TARGET_LINK_LIBRARIES(pcre2-posix-shared pcre2-8-shared)
    SET(targets ${targets} pcre2-posix-shared)
    SET(dll_pdb_files ${PROJECT_BINARY_DIR}/pcre2-8.pdb ${dll_pdb_files})
    SET(dll_pdb_debug_files ${PROJECT_BINARY_DIR}/pcre2-8d.pdb ${dll_pdb_debug_files})

    IF(MINGW)
      IF(NON_STANDARD_LIB_PREFIX)
        SET_TARGET_PROPERTIES(pcre2-8-shared pcre2-posix-shared PROPERTIES PREFIX "")
      ENDIF(NON_STANDARD_LIB_PREFIX)
      IF(NON_STANDARD_LIB_SUFFIX)
        SET_TARGET_PROPERTIES(pcre2-8-shared pcre2-posix-shared PROPERTIES SUFFIX "-0.dll")
      ENDIF(NON_STANDARD_LIB_SUFFIX)
    ENDIF(MINGW)
  ENDIF(BUILD_SHARED_LIBS)

  IF(BUILD_STATIC_LIBS)
    ADD_LIBRARY(pcre2-8 ALIAS pcre2-8-static)
    ADD_LIBRARY(pcre2-posix ALIAS pcre2-posix-static)
  ELSE(BUILD_STATIC_LIBS)
    ADD_LIBRARY(pcre2-8 ALIAS pcre2-8-shared)
    ADD_LIBRARY(pcre2-posix ALIAS pcre2-posix-shared)
  ENDIF(BUILD_STATIC_LIBS)
ENDIF(PCRE2_BUILD_PCRE2_8)

# 16-bit library

IF(PCRE2_BUILD_PCRE2_16)
  IF(BUILD_STATIC_LIBS)
    ADD_LIBRARY(pcre2-16-static STATIC ${PCRE2_HEADERS} ${PCRE2_SOURCES} ${PROJECT_BINARY_DIR}/config.h)
    TARGET_INCLUDE_DIRECTORIES(pcre2-16-static PUBLIC ${PROJECT_BINARY_DIR})
    SET_TARGET_PROPERTIES(pcre2-16-static PROPERTIES
      COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=16
      MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_32_MACHO_COMPATIBILITY_VERSION}"
      MACHO_CURRENT_VERSION "${LIBPCRE2_32_MACHO_CURRENT_VERSION}"
      VERSION ${LIBPCRE2_16_VERSION}
      SOVERSION ${LIBPCRE2_16_SOVERSION})
    TARGET_COMPILE_DEFINITIONS(pcre2-16-static PUBLIC PCRE2_STATIC)
    IF(REQUIRE_PTHREAD)
      TARGET_LINK_LIBRARIES(pcre2-16-static Threads::Threads)
    ENDIF(REQUIRE_PTHREAD)
    SET(targets ${targets} pcre2-16-static)

    IF(MSVC)
      SET_TARGET_PROPERTIES(pcre2-16-static PROPERTIES OUTPUT_NAME pcre2-16-static)
    ELSE(MSVC)
      SET_TARGET_PROPERTIES(pcre2-16-static PROPERTIES OUTPUT_NAME pcre2-16)
    ENDIF(MSVC)
    IF(PCRE2_STATIC_PIC)
      SET_TARGET_PROPERTIES(pcre2-16-static PROPERTIES POSITION_INDEPENDENT_CODE 1)
    ENDIF(PCRE2_STATIC_PIC)
  ENDIF(BUILD_STATIC_LIBS)

  IF(BUILD_SHARED_LIBS)
    ADD_LIBRARY(pcre2-16-shared SHARED ${PCRE2_HEADERS} ${PCRE2_SOURCES} ${PROJECT_BINARY_DIR}/config.h)
    TARGET_INCLUDE_DIRECTORIES(pcre2-16-shared PUBLIC ${PROJECT_BINARY_DIR})
    SET_TARGET_PROPERTIES(pcre2-16-shared PROPERTIES
      COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=16
      MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_32_MACHO_COMPATIBILITY_VERSION}"
      MACHO_CURRENT_VERSION "${LIBPCRE2_32_MACHO_CURRENT_VERSION}"
      VERSION ${LIBPCRE2_16_VERSION}
      SOVERSION ${LIBPCRE2_16_SOVERSION}
      OUTPUT_NAME pcre2-16)
    IF(REQUIRE_PTHREAD)
      TARGET_LINK_LIBRARIES(pcre2-16-shared Threads::Threads)
    ENDIF(REQUIRE_PTHREAD)
    SET(targets ${targets} pcre2-16-shared)
    SET(dll_pdb_files ${PROJECT_BINARY_DIR}/pcre2-16.pdb ${dll_pdb_files})
    SET(dll_pdb_debug_files ${PROJECT_BINARY_DIR}/pcre2-16d.pdb ${dll_pdb_debug_files})

    IF(MINGW)
      IF(NON_STANDARD_LIB_PREFIX)
        SET_TARGET_PROPERTIES(pcre2-16-shared PROPERTIES PREFIX "")
      ENDIF(NON_STANDARD_LIB_PREFIX)
      IF(NON_STANDARD_LIB_SUFFIX)
        SET_TARGET_PROPERTIES(pcre2-16-shared PROPERTIES SUFFIX "-0.dll")
      ENDIF(NON_STANDARD_LIB_SUFFIX)
    ENDIF(MINGW)
  ENDIF(BUILD_SHARED_LIBS)

  IF(BUILD_STATIC_LIBS)
    ADD_LIBRARY(pcre2-16 ALIAS pcre2-16-static)
  ELSE(BUILD_STATIC_LIBS)
    ADD_LIBRARY(pcre2-16 ALIAS pcre2-16-shared)
  ENDIF(BUILD_STATIC_LIBS)
ENDIF(PCRE2_BUILD_PCRE2_16)

# 32-bit library

IF(PCRE2_BUILD_PCRE2_32)
  IF(BUILD_STATIC_LIBS)
    ADD_LIBRARY(pcre2-32-static STATIC ${PCRE2_HEADERS} ${PCRE2_SOURCES} ${PROJECT_BINARY_DIR}/config.h)
    TARGET_INCLUDE_DIRECTORIES(pcre2-32-static PUBLIC ${PROJECT_BINARY_DIR})
    SET_TARGET_PROPERTIES(pcre2-32-static PROPERTIES
      COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=32
      MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_32_MACHO_COMPATIBILITY_VERSION}"
      MACHO_CURRENT_VERSION "${LIBPCRE2_32_MACHO_CURRENT_VERSION}"
      VERSION ${LIBPCRE2_32_VERSION}
      SOVERSION ${LIBPCRE2_32_SOVERSION})
    TARGET_COMPILE_DEFINITIONS(pcre2-32-static PUBLIC PCRE2_STATIC)
    IF(REQUIRE_PTHREAD)
      TARGET_LINK_LIBRARIES(pcre2-32-static Threads::Threads)
    ENDIF(REQUIRE_PTHREAD)
    SET(targets ${targets} pcre2-32-static)

    IF(MSVC)
      SET_TARGET_PROPERTIES(pcre2-32-static PROPERTIES OUTPUT_NAME pcre2-32-static)
    ELSE(MSVC)
      SET_TARGET_PROPERTIES(pcre2-32-static PROPERTIES OUTPUT_NAME pcre2-32)
    ENDIF(MSVC)
    IF(PCRE2_STATIC_PIC)
      SET_TARGET_PROPERTIES(pcre2-32-static PROPERTIES POSITION_INDEPENDENT_CODE 1)
    ENDIF(PCRE2_STATIC_PIC)
  ENDIF(BUILD_STATIC_LIBS)

  IF(BUILD_SHARED_LIBS)
    ADD_LIBRARY(pcre2-32-shared SHARED ${PCRE2_HEADERS} ${PCRE2_SOURCES} ${PROJECT_BINARY_DIR}/config.h)
    TARGET_INCLUDE_DIRECTORIES(pcre2-32-shared PUBLIC ${PROJECT_BINARY_DIR})
    SET_TARGET_PROPERTIES(pcre2-32-shared PROPERTIES
      COMPILE_DEFINITIONS PCRE2_CODE_UNIT_WIDTH=32
      MACHO_COMPATIBILITY_VERSION "${LIBPCRE2_32_MACHO_COMPATIBILITY_VERSION}"
      MACHO_CURRENT_VERSION "${LIBPCRE2_32_MACHO_CURRENT_VERSION}"
      VERSION ${LIBPCRE2_32_VERSION}
      SOVERSION ${LIBPCRE2_32_SOVERSION}
      OUTPUT_NAME pcre2-32)
    IF(REQUIRE_PTHREAD)
      TARGET_LINK_LIBRARIES(pcre2-32-shared Threads::Threads)
    ENDIF(REQUIRE_PTHREAD)
    SET(targets ${targets} pcre2-32-shared)
    SET(dll_pdb_files ${PROJECT_BINARY_DIR}/pcre2-32.pdb ${dll_pdb_files})
    SET(dll_pdb_debug_files ${PROJECT_BINARY_DIR}/pcre2-32d.pdb ${dll_pdb_debug_files})

    IF(MINGW)
      IF(NON_STANDARD_LIB_PREFIX)
        SET_TARGET_PROPERTIES(pcre2-32-shared PROPERTIES PREFIX "")
      ENDIF(NON_STANDARD_LIB_PREFIX)
      IF(NON_STANDARD_LIB_SUFFIX)
        SET_TARGET_PROPERTIES(pcre2-32-shared PROPERTIES SUFFIX "-0.dll")
      ENDIF(NON_STANDARD_LIB_SUFFIX)
    ENDIF(MINGW)
  ENDIF(BUILD_SHARED_LIBS)

  IF(BUILD_STATIC_LIBS)
    ADD_LIBRARY(pcre2-32 ALIAS pcre2-32-static)
  ELSE(BUILD_STATIC_LIBS)
    ADD_LIBRARY(pcre2-32 ALIAS pcre2-32-shared)
  ENDIF(BUILD_STATIC_LIBS)
ENDIF(PCRE2_BUILD_PCRE2_32)

# Executables

# Testing

# Installation

SET(CMAKE_INSTALL_ALWAYS 1)

INSTALL(TARGETS ${targets}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
INSTALL(FILES ${pkg_config_files} DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/pcre2-config"
  DESTINATION bin
  # Set 0755 permissions
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

INSTALL(FILES ${PCRE2_HEADERS} ${PCRE2POSIX_HEADERS} DESTINATION include)

# CMake config files.
set(PCRE2_CONFIG_IN  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/pcre2-config.cmake.in)
set(PCRE2_CONFIG_OUT ${CMAKE_CURRENT_BINARY_DIR}/cmake/pcre2-config.cmake)
configure_file(${PCRE2_CONFIG_IN} ${PCRE2_CONFIG_OUT} @ONLY)
set(PCRE2_CONFIG_VERSION_IN  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/pcre2-config-version.cmake.in)
set(PCRE2_CONFIG_VERSION_OUT ${CMAKE_CURRENT_BINARY_DIR}/cmake/pcre2-config-version.cmake)
configure_file(${PCRE2_CONFIG_VERSION_IN} ${PCRE2_CONFIG_VERSION_OUT} @ONLY)
install(FILES ${PCRE2_CONFIG_OUT} ${PCRE2_CONFIG_VERSION_OUT} DESTINATION cmake)

IF(MSVC AND INSTALL_MSVC_PDB)
 INSTALL(FILES ${dll_pdb_files} DESTINATION bin CONFIGURATIONS RelWithDebInfo)
 INSTALL(FILES ${dll_pdb_debug_files} DESTINATION bin CONFIGURATIONS Debug)
ENDIF(MSVC AND INSTALL_MSVC_PDB)

# Help, only for nice output
IF(BUILD_STATIC_LIBS)
  SET(BUILD_STATIC_LIBS ON)
ELSE(BUILD_STATIC_LIBS)
  SET(BUILD_STATIC_LIBS OFF)
ENDIF(BUILD_STATIC_LIBS)

IF(PCRE2_HEAP_MATCH_RECURSE)
  MESSAGE(WARNING "HEAP_MATCH_RECURSE is obsolete and does nothing.")
ENDIF(PCRE2_HEAP_MATCH_RECURSE)

IF(PCRE2_SHOW_REPORT)
  STRING(TOUPPER "${CMAKE_BUILD_TYPE}" buildtype)
  IF (CMAKE_C_FLAGS)
    SET(cfsp " ")
  ENDIF(CMAKE_C_FLAGS)
  MESSAGE(STATUS "")
  MESSAGE(STATUS "")
  MESSAGE(STATUS "PCRE2-${PCRE2_MAJOR}.${PCRE2_MINOR} configuration summary:")
  MESSAGE(STATUS "")
  MESSAGE(STATUS "  Install prefix .................. : ${CMAKE_INSTALL_PREFIX}")
  MESSAGE(STATUS "  C compiler ...................... : ${CMAKE_C_COMPILER}")
  MESSAGE(STATUS "  C compiler flags ................ : ${CMAKE_C_FLAGS}${cfsp}${CMAKE_C_FLAGS_${buildtype}}")
  MESSAGE(STATUS "")
  MESSAGE(STATUS "  Build 8 bit PCRE2 library ....... : ${PCRE2_BUILD_PCRE2_8}")
  MESSAGE(STATUS "  Build 16 bit PCRE2 library ...... : ${PCRE2_BUILD_PCRE2_16}")
  MESSAGE(STATUS "  Build 32 bit PCRE2 library ...... : ${PCRE2_BUILD_PCRE2_32}")
  MESSAGE(STATUS "  Enable Unicode support .......... : ${PCRE2_SUPPORT_UNICODE}")
  MESSAGE(STATUS "  Newline char/sequence ........... : ${PCRE2_NEWLINE}")
  MESSAGE(STATUS "  \\R matches only ANYCRLF ......... : ${PCRE2_SUPPORT_BSR_ANYCRLF}")
  MESSAGE(STATUS "  \\C is disabled .................. : ${PCRE2_NEVER_BACKSLASH_C}")
  MESSAGE(STATUS "  EBCDIC coding ................... : ${PCRE2_EBCDIC}")
  MESSAGE(STATUS "  EBCDIC coding with NL=0x25 ...... : ${PCRE2_EBCDIC_NL25}")
  MESSAGE(STATUS "  Rebuild char tables ............. : ${PCRE2_REBUILD_CHARTABLES}")
  MESSAGE(STATUS "  Internal link size .............. : ${PCRE2_LINK_SIZE}")
  MESSAGE(STATUS "  Parentheses nest limit .......... : ${PCRE2_PARENS_NEST_LIMIT}")
  MESSAGE(STATUS "  Heap limit ...................... : ${PCRE2_HEAP_LIMIT}")
  MESSAGE(STATUS "  Match limit ..................... : ${PCRE2_MATCH_LIMIT}")
  MESSAGE(STATUS "  Match depth limit ............... : ${PCRE2_MATCH_LIMIT_DEPTH}")
  MESSAGE(STATUS "  Build shared libs ............... : ${BUILD_SHARED_LIBS}")
  MESSAGE(STATUS "  Build static libs ............... : ${BUILD_STATIC_LIBS}")
  MESSAGE(STATUS "     with PIC enabled ............. : ${PCRE2_STATIC_PIC}")
  MESSAGE(STATUS "  Support Valgrind .................: ${PCRE2_SUPPORT_VALGRIND}")
  IF(PCRE2_DISABLE_PERCENT_ZT)
    MESSAGE(STATUS "  Use %zu and %td ..................: OFF" )
  ELSE(PCRE2_DISABLE_PERCENT_ZT)
    MESSAGE(STATUS "  Use %zu and %td ..................: AUTO" )
  ENDIF(PCRE2_DISABLE_PERCENT_ZT)

  IF(MINGW AND BUILD_SHARED_LIBS)
    MESSAGE(STATUS "  Non-standard dll names (prefix) . : ${NON_STANDARD_LIB_PREFIX}")
    MESSAGE(STATUS "  Non-standard dll names (suffix) . : ${NON_STANDARD_LIB_SUFFIX}")
  ENDIF(MINGW AND BUILD_SHARED_LIBS)

  IF(MSVC)
    MESSAGE(STATUS "  Install MSVC .pdb files ..........: ${INSTALL_MSVC_PDB}")
  ENDIF(MSVC)

  MESSAGE(STATUS "")
ENDIF(PCRE2_SHOW_REPORT)

# end CMakeLists.txt
