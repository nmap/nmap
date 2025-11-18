# - Try to find wolfssl
# Once done this will define
#  WOLFSSL_FOUND           - System has wolfssl
#  WOLFSSL_INCLUDE_DIR     - The wolfssl include directories
#  WOLFSSL_LIBRARIES       - The libraries needed to use wolfssl

find_package(PkgConfig QUIET)
pkg_check_modules(PC_WOLFSSL QUIET wolfssl)

find_path(WOLFSSL_INCLUDE_DIR
  NAMES wolfssl/ssl.h
  HINTS ${PC_WOLFSSL_INCLUDE_DIRS}
)
find_library(WOLFSSL_LIBRARY
  NAMES wolfssl
  HINTS ${PC_WOLFSSL_LIBRARY_DIRS}
)

if(WOLFSSL_INCLUDE_DIR)
  set(_version_regex "^#define[ \t]+LIBWOLFSSL_VERSION_STRING[ \t]+\"([^\"]+)\".*")
  file(STRINGS "${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h"
    WOLFSSL_VERSION REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1"
    WOLFSSL_VERSION "${WOLFSSL_VERSION}")
  unset(_version_regex)
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set WOLFSSL_FOUND
# to TRUE if all listed variables are TRUE and the requested version
# matches.
find_package_handle_standard_args(wolfssl REQUIRED_VARS
                                  WOLFSSL_LIBRARY WOLFSSL_INCLUDE_DIR
                                  VERSION_VAR WOLFSSL_VERSION)

if(WOLFSSL_FOUND)
  set(WOLFSSL_LIBRARIES     ${WOLFSSL_LIBRARY})
  set(WOLFSSL_INCLUDE_DIRS  ${WOLFSSL_INCLUDE_DIR})
endif()

mark_as_advanced(WOLFSSL_INCLUDE_DIR WOLFSSL_LIBRARY)
