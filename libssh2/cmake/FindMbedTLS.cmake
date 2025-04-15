# - Try to find mbedTLS
# Once done this will define
#
# Read-Only variables
#  MBEDTLS_FOUND - system has mbedTLS
#  MBEDTLS_INCLUDE_DIR - the mbedTLS include directory
#  MBEDTLS_LIBRARY_DIR - the mbedTLS library directory
#  MBEDTLS_LIBRARIES - Link these to use mbedTLS
#  MBEDTLS_LIBRARY - path to mbedTLS library
#  MBEDX509_LIBRARY - path to mbedTLS X.509 library
#  MBEDCRYPTO_LIBRARY - path to mbedTLS Crypto library

find_path(MBEDTLS_INCLUDE_DIR mbedtls/version.h)

if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIBRARIES)
  # Already in cache, be silent
  set(MBEDTLS_FIND_QUIETLY TRUE)
endif()

find_library(MBEDTLS_LIBRARY NAMES mbedtls libmbedtls libmbedx509)
find_library(MBEDX509_LIBRARY NAMES mbedx509 libmbedx509)
find_library(MBEDCRYPTO_LIBRARY NAMES mbedcrypto libmbedcrypto)

if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIBRARY AND MBEDX509_LIBRARY AND MBEDCRYPTO_LIBRARY)
  set(MBEDTLS_FOUND TRUE)
endif()

if(MBEDTLS_FOUND)
  # split mbedTLS into -L and -l linker options, so we can set them for pkg-config
  get_filename_component(MBEDTLS_LIBRARY_DIR ${MBEDTLS_LIBRARY} PATH)
  get_filename_component(MBEDTLS_LIBRARY_FILE ${MBEDTLS_LIBRARY} NAME_WE)
  get_filename_component(MBEDX509_LIBRARY_FILE ${MBEDX509_LIBRARY} NAME_WE)
  get_filename_component(MBEDCRYPTO_LIBRARY_FILE ${MBEDCRYPTO_LIBRARY} NAME_WE)
  string(REGEX REPLACE "^lib" "" MBEDTLS_LIBRARY_FILE ${MBEDTLS_LIBRARY_FILE})
  string(REGEX REPLACE "^lib" "" MBEDX509_LIBRARY_FILE ${MBEDX509_LIBRARY_FILE})
  string(REGEX REPLACE "^lib" "" MBEDCRYPTO_LIBRARY_FILE ${MBEDCRYPTO_LIBRARY_FILE})
  set(MBEDTLS_LIBRARIES "-L${MBEDTLS_LIBRARY_DIR} -l${MBEDTLS_LIBRARY_FILE} -l${MBEDX509_LIBRARY_FILE} -l${MBEDCRYPTO_LIBRARY_FILE}")

  if(NOT MBEDTLS_FIND_QUIETLY)
    message(STATUS "Found mbedTLS:")
    file(READ ${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h MBEDTLSCONTENT)
    string(REGEX MATCH "MBEDTLS_VERSION_STRING +\"[0-9|.]+\"" MBEDTLSMATCH ${MBEDTLSCONTENT})
    if(MBEDTLSMATCH)
      string(REGEX REPLACE "MBEDTLS_VERSION_STRING +\"([0-9|.]+)\"" "\\1" MBEDTLS_VERSION ${MBEDTLSMATCH})
      message(STATUS "  version ${MBEDTLS_VERSION}")
    endif()
    message(STATUS "  TLS: ${MBEDTLS_LIBRARY}")
    message(STATUS "  X509: ${MBEDX509_LIBRARY}")
    message(STATUS "  Crypto: ${MBEDCRYPTO_LIBRARY}")
  endif()
elseif(MBEDTLS_FIND_REQUIRED)
  message(FATAL_ERROR "Could not find mbedTLS")
endif()

mark_as_advanced(
  MBEDTLS_INCLUDE_DIR
  MBEDTLS_LIBRARY_DIR
  MBEDTLS_LIBRARIES
  MBEDTLS_LIBRARY
  MBEDX509_LIBRARY
  MBEDCRYPTO_LIBRARY
)
