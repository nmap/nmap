#
# Try to find the Myricom SNF library.
#

# Try to find the header
find_path(SNF_INCLUDE_DIR snf.h /opt/snf)

# Try to find the library
find_library(SNF_LIBRARY snf /opt/snf)

#
# Get link information from the _LIBRARY paths.
#
get_link_info_from_library_path(SNF snf)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SNF
  DEFAULT_MSG
  SNF_INCLUDE_DIR
  SNF_LIBRARY
)

mark_as_advanced(
  SNF_INCLUDE_DIR
  SNF_LIBRARY
)

set(SNF_INCLUDE_DIRS ${SNF_INCLUDE_DIR})
set(SNF_LIBRARIES ${SNF_LIBRARY})
set(SNF_STATIC_LIBRARIES ${SNF_LIBRARY})
