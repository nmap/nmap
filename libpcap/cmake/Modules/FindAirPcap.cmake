#
# FindAirPcap
# ==========
#
# Find the AirPcap library and include files.
#
# This module defines the following variables:
#
# AirPcap_INCLUDE_DIR     - absolute path to the directory containing airpcap.h.
#
# AirPcap_LIBRARY         - relative or absolute path to the AirPcap library to
#                          link with. An absolute path is will be used if the
#                          AirPcap library is not located in the compiler's
#                          default search path.

# AirPcap_FOUND           - TRUE if the AirPcap library *and* header are found.
#
# Hints and Backward Compatibility
# ================================
#
# To tell this module where to look, a user may set the environment variable
# AirPcap_ROOT to point cmake to the *root* of a directory with include and
# lib subdirectories for airpcap.dll (e.g Airpcap_Devpack).
# Alternatively, AirPcap_ROOT may also be set from the CMake command
# line or GUI (e.g cmake -DAirPcap_ROOT=C:\path\to\airpcap_sdk [...])
#

# The 64-bit airpcap.lib is located under /x64
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  #
  # For the WinPcap and Npcap SDKs, the Lib subdirectory of the top-level
  # directory contains 32-bit libraries; the 64-bit libraries are in the
  # Lib/x64 directory.
  #
  # The only way to *FORCE* CMake to look in the Lib/x64 directory
  # without searching in the Lib directory first appears to be to set
  # CMAKE_LIBRARY_ARCHITECTURE to "x64".
  #
  # In newer versions of CMake, CMAKE_LIBRARY_ARCHITECTURE is set according to
  # the language, e.g., CMAKE_<LANG>_LIBRARY_ARCHITECTURE. So, set the new
  # variable, CMAKE_C_LIBRARY_ARCHITECTURE, so that CMAKE_LIBRARY_ARCHITECTURE
  # inherits the correct value.
  #
  set(CMAKE_C_LIBRARY_ARCHITECTURE "x64")
  set(CMAKE_LIBRARY_ARCHITECTURE "x64")
endif()

# Find the header
find_path(AirPcap_INCLUDE_DIR airpcap.h
  PATH_SUFFIXES include
)

# Find the library
find_library(AirPcap_LIBRARY
  NAMES airpcap
)

# Set AirPcap_FOUND to TRUE if AirPcap_INCLUDE_DIR and AirPcap_LIBRARY are TRUE.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(AirPcap
  DEFAULT_MSG
  AirPcap_INCLUDE_DIR
  AirPcap_LIBRARY
)

mark_as_advanced(AirPcap_INCLUDE_DIR AirPcap_LIBRARY)

set(AirPcap_INCLUDE_DIRS ${AirPcap_INCLUDE_DIR})
set(AirPcap_LIBRARIES ${AirPcap_LIBRARY})
