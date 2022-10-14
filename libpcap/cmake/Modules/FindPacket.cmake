#
# Copyright (C) 2017 Ali Abdulkadir <autostart.ini@gmail.com>.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sub-license, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# FindPacket
# ==========
#
# Find the Packet library and include files.
#
# This module defines the following variables:
#
# PACKET_INCLUDE_DIR     - absolute path to the directory containing Packet32.h.
#
# PACKET_LIBRARY         - relative or absolute path to the Packet library to
#                          link with. An absolute path is will be used if the
#                          Packet library is not located in the compiler's
#                          default search path.

# PACKET_FOUND           - TRUE if the Packet library *and* header are found.
#
# Hints and Backward Compatibility
# ================================
#
# To tell this module where to look, a user may set the environment variable
# Packet_ROOT to point cmake to the *root* of a directory with include and
# lib subdirectories for packet.dll (e.g WpdPack or npcap-sdk).
# Alternatively, Packet_ROOT may also be set from cmake command line or GUI
# (e.g cmake -DPacket_ROOT=C:\path\to\packet [...])
#

# The 64-bit Packet.lib is located under /x64
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
  set(archdetect_c_code "
  #ifndef _M_ARM64
  #error Not ARM64
  #endif
  int main() { return 0; }
  ")

  file(WRITE "${CMAKE_BINARY_DIR}/archdetect.c" "${archdetect_c_code}")
  try_compile(
	  IsArm64 
	  "${CMAKE_BINARY_DIR}/archdetect"
	  "${CMAKE_BINARY_DIR}/archdetect.c"
	  )
  if(IsArm64)
	  set(CMAKE_C_LIBRARY_ARCHITECTURE "ARM64")
	  set(CMAKE_LIBRARY_ARCHITECTURE "ARM64")
  else()
	  set(CMAKE_C_LIBRARY_ARCHITECTURE "x64")
	  set(CMAKE_LIBRARY_ARCHITECTURE "x64")
  endif()
endif()

# Find the header
find_path(PACKET_INCLUDE_DIR Packet32.h
  PATH_SUFFIXES include Include
)

# Find the library
find_library(PACKET_LIBRARY
  NAMES Packet packet
)

# Set PACKET_FOUND to TRUE if PACKET_INCLUDE_DIR and PACKET_LIBRARY are TRUE.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PACKET
  DEFAULT_MSG
  PACKET_INCLUDE_DIR
  PACKET_LIBRARY
)

mark_as_advanced(PACKET_INCLUDE_DIR PACKET_LIBRARY)

set(PACKET_INCLUDE_DIRS ${PACKET_INCLUDE_DIR})
set(PACKET_LIBRARIES ${PACKET_LIBRARY})
