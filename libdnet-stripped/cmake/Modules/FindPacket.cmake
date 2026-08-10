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
# Packet_INCLUDE_DIR     - absolute path to the directory containing Packet32.h.
#
# Packet_LIBRARY         - relative or absolute path to the Packet library to
#                          link with. An absolute path is will be used if the
#                          Packet library is not located in the compiler's
#                          default search path.

# Packet_FOUND           - TRUE if the Packet library *and* header are found.
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

if(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
  #
  # 32-bit x86; no need to look in subdirectories of the SDK's
  # Lib directory for the libraries, as the libraries are in
  # the Lib directory
  #
else()
  #
  # Platform other than 32-bit x86.
  #
  # For the WinPcap and Npcap SDKs, the Lib subdirectory of the top-level
  # directory contains 32-bit x86 libraries; the libraries for other
  # platforms are in subdirectories of the Lib directory whose names
  # are the names of the supported platforms.
  #
  # The only way to *FORCE* CMake to look in the appropriate
  # subdirectory of Lib for libraries without searching in the
  # Lib directory first appears to be to set
  # CMAKE_LIBRARY_ARCHITECTURE to the name of the subdirectory.
  #
  set(CMAKE_LIBRARY_ARCHITECTURE "${CMAKE_GENERATOR_PLATFORM}")
endif()

# Find the header
find_path(Packet_INCLUDE_DIR Packet32.h
  PATH_SUFFIXES include Include
)

# Find the library
find_library(Packet_LIBRARY
  NAMES Packet packet
)

# Set Packet_FOUND to TRUE if Packet_INCLUDE_DIR and Packet_LIBRARY are TRUE.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Packet
  DEFAULT_MSG
  Packet_INCLUDE_DIR
  Packet_LIBRARY
)

mark_as_advanced(Packet_INCLUDE_DIR Packet_LIBRARY)

set(Packet_INCLUDE_DIRS ${Packet_INCLUDE_DIR})
set(Packet_LIBRARIES ${Packet_LIBRARY})
