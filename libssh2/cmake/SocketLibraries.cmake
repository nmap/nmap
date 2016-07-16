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

# Some systems have their socket functions in a library.
# (Solaris -lsocket/-lnsl, Windows -lws2_32).  This macro appends those
# libraries to the given list
macro(append_needed_socket_libraries LIBRARIES_LIST)
  if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    # x86 Windows uses STDCALL for these functions, so their names are mangled,
    # meaning the platform checks don't work. Hardcoding these until we get
    # a better solution.
    set(HAVE_SOCKET 1)
    set(HAVE_SELECT 1)
    set(HAVE_INET_ADDR 1)
    set(NEED_LIB_WS2_32 1)
  else()
    check_function_exists_may_need_library(socket HAVE_SOCKET socket ws2_32)
    check_function_exists_may_need_library(select HAVE_SELECT ws2_32)
    check_function_exists_may_need_library(inet_addr HAVE_INET_ADDR nsl ws2_32)
  endif()

  if(NEED_LIB_SOCKET)
    list(APPEND ${LIBRARIES_LIST} socket)
  endif()
  if(NEED_LIB_NSL)
    list(APPEND ${LIBRARIES_LIST} nsl)
  endif()
  if(NEED_LIB_WS2_32)
    list(APPEND ${LIBRARIES_LIST} ws2_32)
  endif()

endmacro()