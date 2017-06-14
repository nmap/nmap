# Copyright (c) 2014, 2015 Alexander Lamaison <alexander.lamaison@gmail.com>
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

include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CopyRuntimeDependencies)
include(SocketLibraries)

set(EXAMPLES
  direct_tcpip
  ssh2
  scp
  scp_nonblock
  scp_write
  scp_write_nonblock
  sftp
  sftp_nonblock
  sftp_write
  sftp_write_nonblock
  sftp_mkdir
  sftp_mkdir_nonblock
  sftp_RW_nonblock
  sftp_write_sliding
  sftpdir
  sftpdir_nonblock
  ssh2_exec
  ssh2_agent
  ssh2_echo
  sftp_append
  subsystem_netconf
  tcpip-forward)

append_needed_socket_libraries(LIBRARIES)

foreach(example ${EXAMPLES})
  add_executable(example-${example} ${example}.c)
  list(APPEND EXAMPLE_TARGETS example-${example})
  # to find generated header
  target_include_directories(example-${example} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(example-${example} libssh2 ${LIBRARIES})
endforeach()
add_target_to_copy_dependencies(
  TARGET copy_example_dependencies
  DEPENDENCIES ${RUNTIME_DEPENDENCIES}
  BEFORE_TARGETS ${EXAMPLE_TARGETS})

## Platform checks
check_include_files(inttypes.h HAVE_INTTYPES_H)
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(sys/select.h HAVE_SYS_SELECT_H)
check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_files(sys/time.h HAVE_SYS_TIME_H)
check_include_files(arpa/inet.h HAVE_ARPA_INET_H)
check_include_files(netinet/in.h HAVE_NETINET_IN_H)
check_include_files(winsock2.h HAVE_WINSOCK2_H)

check_symbol_exists(strcasecmp strings.h HAVE_STRCASECMP)
check_symbol_exists(_stricmp string.h HAVE__STRICMP)
check_symbol_exists(snprintf stdio.h HAVE_SNPRINTF)
check_symbol_exists(_snprintf stdio.h HAVE__SNPRINTF)

check_symbol_exists(__func__ "" HAVE___FUNC__)
check_symbol_exists(__FUNCTION__ "" HAVE___FUNCTION__)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/libssh2_config_cmake.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/libssh2_config.h)
