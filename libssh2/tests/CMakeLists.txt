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
include(CheckFunctionExists)
include(CheckSymbolExists)
include(BundleUtilities)
include(CopyRuntimeDependencies)
include(SocketLibraries)

## Platform checks
check_include_files(inttypes.h HAVE_INTTYPES_H)
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_files(arpa/inet.h HAVE_ARPA_INET_H)
check_include_files(windows.h HAVE_WINDOWS_H)
check_include_files(winsock2.h HAVE_WINSOCK2_H)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/libssh2_config_cmake.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/libssh2_config.h)

set(TESTS
  simple
  ssh2)

append_needed_socket_libraries(LIBRARIES)

foreach(test ${TESTS})
  add_executable(test-${test} ${test}.c)
  target_link_libraries(test-${test} libssh2 ${LIBRARIES})
  target_include_directories(test-${test} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
  list(APPEND TEST_TARGETS test-${test})
endforeach()

add_target_to_copy_dependencies(
  TARGET copy_test_dependencies
  DEPENDENCIES ${RUNTIME_DEPENDENCIES}
  BEFORE_TARGETS ${TEST_TARGETS})

# TODO convert mansyntax.sh into CMake script.
# XXX Just because we can find all three programs, doesn't mean sh can
# find man and grep
find_program(SH_EXECUTABLE sh)
find_program(MAN_EXECUTABLE man)
find_program(GREP_EXECUTABLE grep)
mark_as_advanced(SH_EXECUTABLE MAN_EXECUTABLE GREP_EXECUTABLE)
if(SH_EXECUTABLE AND MAN_EXECUTABLE AND GREP_EXECUTABLE)
  set(cmd "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")
  set(cmd "${cmd} ${CMAKE_CURRENT_SOURCE_DIR}/mansyntax.sh")
  add_test(mansyntax ${SH_EXECUTABLE} -c "${cmd}")
endif()

add_test(simple test-simple)

find_program(SSHD_EXECUTABLE sshd)
find_program(CHMOD_EXECUTABLE chmod)
find_program(KILL_EXECUTABLE kill)
mark_as_advanced(SSHD_EXECUTABLE CHMOD_EXECUTABLE KILL_EXECUTABLE)
if(SSHD_EXECUTABLE AND CHMOD_EXECUTABLE AND KILL_EXECUTABLE)
  set(SSHD_TEST_CONFIG_DIR ${CMAKE_CURRENT_BINARY_DIR})
  set(TEST_NAME ssh2)

  add_custom_command(
    TARGET test-${TEST_NAME}
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_SOURCE_DIR}/etc
    ${SSHD_TEST_CONFIG_DIR}/etc)

  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/sshd_fixture.sh.in
    ${CMAKE_CURRENT_BINARY_DIR}/test-${TEST_NAME}_fixture.sh
    @ONLY)

  add_test(NAME ssh2 COMMAND ${SH_EXECUTABLE}
    ${CMAKE_CURRENT_BINARY_DIR}/test-${TEST_NAME}_fixture.sh
    $<TARGET_FILE:test-${TEST_NAME}>)

endif()
