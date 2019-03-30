if(MSVC)
  file(GLOB PROJECT_SOURCE_LIST_WIN32_C ${pcap_SOURCE_DIR}/missing/getopt.c)
  include_directories(${pcap_SOURCE_DIR}/missing)
endif(MSVC)

add_custom_target(testprogs)

macro(add_test_executable _executable)
  add_executable(${_executable} EXCLUDE_FROM_ALL
    ${_executable}.c ${PROJECT_SOURCE_LIST_WIN32_C})
  if(NOT C_ADDITIONAL_FLAGS STREQUAL "")
    set_target_properties(${_executable} PROPERTIES
      COMPILE_FLAGS ${C_ADDITIONAL_FLAGS})
  endif()
  if(WIN32)
    target_link_libraries(${_executable}
      ${ARGN} ${LIBRARY_NAME} ${PCAP_LINK_LIBRARIES})
  else(WIN32)
    target_link_libraries(${_executable}
      ${ARGN} ${LIBRARY_NAME}_static ${PCAP_LINK_LIBRARIES})
  endif(WIN32)
  add_dependencies(testprogs ${_executable})
endmacro()

add_test_executable(can_set_rfmon_test)
add_test_executable(capturetest)
add_test_executable(filtertest)
add_test_executable(findalldevstest)
add_test_executable(opentest)
add_test_executable(reactivatetest)

if(NOT WIN32)
  add_test_executable(selpolltest)
endif()

add_test_executable(threadsignaltest ${CMAKE_THREAD_LIBS_INIT})

if(NOT WIN32)
  add_test_executable(valgrindtest)
endif()
