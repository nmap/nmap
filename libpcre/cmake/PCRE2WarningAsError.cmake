# This file can be removed once the minimum CMake version is increased to 3.24
# or higher. Calls to pcre2_warning_as_error can be changed to the built in
# CMAKE_C_COMPILE_OPTIONS_WARNING_AS_ERROR.

function(pcre2_warning_as_error out_var)
  set(${out_var} "" PARENT_SCOPE)

  if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
    # Since CMake 3.24, we should use the CMAKE_C_COMPILE_OPTIONS_WARNING_AS_ERROR
    # variable for greatest compiler compatibility.
    if(DEFINED CMAKE_C_COMPILE_OPTIONS_WARNING_AS_ERROR)
      set(${out_var} "${CMAKE_C_COMPILE_OPTIONS_WARNING_AS_ERROR}" PARENT_SCOPE)
    endif()
  else()
    # The fallback probes for support, trying a few common flags.

    if(NOT MSVC)
      include(CheckCCompilerFlag)
      include(CMakePushCheckState)

      cmake_push_check_state(RESET)
      check_c_compiler_flag("-Werror" HAVE_WERROR)
      if(HAVE_WERROR)
        set(${out_var} "-Werror" PARENT_SCOPE)
      else()
        check_c_compiler_flag("-errwarn=%all" HAVE_ERRWARN_ALL)
        if(HAVE_ERRWARN_ALL)
          set(${out_var} "-errwarn=%all" PARENT_SCOPE)
        endif()
      endif()

      cmake_pop_check_state()
    endif()
  endif()
endfunction()
