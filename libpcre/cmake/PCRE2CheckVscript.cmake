# Similarly to Autoconf's ax_check_vscript.m4, check whether the linker supports
# version scripts (GNU ld) or map files (Sun linker).
# Sets the "have_var" to TRUE or FALSE depending on the detected support; and if
# support is detected then sets "flag_var" to the appropriate flag to pass to
# the linker (namely, --version-script or -M).

function(pcre2_check_vscript have_var flag_var)
  set(${have_var} FALSE PARENT_SCOPE)
  set(${flag_var} "" PARENT_SCOPE)

  if(MSVC)
    return()
  endif()

  set(first_run FALSE)
  if(NOT DEFINED HAVE_VSCRIPT_GNU)
    set(first_run TRUE)
    message(STATUS "Detecting linker version script support")
  endif()

  include(CheckCSourceCompiles)
  include(CMakePushCheckState)

  # The BSD file here is a workaround for the fact that check_c_source_compiles
  # very unfortunately only supports linking executables
  # with an entrypoint (or a static library), and yet the symbol visibility
  # requirements for executables are understandably different on some platforms
  # as compared to linking a shared library. On FreeBSD, linking fails if you
  # use the linker script to hide various global symbols from /usr/lib/crt1.o.
  #   https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=269370
  # Basically, everyone using --version-script is actually going to be creating
  # a shared library. It's a frustrating mismatch.
  file(WRITE ${PROJECT_BINARY_DIR}/test-map-file.sym "PCRE2_10.00 { global: exposethis; local: *; };")
  file(WRITE ${PROJECT_BINARY_DIR}/test-map-file-bsd.sym "PCRE2_10.00 { global: exposethis; environ; __progname; local: *; };")
  file(WRITE ${PROJECT_BINARY_DIR}/test-map-file-broken.sym "PCRE2_10.00 { global: exposethis; local: *; };  {")

  set(HAVE_VSCRIPT FALSE)

  # Using an executable to check for version-script support is rather delicate,
  # because linking in an entrypoint (main) adds extra symbols into the mix.
  # If CMake ever added a SHARED_LIBRARY option to check_c_source_compiles, we'd
  # use it here.
  set(
    test_source
    [=[
    int exposethis = 0, hidethis = 0;
    int main(void) {
      return exposethis + hidethis;
    }
    ]=]
  )

  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_QUIET TRUE)

  set(CMAKE_REQUIRED_LINK_OPTIONS "-Wl,--version-script,${PROJECT_BINARY_DIR}/test-map-file.sym")
  check_c_source_compiles("${test_source}" HAVE_VSCRIPT_GNU)

  if(HAVE_VSCRIPT_GNU)
    set(VSCRIPT_FLAG --version-script)
    set(HAVE_VSCRIPT TRUE)
  else()
    set(CMAKE_REQUIRED_LINK_OPTIONS "-Wl,--version-script,${PROJECT_BINARY_DIR}/test-map-file-bsd.sym")
    check_c_source_compiles("${test_source}" HAVE_VSCRIPT_BSD)

    if(HAVE_VSCRIPT_BSD)
      set(VSCRIPT_FLAG --version-script)
      set(HAVE_VSCRIPT TRUE)
    else()
      set(CMAKE_REQUIRED_LINK_OPTIONS "-Wl,-M,${PROJECT_BINARY_DIR}/test-map-file.sym")
      check_c_source_compiles("${test_source}" HAVE_VSCRIPT_SUN)

      if(HAVE_VSCRIPT_SUN)
        set(VSCRIPT_FLAG -M)
        set(HAVE_VSCRIPT TRUE)
      endif()
    endif()
  endif()

  if(HAVE_VSCRIPT)
    # Perform the same logic as ax_check_vscript.m4, to test whether the linker
    # silently ignores (and overwrites) linker scripts it doesn't understand.
    set(CMAKE_REQUIRED_LINK_OPTIONS "-Wl,${VSCRIPT_FLAG},${PROJECT_BINARY_DIR}/test-map-file-broken.sym")
    check_c_source_compiles("${test_source}" HAVE_VSCRIPT_BROKEN)

    if(HAVE_VSCRIPT_BROKEN)
      set(HAVE_VSCRIPT FALSE)
      if(first_run)
        message(STATUS "Detecting linker version script support - no (linker overwrites unknown scripts)")
      endif()
    else()
      if(first_run)
        message(STATUS "Detecting linker version script support - yes (${VSCRIPT_FLAG})")
      endif()
    endif()
  else()
    if(first_run)
      message(STATUS "Detecting linker version script support - none detected")
    endif()
  endif()

  cmake_pop_check_state()

  file(REMOVE ${PROJECT_BINARY_DIR}/test-map-file.sym)
  file(REMOVE ${PROJECT_BINARY_DIR}/test-map-file-bsd.sym)
  file(REMOVE ${PROJECT_BINARY_DIR}/test-map-file-broken.sym)

  if(HAVE_VSCRIPT)
    set(${have_var} TRUE PARENT_SCOPE)
    set(${flag_var} "${VSCRIPT_FLAG}" PARENT_SCOPE)
  endif()
endfunction()
