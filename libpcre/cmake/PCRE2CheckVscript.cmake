# Similarly to Autoconf's ax_check_vscript.m4, check whether the linker supports
# version scripts (GNU ld) or map files (Sun linker).
# Sets the "have_var" to TRUE or FALSE depending on the detected support; and if
# support is detected then sets "flag_var" to the appropriate flag to pass to
# the linker (namely, --version-script or -M).

# Helper function: try to compile a shared library with a given linker flag and
# version script. This properly tests version script support by building a
# shared library rather than an executable, avoiding issues with
# executable-specific symbols (e.g. FreeBSD's crt1.o symbols, Solaris linker
# symbols in values-Xc.o).
function(_pcre2_try_vscript_shared_lib link_flag map_file result_var)
  if(DEFINED ${result_var})
    return()
  endif()

  message(STATUS "Performing Test ${result_var}")

  set(${result_var} FALSE PARENT_SCOPE)

  set(try_dir "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/CMakeScratch/CheckVscript")
  file(REMOVE_RECURSE "${try_dir}")
  file(MAKE_DIRECTORY "${try_dir}")

  # Write a minimal C source with exported symbols
  file(WRITE "${try_dir}/test_vscript.c" "
int hidethis(void) { return 0; }
int exposethis(void) { return hidethis(); }
")

  # Write a CMakeLists.txt that builds a shared library with the version script
  file(WRITE "${try_dir}/CMakeLists.txt" "
cmake_minimum_required(VERSION 3.15)
project(test_vscript C)
add_library(test_vscript SHARED test_vscript.c)
target_link_options(test_vscript PRIVATE \"-Wl,${link_flag},${map_file}\")
")

  try_compile(
    compile_result
    "${try_dir}/build" # BINARY_DIR
    "${try_dir}" # SOURCE_DIR
    test_vscript # Project name
    OUTPUT_VARIABLE compile_output
  )

  if(compile_result)
    set(${result_var} TRUE PARENT_SCOPE)
  endif()

  if(${compile_result})
    set(${result_var} 1 CACHE INTERNAL "Test ${result_var}")
    message(STATUS "Performing Test ${result_var} - Success")
  else()
    set(${result_var} "" CACHE INTERNAL "Test ${result_var}")
    message(STATUS "Performing Test ${result_var} - Failed")
  endif()
endfunction()

function(pcre2_check_vscript have_var flag_var no_star_var)
  set(${have_var} FALSE PARENT_SCOPE)
  set(${flag_var} "" PARENT_SCOPE)
  set(${no_star_var} FALSE PARENT_SCOPE)

  if(MSVC)
    return()
  endif()

  set(first_run FALSE)
  if(NOT DEFINED HAVE_VSCRIPT_GNU)
    set(first_run TRUE)
    message(STATUS "Detecting linker version script support")
  endif()

  # Write test version script files
  file(WRITE "${PROJECT_BINARY_DIR}/test-map-file.sym" "PCRE2_10.00 { global: exposethis; local: *; };")
  file(WRITE "${PROJECT_BINARY_DIR}/test-map-file-broken.sym" "PCRE2_10.00 { global: exposethis; local: *; };  {")
  file(WRITE "${PROJECT_BINARY_DIR}/test-map-file-no-star.sym" "PCRE2_10.00 { global: exposethis; local: hidethis; };")

  set(HAVE_VSCRIPT FALSE)

  # Test GNU ld --version-script flag
  _pcre2_try_vscript_shared_lib("--version-script" "${PROJECT_BINARY_DIR}/test-map-file.sym" HAVE_VSCRIPT_GNU)

  if(HAVE_VSCRIPT_GNU)
    set(VSCRIPT_FLAG --version-script)
    set(HAVE_VSCRIPT TRUE)
  else()
    # Test Sun linker -M flag
    _pcre2_try_vscript_shared_lib("-M" "${PROJECT_BINARY_DIR}/test-map-file.sym" HAVE_VSCRIPT_SUN)

    if(HAVE_VSCRIPT_SUN)
      set(VSCRIPT_FLAG -M)
      set(HAVE_VSCRIPT TRUE)
    endif()
  endif()

  if(HAVE_VSCRIPT)
    # Perform the same logic as ax_check_vscript.m4, to test whether the linker
    # silently ignores (and overwrites) linker scripts it doesn't understand.
    _pcre2_try_vscript_shared_lib("${VSCRIPT_FLAG}" "${PROJECT_BINARY_DIR}/test-map-file-broken.sym" HAVE_VSCRIPT_BROKEN)

    if(HAVE_VSCRIPT_BROKEN)
      set(HAVE_VSCRIPT FALSE)
    endif()
  endif()

  if(first_run)
    if(HAVE_VSCRIPT)
      message(STATUS "Detecting linker version script support - yes (${VSCRIPT_FLAG})")
    elseif(HAVE_VSCRIPT_BROKEN)
      message(STATUS "Detecting linker version script support - no (linker overwrites unknown scripts)")
    else()
      message(STATUS "Detecting linker version script support - none detected")
    endif()
  endif()

  if(HAVE_VSCRIPT)
    if(first_run)
      message(STATUS "Detecting if version scripts work without wildcard")
    endif()

    # Test that the linker works without requiring a wildcard to hide platform-specific
    # symbols (_init, _fini, etc.).
    _pcre2_try_vscript_shared_lib("${VSCRIPT_FLAG}" "${PROJECT_BINARY_DIR}/test-map-file-no-star.sym" HAVE_VSCRIPT_NO_STAR)

    if(first_run)
      message(STATUS "Detecting if version scripts work without wildcard - ${HAVE_VSCRIPT_NO_STAR}")
    endif()
  endif()

  file(REMOVE "${PROJECT_BINARY_DIR}/test-map-file.sym")
  file(REMOVE "${PROJECT_BINARY_DIR}/test-map-file-broken.sym")
  file(REMOVE "${PROJECT_BINARY_DIR}/test-map-file-no-star.sym")

  if(HAVE_VSCRIPT)
    set(${have_var} TRUE PARENT_SCOPE)
    set(${flag_var} "${VSCRIPT_FLAG}" PARENT_SCOPE)
    set(${no_star_var} "${HAVE_VSCRIPT_NO_STAR}" PARENT_SCOPE)
  endif()
endfunction()
