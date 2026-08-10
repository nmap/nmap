# Try to find dpdk
#
# Once done, this will define
#
# dpdk_FOUND
# dpdk_INCLUDE_DIRS
# dpdk_LIBRARIES
# dpdk_STATIC_LIBRARIES
# dpdk_LIBS_STATIC
# dpdk_REQUIRES_PRIVATE
# dpdk_PACKAGE_NAME

#
# We only try to find DPDK using pkg-config; DPDK is *SO*
# complicated - DPDK 19.02, for example, has about 117(!)
# libraries, and the precise set of libraries required has
# changed over time  - so attempting to guess which libraries
# you need, and hardcoding that in an attempt to find the
# libraries without DPDK, rather than relying on DPDK to
# tell you, with a .pc file, what libraries are needed,
# is *EXTREMELY* fragile and has caused some bug reports,
# so we're just not going to do it.
#
# If that causes a problem, the only thing we will do is
# accept an alternative way of finding the appropriate
# library set for the installed version of DPDK that is
# as robust as pkg-config (i.e., it had better work as well
# as pkg-config with *ALL* versions of DPDK that provide a
# libdpdk.pc file).
#
# If dpdk_ROOT is set, add ${dpdk_ROOT}/pkgconfig
# to PKG_CONFIG_PATH, so we look for the .pc file there,
# first.
#
if(PKG_CONFIG_FOUND)
  set(save_PKG_CONFIG_PATH $ENV{PKG_CONFIG_PATH})
  if(dpdk_ROOT)
    set(ENV{PKG_CONFIG_PATH} "${dpdk_ROOT}/pkgconfig:$ENV{PKG_CONFIG_PATH}")
  endif()
  pkg_check_modules(dpdk QUIET libdpdk)
  if(dpdk_FOUND)
    #
    # Get link information for DPDK.
    #
    pkg_get_link_info(dpdk libdpdk)
  endif()
  set(ENV{PKG_CONFIG_PATH} "${save_PKG_CONFIG_PATH}")
endif()

mark_as_advanced(dpdk_INCLUDE_DIRS dpdk_LIBRARIES dpdk_STATIC_LIBRARIES dpdk_REQUIRES_PRIVATE)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(dpdk DEFAULT_MSG
  dpdk_INCLUDE_DIRS
  dpdk_LIBRARIES)

if(dpdk_FOUND)
  #
  # This depends on CMake support for "imported targets",
  # which are not supported until CMake 3.19.
  #
  # Ubuntu 20.04 provides CMake 3.16.3, so we are *NOT*
  # going to require CMake 3.19.  If you want to use
  # Shiny New Features(TM), wait until all the OSes on
  # which a build might conceivably be done, and that
  # provide CMake, provide 3.19 or later.
  #
  # Just don't do this stuff on earlier versions.  If that
  # breaks something, figure out a way to do it *without*
  # "imported targets", and either do this that way, or,
  # at least, do it that way on older versions of CMake.
  #
  # (One good thing about autotools is that only the builders
  # of a package, and people doing configure-script development,
  # have to care about the autoconf etc. version; you don't
  # even need to have autotools installed in order to be able
  # to run an autotools-generated configure script, you just
  # need an environment UN*Xy enough, and modern enough, to
  # run the stuff in the script.
  #
  # This is *NOT* the case for CMake; not only do you need
  # CMake in order to build a package using CMake, you need
  # a version recent enough to run the stuff the package's
  # CMake files use.
  #
  # Please keep this in mind when changing any CMake files,
  # and keep in mind what versions of CMake come with, for
  # example, commonly-used versions of commonly-used
  # Linux distributions.)
  #
  if(NOT CMAKE_VERSION VERSION_LESS 3.19)
    if(NOT TARGET dpdk::cflags)
       if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64|x86_64|AMD64")
        set(rte_cflags "-march=core2")
      elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM")
        set(rte_cflags "-march=armv7-a")
      elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|AARCH64")
        set(rte_cflags "-march=armv8-a+crc")
      endif()
      add_library(dpdk::cflags INTERFACE IMPORTED)
      if (rte_cflags)
        set_target_properties(dpdk::cflags PROPERTIES
          INTERFACE_COMPILE_OPTIONS "${rte_cflags}")
      endif()
    endif()

    if(NOT TARGET dpdk::dpdk)
      add_library(dpdk::dpdk INTERFACE IMPORTED)
      find_package(Threads QUIET)
      list(APPEND dpdk_LIBRARIES
        Threads::Threads
        dpdk::cflags)
      set_target_properties(dpdk::dpdk PROPERTIES
        INTERFACE_LINK_LIBRARIES "${dpdk_LIBRARIES}"
        INTERFACE_INCLUDE_DIRECTORIES "${dpdk_INCLUDE_DIRS}")
    endif()
  endif()
endif()
