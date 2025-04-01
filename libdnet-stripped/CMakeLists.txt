cmake_minimum_required(VERSION 3.14)

project(dnet VERSION 1.18.0 LANGUAGES C)

find_package(TCL)

include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckStructHasMember)
include(CheckSymbolExists)
include(CheckTypeSize)
include(CheckCSourceCompiles)
include(GNUInstallDirs)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS True)
option(BUILD_SHARED_LIBS "Build in shared lib mode" OFF)

foreach (header stdio.h stdlib.h string.h inttypes.h)
  string(TOUPPER HAVE_${header} var)
  string(REGEX REPLACE "\\.|/" "_" var ${var})
  check_include_file(${header} ${var})
endforeach ()

if (MSVC)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    check_include_file(winsock2.h HAVE_WINSOCK2_H)
    set(HAVE_LIBWS2_32 ${HAVE_WINSOCK2_H})
    check_c_source_compiles("
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #include <Iphlpapi.h>
        int main() { return 0; }"
        HAVE_IPHLPAPI_H)
    set(HAVE_LIBIPHLPAPI ${HAVE_IPHLPAPI_H})
    set(CMAKE_REQUIRED_LIBRARIES "ws2_32")
    check_symbol_exists(inet_pton WS2tcpip.h HAVE_INET_PTON)
    set(CMAKE_REQUIRED_LIBRARIES )
endif()
if(UNIX)
    foreach (header strings.h
            unistd.h sys/bufmod.h sys/dlpi.h sys/dlpihdr.h sys/dlpi_ext.h
            sys/ioctl.h sys/mib.h sys/ndd_var.h sys/socket.h sys/sockio.h
            sys/time.h sys/stat.h net/if.h net/if_var.h
            net/if_dl.h net/pfilt.h
            net/radix.h net/raw.h net/route.h netinet/in_var.h
            linux/if_tun.h netinet/ip_fw.h linux/ip_fw.h
            linux/ip_fwchains.h linux/netfilter_ipv4/ipchains_core.h
            ip_fil_compat.h netinet/ip_fil_compat.h ip_compat.h
            netinet/ip_compat.h ip_fil.h netinet/ip_fil.h
            hpsecurity.h stropts.h dlfcn.h fcntl.h)
      string(TOUPPER HAVE_${header} var)
      string(REGEX REPLACE "\\.|/" "_" var ${var})
      check_include_file(${header} ${var})
    endforeach ()

    check_include_files("sys/types.h;net/bpf.h" HAVE_NET_BPF_H)
    check_include_files("sys/types.h;net/if_arp.h" HAVE_NET_IF_ARP_H)
    check_include_files("sys/types.h;net/if_tun.h" HAVE_NET_IF_TUN_H)
    check_include_files("sys/types.h;net/if.h;net/pfvar.h" HAVE_NET_PFVAR_H)
    check_include_files("sys/types.h;sys/sysctl.h" HAVE_SYS_SYSCTL_H)
endif()

set(CMAKE_REQUIRED_LIBRARIES )
foreach (func err strlcat strlcpy strse)
  string(TOUPPER HAVE_${func} var)
  check_function_exists(${func} ${var})
endforeach ()

if (UNIX)
    set(CMAKE_REQUIRED_LIBRARIES "nm")
    check_function_exists(open_mib HAVE_OPEN_MIB)
    set(CMAKE_REQUIRED_LIBRARIES )

    CHECK_STRUCT_HAS_MEMBER("struct arpreq" arp_dev net/if_arp.h HAVE_ARPREQ_ARP_DEV LANGUAGE C)
    CHECK_STRUCT_HAS_MEMBER("struct sockaddr" sa_len sys/socket.h HAVE_SOCKADDR_SA_LEN LANGUAGE C)
    CHECK_STRUCT_HAS_MEMBER("struct rt_msghdr" rtm_msglen "sys/socket.h;net/if.h;net/route.h" HAVE_ROUTE_RT_MSGHDR LANGUAGE C)

    set(CMAKE_EXTRA_INCLUDE_FILES "netinet/in.h")
    check_type_size("struct sockaddr_in6" HAVE_SOCKADDR_IN6  LANGUAGE C)
    set(CMAKE_EXTRA_INCLUDE_FILES )

    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        file(STRINGS /proc/sys/kernel/ostype PROCFS)
        message(STATUS "${PROCFS}")
        if (${PROCFS} STREQUAL "Linux")
            set(HAVE_LINUX_PROCFS True)
        endif()
    endif()

    check_include_file(inet/mib2.h HAVE_STREAMS_MIB2)

    check_symbol_exists(ETH_P_ALL linux/if_ether.h HAVE_LINUX_PF_PACKET)

    check_symbol_exists(RTSTR_SEND net/route.h HAVE_STREAMS_ROUTE)

    check_symbol_exists(SIOCGARP sys/ioctl.h HAVE_IOCTL_ARP)

    string(TOLOWER ${CMAKE_SYSTEM_NAME} CMAKE_SYSTEM_NAME_LOWER)

    string(REGEX MATCH "bsd" BSD ${CMAKE_SYSTEM_NAME_LOWER})
    string(REGEX MATCH "darwin" DARWIN ${CMAKE_SYSTEM_NAME_LOWER})
    string(REGEX MATCH "osf" OSF ${CMAKE_SYSTEM_NAME_LOWER})
    string(REGEX MATCH "unixware" UNIXWARE ${CMAKE_SYSTEM_NAME_LOWER})
    string(REGEX MATCH "openbsd" OPENBSD ${CMAKE_SYSTEM_NAME_LOWER})
    string(REGEX MATCH "solaris" SOLARIS ${CMAKE_SYSTEM_NAME_LOWER})
    string(REGEX MATCH "irix" IRIX ${CMAKE_SYSTEM_NAME_LOWER})
    string(REGEX MATCH "freebsd5" FREEBSD5 ${CMAKE_SYSTEM_NAME_LOWER})
    string(REGEX MATCH "kfreebsd" KFREEBSD ${CMAKE_SYSTEM_NAME_LOWER})

    if (BSD OR DARWIN OR OSF OR UNIXWARE)
        set(HAVE_RAWIP_HOST_OFFLEN True)
    endif()

    if (OPENBSD)
        set(HAVE_RAWIP_HOST_OFFLEN False)
    endif()

    if (SOLARIS OR IRIX)
        set(HAVE_RAWIP_COOKED True)
    endif()

    set(CMAKE_REQUIRED_LIBRARIES )
    foreach (func err strlcat strlcpy strse)
      string(TOUPPER HAVE_${func} var)
      check_function_exists(${func} ${var})
    endforeach ()



    set(CMAKE_REQUIRED_LIBRARIES nsl socket)
    check_function_exists(gethostbyname HAVE_GETHOSTBYNAME)
    if (NOT HAVE_GETHOSTBYNAME)
        unset(HAVE_GETHOSTBYNAME CACHE)
        set(CMAKE_REQUIRED_LIBRARIES nsl)
        check_function_exists(gethostbyname HAVE_GETHOSTBYNAME)
        if (NOT HAVE_GETHOSTBYNAME)
            unset(HAVE_GETHOSTBYNAME CACHE)
            set(CMAKE_REQUIRED_LIBRARIES)
            check_function_exists(gethostbyname HAVE_GETHOSTBYNAME)
        endif()
    endif()
    set(CMAKE_REQUIRED_LIBRARIES )
    check_function_exists(gethostbyaddr HAVE_GETHOSTBYADDR)
    check_function_exists(gethostname HAVE_GETHOSTNAME)
endif (UNIX)

check_function_exists(inet_ntoa HAVE_INET_NTOA)
check_function_exists(memset HAVE_MEMSET)
check_function_exists(select HAVE_SELECT)
check_function_exists(socket HAVE_SOCKET)
check_function_exists(strerror HAVE_STRERROR)
check_function_exists(strsep HAVE_STRSEP)

set(CMAKE_REQUIRED_LIBRARIES str)
check_function_exists(putmsg HAVE_PUTMSG)
set(CMAKE_REQUIRED_LIBRARIES )

set(PACKAGE ${PROJECT_NAME})
set(PACKAGE_BUGREPORT)
set(PACKAGE_NAME ${PROJECT_NAME})
set(PACKAGE_STRING "${PROJECT_NAME} ${CMAKE_PROJECT_VERSION}")
set(PACKAGE_TARNAME ${PROJECT_NAME})
set(PACKAGE_URL)
set(PACKAGE_VERSION ${CMAKE_PROJECT_VERSION})
set(VERSION ${CMAKE_PROJECT_VERSION})

configure_file(config.h.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

set(PLATFORM_SOURCES)

if (NOT HAVE_STRLCAT)
    list(APPEND PLATFORM_SOURCES src/strlcat.c)
endif()
if (NOT HAVE_STRLCPY)
    list(APPEND PLATFORM_SOURCES src/strlcpy.c)
endif()
if (NOT HAVE_STRSEP)
    list(APPEND PLATFORM_SOURCES src/strsep.c)
endif()


if (HAVE_ROUTE_RT_MSGHDR)
    list(APPEND PLATFORM_SOURCES src/arp-bsd.c)
elseif (HAVE_IOCTL_ARP)
    list(APPEND PLATFORM_SOURCES src/arp-ioctl.c)
elseif (HAVE_IPHLPAPI_H)
    list(APPEND PLATFORM_SOURCES src/arp-win32.c)
else()
    list(APPEND PLATFORM_SOURCES src/arp-none.c)
endif()

if (HAVE_IPHLPAPI_H)
#    no npcap support
#    list(APPEND PLATFORM_SOURCES src/eth-win32.c)
elseif(HAVE_NET_PFILT_H)
    list(APPEND PLATFORM_SOURCES src/eth-pfilt.c)
elseif(HAVE_LINUX_PF_PACKET)
    list(APPEND PLATFORM_SOURCES src/eth-linux.c)
elseif(HAVE_NET_BPF_H)
    list(APPEND PLATFORM_SOURCES src/eth-bsd.c)
elseif(HAVE_NET_RAW_H)
    list(APPEND PLATFORM_SOURCES src/eth-snoop.c)
elseif(HAVE_SYS_NDD_VAR_H)
    list(APPEND PLATFORM_SOURCES src/eth-ndd.c)
elseif(HAVE_SYS_DLPI_H OR HAVE_SYS_DLPIHDR_H)
    list(APPEND PLATFORM_SOURCES src/eth-dlpi.c)
else()
    list(APPEND PLATFORM_SOURCES src/eth-none.c)
endif()

if (HAVE_IPHLPAPI_H)
    list(APPEND PLATFORM_SOURCES src/fw-pktfilter.c)
elseif(HAVE_NET_PFVAR_H)
    list(APPEND PLATFORM_SOURCES src/fw-pf.c)
elseif(HAVE_NETINET_IP_FW_H)
    if (FREEBSD5 OR KFREEBSD)
        list(APPEND PLATFORM_SOURCES src/fw-none.c)
    else()
        list(APPEND PLATFORM_SOURCES src/fw-ipfw.c)
    endif()
elseif(HAVE_IP_FIL_H)
    list(APPEND PLATFORM_SOURCES src/fw-ipf.c)
elseif(HAVE_LINUX_IP_FW_H OR HAVE_LINUX_IP_FWCHAINS_H OR HAVE_LINUX_NETFILTER_IPV4_IPCHAINS_CORE_H)
    list(APPEND PLATFORM_SOURCES src/fw-ipchains.c)
else()
    list(APPEND PLATFORM_SOURCES src/fw-none.c)
endif()

if (HAVE_IPHLPAPI_H)
    list(APPEND PLATFORM_SOURCES src/intf-win32.c)
else()
    list(APPEND PLATFORM_SOURCES src/intf.c)
endif()

if (HAVE_IPHLPAPI_H)
    list(APPEND PLATFORM_SOURCES src/ip-win32.c)
elseif(HAVE_RAWIP_COOKED)
    list(APPEND PLATFORM_SOURCES src/ip-cooked.c)
else()
    list(APPEND PLATFORM_SOURCES src/ip.c)
endif()

if (HAVE_IPHLPAPI_H)
    list(APPEND PLATFORM_SOURCES src/route-win32.c)
elseif(HAVE_ROUTE_RT_MSGHDR)
    list(APPEND PLATFORM_SOURCES src/route-bsd.c)
elseif(HAVE_LINUX_PROCFS)
    list(APPEND PLATFORM_SOURCES src/route-linux.c)
elseif(HAVE_HPSECURITY_H)
    list(APPEND PLATFORM_SOURCES src/route-hpux.c)
else()
    list(APPEND PLATFORM_SOURCES src/route-none.c)
endif()

if(HAVE_LINUX_PROCFS)
    list(APPEND PLATFORM_SOURCES src/ndisc-linux.c)
else()
    list(APPEND PLATFORM_SOURCES src/ndisc-none.c)
endif()

find_file(HAVE_DEV_TUN
            NAMES /dev/tun0
            DOC "Check for tun0")

if(HAVE_LINUX_IF_TUN_H)
    list(APPEND PLATFORM_SOURCES src/tun-linux.c)
elseif(HAVE_NET_IF_TUN_H)
    if(HAVE_STROPTS_H)
        list(APPEND PLATFORM_SOURCES src/tun-solaris.c)
    else()
        list(APPEND PLATFORM_SOURCES src/tun-bsd.c)
    endif()
elseif(HAVE_DEV_TUN)
    list(APPEND PLATFORM_SOURCES src/tun-bsd.c)
else()
    list(APPEND PLATFORM_SOURCES src/tun-none.c)
endif()

add_library(${PROJECT_NAME}
    src/addr-util.c
    src/addr.c
    src/blob.c
    src/err.c
    src/ip-util.c
    src/ip6.c
    src/rand.c
    ${PLATFORM_SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<INSTALL_INTERFACE:include>
    $<INSTALL_INTERFACE:include/dnet>
)

set(DNET_HEADERS
    include/dnet/addr.h
    include/dnet/arp.h
    include/dnet/blob.h
    include/dnet/eth.h
    include/dnet/fw.h
    include/dnet/icmp.h
    include/dnet/intf.h
    include/dnet/ip.h
    include/dnet/ip6.h
    include/dnet/ndisc.h
    include/dnet/os.h
    include/dnet/rand.h
    include/dnet/route.h
    include/dnet/sctp.h
    include/dnet/tcp.h
    include/dnet/tun.h
    include/dnet/udp.h
)
set(DNET_HEADERS1
    include/dnet.h
    include/err.h
    include/queue.h
    ${CMAKE_CURRENT_BINARY_DIR}/config.h
)
set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
    PUBLIC_HEADER "${DNET_HEADERS}"
)

if (MSVC)
    target_link_libraries(${PROJECT_NAME} PUBLIC Iphlpapi ws2_32)
endif()

install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}Targets DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT runtime
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT devel
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/${PROJECT_NAME} COMPONENT devel
)


install(FILES ${DNET_HEADERS1}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
        COMPONENT devel)

install(EXPORT ${PROJECT_NAME}Targets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}/
    FILE ${PROJECT_NAME}Targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    COMPONENT devel
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/${PROJECT_NAME}-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    @ONLY
)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/${PROJECT_NAME}-config-version.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    @ONLY
)
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}/
    COMPONENT devel
)

if(UNIX)
  if(NOT CPACK_GENERATOR)
    set(CPACK_GENERATOR "DEB")
  endif()

  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  set(CPACK_STRIP_FILES 1)
  if(${CMAKE_VERSION} VERSION_GREATER "3.5")
    set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
  endif()
endif()

include(CPack)
