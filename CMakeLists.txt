cmake_minimum_required(VERSION 2.8)
set(PROJECT "uvrawpkt")

project(${PROJECT} C CXX )

if( $ENV{LIBUVDIR} )
  set(LIBUVDIR $ENV{LIBUVDIR} )
else()
  set(LIBUVDIR "../libuv")
endif()

include_directories("include" "${LIBUVDIR}/include")

set( LIBS ${LIBS} uv )

if( WIN32 )
    include_directories($ENV{PCAP_INCLUDE})
    set(LIBS ${LIBS} wpcap)
    link_directories($ENV{PCAP_LIBRARY})
elseif( ${CMAKE_SYSTEM_NAME} MATCHES "Darwin" )
    set(LIBS ${LIBS} pcap)
elseif( ${CMAKE_SYSTEM_NAME} MATCHES "Linux" )
   set( LIBS ${LIBS} pcap m rt )
endif()


INCLUDE (common.cmake)

