cmake_minimum_required(VERSION 2.8)

IF(BIICODE)
    ADD_BIICODE_TARGETS()
ELSE(NOT BIICODE)

    set(PROJECT "uvrawpkt")
    project(${PROJECT} C CXX )

    option(UV_RAWPKT_ENABLE_PCAP "Enable LIBPCAP usage" ON)

    if( $ENV{LIBUVDIR} )
      set(LIBUVDIR $ENV{LIBUVDIR} )
    else()
      set(LIBUVDIR "../libuv")
    endif()

    include_directories("include" "${LIBUVDIR}/include")

    set( LIBS ${LIBS} uv )

    if( UV_RAWPKT_ENABLE_PCAP )
        add_definitions(-DUV_RAWPKT_ENABLE_PCAP=1)
        if( WIN32 )
            include_directories($ENV{PCAP_INCLUDE})
            set(LIBS ${LIBS} wpcap)
            link_directories($ENV{PCAP_LIBRARY})
        elseif( ${CMAKE_SYSTEM_NAME} MATCHES "Darwin" )
            set(LIBS ${LIBS} pcap)
        elseif( ${CMAKE_SYSTEM_NAME} MATCHES "Linux" )
            set( LIBS ${LIBS} pcap m rt )
        endif()
    else()
        add_definitions(-DUV_RAWPKT_ENABLE_PCAP=0)
        if( WIN32 )
            message(FATAL_ERROR "Win32 usage requires UV_RAWPKT_ENABLE_PCAP ON")
        elseif( ${CMAKE_SYSTEM_NAME} MATCHES "Darwin" )
            message(FATAL_ERROR "Mac OS X usage requires UV_RAWPKT_ENABLE_PCAP ON")
        elseif( ${CMAKE_SYSTEM_NAME} MATCHES "Linux" )
            set( LIBS ${LIBS} m rt )
        endif()
    endif()

    INCLUDE (common.cmake)
ENDIF(BIICODE)

