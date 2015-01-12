#ifndef UV_RAWPKT_H
#define UV_RAWPKT_H

#include "uv-rawpkt-common.h"

#if defined(__APPLE__)
#include "uv-rawpkt-macosx-pcap.h"
#elif defined(_WIN32)
#include "uv-rawpkt-win32-pcap.h"
#elif defined(__linux__)
#include "uv-rawpkt-linux.h"
#else
#error uv-rawpkt platform not supported
#endif

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif


#endif

