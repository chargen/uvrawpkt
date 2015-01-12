#include "uv.h"

#if defined(__APPLE__)
#include "uv-rawpkt-macosx-pcap.h"

void *todo = 0;

#else
const char *uv_rawpkt_macosx_pcap_file = __FILE__;
#endif

