#include "uv.h"

#if defined(_WIN32)
#include "uv-rawpkt-win32-pcap.h"

#  pragma comment(lib, "IPHLPAPI.lib")
#  pragma comment(lib, "wpcap.lib" )
#  pragma comment(lib, "ws2_32.lib" )

#else
const char *uv_rawpkt_win32_pcap_file = __FILE__;
#endif

