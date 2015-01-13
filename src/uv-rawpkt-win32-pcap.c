#include "uv.h"
#include "uv-rawpkt.h"

#if defined(_WIN32)

#include <iphlpapi.h>
#include <ws2_32.h>
#include <pcap.h>

#  pragma comment(lib, "IPHLPAPI.lib")
#  pragma comment(lib, "wpcap.lib" )
#  pragma comment(lib, "ws2_32.lib" )

#else
const char *uv_rawpkt_win32_pcap_file = __FILE__;
#endif

