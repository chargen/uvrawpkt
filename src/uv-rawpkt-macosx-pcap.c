#include "uv.h"

#if defined(__APPLE__)
#include "uv-rawpkt-macosx-pcap.h"

int uv_rawpkt_iter_init(uv_loop_t* loop,
                        uv_rawpkt_iter_t* iter)
{
    return -1;
}

int uv_rawpkt_iter_start(uv_rawpkt_iter_t* iter,
                         uv_rawpkt_iter_found_cb* found_cb,
                         uv_rawpkt_iter_removed_cb* removed_cb)
{
    return -1;
}

void uv_rawpkt_iter_stop(uv_rawpkt_iter_t* iter)
{

}

int uv_rawpkt_init(uv_loop_t* loop, uv_rawpkt_t* rawpkt )
{
    return -1;
}

int uv_rawpkt_open(uv_rawpkt_t* rawpkt,
                             const char* device_name,
                             int promiscuous)
{
    return -1;
}

void uv_rawpkt_close(uv_rawpkt_t* rawpkt,
                              uv_close_cb close_cb)
{
}

int uv_rawpkt_getmac(uv_rawpkt_t* rawpkt,
                               uint8_t *eui48)
{
    return -1;
}

int uv_rawpkt_membership(uv_rawpkt_t* rawpkt,
                                   uint8_t* multicast_addr,
                                   uv_membership membership)
{
    return -1;
}

int uv_rawpkt_send(uv_rawpkt_send_t* req,
                             uv_rawpkt_t* handle,
                             const uv_buf_t bufs[],
                             unsigned int nbufs,
                             uv_rawpkt_send_cb send_cb)
{
    return -1;
}

int uv_rawpkt_recv_start(uv_rawpkt_t* handle,
                                   uv_alloc_cb alloc_cb,
                                   uv_rawpkt_recv_cb recv_cb)
{
    return -1;
}

int uv_rawpkt_recv_stop(uv_rawpkt_t* handle)
{
    return -1;
}

int uv_rawpkt_link_status_start(uv_rawpkt_t* handle,
                                uv_rawpkt_link_status_cb link_status_cb)
{
    return -1;
}

int uv_rawpkt_link_status_stop(uv_rawpkt_t* handle,
                               uv_rawpkt_link_status_cb link_status_cb)
{
    return -1;
}

#else
const char *uv_rawpkt_macosx_pcap_file = __FILE__;
#endif

