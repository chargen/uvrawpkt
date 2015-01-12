#ifndef UV_RAWPKT_MACOSX_PCAP_H
#define UV_RAWPKT_MACOSX_PCAP_H

#include "uv-rawpkt-common.h"

#if defined(__APPLE__)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The uv_rawpkt_s struct
 *
 * Manages the send/receive packets on a single ethernet port
 */
struct uv_rawpkt_s
{
    uv_handle_t handle;
    uv_timer_t link_status_timer;
    int link_status;
    uv_rawpkt_link_status_cb link_status_cb;
    uv_rawpkt_recv_cb recv_cb;
    const char *device_name;
};

/**
 * @brief The uv_rawpkt_send_s struct
 *
 * Maintains the context for a rawpkt send request
 */
struct uv_rawpkt_send_s
{
    void *data;
    uv_rawpkt_t* handle;
    uv_rawpkt_send_cb cb;
};

/**
 * @brief The uv_rawpkt_iter_node_s struct
 *
 * Maintains the context of a single discovered network port
 */
struct uv_rawpkt_iter_node_s
{
    struct uv_rawpkt_iter_node_s *next;
    const char *device_name;
};

/**
 * @brief The uv_rawpkt_iter_s struct
 *
 * Manages the discovery and removal events of an ethernet network port
 */
struct uv_rawpkt_iter_s
{
    uv_timer_t scan_timer;
    uv_rawpkt_iter_found_cb added_cb;
    uv_rawpkt_iter_removed_cb removed_cb;

    struct uv_rawpkt_iter_node_s *first;
};


#ifdef __cplusplus
}
#endif

#endif

#endif