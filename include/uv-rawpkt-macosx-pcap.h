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
    uv_poll_t handle;
    void *pcap;
    void *data;
    uv_loop_t *loop;
    int link_status;
    uv_timer_t link_status_timer;
    uv_rawpkt_link_status_cb link_status_cb;
    uv_rawpkt_recv_cb recv_cb;
    char device_name[256];
    uint8_t mac[6];
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
    struct uv_rawpkt_iter_node_s *prev;
    int seen;
    char *device_name;
    char *device_description;
    uint8_t mac[6];
};

/**
 * @brief The uv_rawpkt_iter_s struct
 *
 * Manages the discovery and removal events of an ethernet network port
 */
struct uv_rawpkt_iter_s
{
    void *data;
    uv_timer_t scan_timer;
    uv_rawpkt_iter_cb added_cb;
    uv_rawpkt_iter_cb removed_cb;

    struct uv_rawpkt_iter_node_s *first;
    struct uv_rawpkt_iter_node_s *last;
};


#ifdef __cplusplus
}
#endif

#endif

#endif
