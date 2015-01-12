#ifndef UV_RAWPKT_MACOSX_PCAP_H
#define UV_RAWPKT_MACOSX_PCAP_H

#include "uv.h"

#ifdef __cplusplus
extern "C" {
#endif

struct uv_rawpkt_s;
struct uv_rawpkt_send_s;
struct uv_rawpkt_iter_node_s;
struct uv_rawpkt_iter_s;

typedef void (*uv_rawpkt_send_cb)(struct uv_rawpkt_send_s* handle,
                                  int status );

typedef void (*uv_rawpkt_recv_cb)(struct uv_rawpkt_s* handle,
                                  ssize_t nread,
                                  const uv_buf_t* buf);

typedef void (*uv_rawpkt_link_status_cb)(struct uv_rawpkt_s* handle,
                                         int link_status);

typedef void (*uv_rawpkt_iter_found_cb)(struct uv_rawpkt_iter_s* handle,
                                        const char *device_name );

typedef void (*uv_rawpkt_iter_removed_cb)(struct uv_rawpkt_iter_s* handle,
                                          const char *device_name );

struct uv_rawpkt_s
{
    uv_handle_t handle;
    uv_timer_t link_status_timer;
    int link_status;
    uv_rawpkt_link_status_cb link_status_cb;
    uv_rawpkt_recv_cb recv_cb;
    const char *device_name;
};

typedef struct uv_rawpkt_s uv_rawpkt_t;

struct uv_rawpkt_send_s
{
    void *data;
    uv_rawpkt_t* handle;
    uv_rawpkt_send_cb cb;
};

typedef struct uv_rawpkt_send_s uv_rawpkt_send_t;

struct uv_rawpkt_iter_node_s
{
    struct uv_rawpkt_iter_node_s *next;
    const char *device_name;
};

typedef struct uv_rawpkt_iter_node_s uv_rawpkt_iter_node_t;

struct uv_rawpkt_iter_s
{
    uv_timer_t scan_timer;
    uv_rawpkt_iter_found_cb added_cb;
    uv_rawpkt_iter_removed_cb removed_cb;

    struct uv_rawpkt_iter_node_s *first;
};

typedef struct uv_rawpkt_iter_s uv_rawpkt_iter_t;

UV_EXTERN int uv_rawpkt_iter_init(uv_loop_t* loop,
                                  uv_rawpkt_iter_t* iter);
UV_EXTERN int uv_rawpkt_iter_start(uv_rawpkt_iter_t* iter,
                                   uv_rawpkt_iter_found_cb* found_cb,
                                   uv_rawpkt_iter_removed_cb* removed_cb);
UV_EXTERN void uv_rawpkt_iter_stop(uv_rawpkt_iter_t* iter);

UV_EXTERN int uv_rawpkt_init(uv_loop_t* loop,
                             uv_rawpkt_t* rawpkt);
UV_EXTERN int uv_rawpkt_open(uv_rawpkt_t* rawpkt,
                             const char* device_name,
                             int promiscuous);
UV_EXTERN void uv_rawpkt_close(uv_rawpkt_t* rawpkt,
                               uv_close_cb close_cb);
UV_EXTERN int uv_rawpkt_getmac(uv_rawpkt_t* rawpkt,
                               uint8_t *eui48);
UV_EXTERN int uv_rawpkt_membership(uv_rawpkt_t* rawpkt,
                                   uint8_t* multicast_addr,
                                   uv_membership membership);
UV_EXTERN int uv_rawpkt_send(uv_rawpkt_send_t* req,
                             uv_rawpkt_t* handle,
                             const uv_buf_t bufs[],
                             unsigned int nbufs,
                             uv_rawpkt_send_cb send_cb);
UV_EXTERN int uv_rawpkt_recv_start(uv_rawpkt_t* handle,
                                   uv_alloc_cb alloc_cb,
                                   uv_rawpkt_recv_cb recv_cb);
UV_EXTERN int uv_rawpkt_recv_stop(uv_rawpkt_t* handle);
UV_EXTERN int uv_rawpkt_link_status_start(uv_rawpkt_t* handle,
                                          uv_rawpkt_link_status_cb link_status_cb);
UV_EXTERN int uv_rawpkt_link_status_stop(uv_rawpkt_t* handle,
                                          uv_rawpkt_link_status_cb link_status_cb);

#ifdef __cplusplus
}
#endif

#endif
