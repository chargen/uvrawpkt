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

/**
 * @brief uv_rawpkt_iter_init
 * @param loop
 * @param iter
 * @return
 */
UV_EXTERN int uv_rawpkt_iter_init(uv_loop_t* loop,
                                  uv_rawpkt_iter_t* iter);


/**
 * @brief uv_rawpkt_iter_start
 * @param iter
 * @param found_cb
 * @param removed_cb
 * @return
 */
UV_EXTERN int uv_rawpkt_iter_start(uv_rawpkt_iter_t* iter,
                                   uv_rawpkt_iter_found_cb* found_cb,
                                   uv_rawpkt_iter_removed_cb* removed_cb);
/**
 * @brief uv_rawpkt_iter_stop
 * @param iter
 */
UV_EXTERN void uv_rawpkt_iter_stop(uv_rawpkt_iter_t* iter);

/**
 * @brief uv_rawpkt_init
 * @param loop
 * @param rawpkt
 * @return
 */
UV_EXTERN int uv_rawpkt_init(uv_loop_t* loop,
                             uv_rawpkt_t* rawpkt);

/**
 * @brief uv_rawpkt_open
 * @param rawpkt
 * @param device_name
 * @param promiscuous
 * @return
 */
UV_EXTERN int uv_rawpkt_open(uv_rawpkt_t* rawpkt,
                             const char* device_name,
                             int promiscuous);


/**
 * @brief uv_rawpkt_close
 * @param rawpkt
 * @param close_cb
 */
void uv_rawpkt_close(uv_rawpkt_t* rawpkt,
                               uv_close_cb close_cb);


/**
 * @brief uv_rawpkt_getmac
 * @param rawpkt
 * @param eui48
 * @return
 */
UV_EXTERN int uv_rawpkt_getmac(uv_rawpkt_t* rawpkt,
                               uint8_t *eui48);

/**
 * @brief uv_rawpkt_membership
 * @param rawpkt
 * @param multicast_addr
 * @param membership
 * @return
 */
UV_EXTERN int uv_rawpkt_membership(uv_rawpkt_t* rawpkt,
                                   uint8_t* multicast_addr,
                                   uv_membership membership);

/**
 * @brief uv_rawpkt_send
 * @param req
 * @param handle
 * @param bufs
 * @param nbufs
 * @param send_cb
 * @return
 */
UV_EXTERN int uv_rawpkt_send(uv_rawpkt_send_t* req,
                             uv_rawpkt_t* handle,
                             const uv_buf_t bufs[],
                             unsigned int nbufs,
                             uv_rawpkt_send_cb send_cb);

/**
 * @brief uv_rawpkt_recv_start
 * @param handle
 * @param alloc_cb
 * @param recv_cb
 * @return
 */
UV_EXTERN int uv_rawpkt_recv_start(uv_rawpkt_t* handle,
                                   uv_alloc_cb alloc_cb,
                                   uv_rawpkt_recv_cb recv_cb);


/**
 * @brief uv_rawpkt_recv_stop
 * @param handle
 * @return
 */
UV_EXTERN int uv_rawpkt_recv_stop(uv_rawpkt_t* handle);

/**
 * @brief uv_rawpkt_link_status_start
 * @param handle
 * @param link_status_cb
 * @return
 */
UV_EXTERN int uv_rawpkt_link_status_start(uv_rawpkt_t* handle,
                                          uv_rawpkt_link_status_cb link_status_cb);

/**
 * @brief uv_rawpkt_link_status_stop
 * @param handle
 * @param link_status_cb
 * @return
 */
UV_EXTERN int uv_rawpkt_link_status_stop(uv_rawpkt_t* handle,
                                          uv_rawpkt_link_status_cb link_status_cb);


#ifdef __cplusplus
}
#endif


#endif

