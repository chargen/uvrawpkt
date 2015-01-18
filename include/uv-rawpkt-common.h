#ifndef UV_RAWPKT_COMMON_H
#define UV_RAWPKT_COMMON_H

#include "uv.h"
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UV_RAWPKT_ENABLE_PCAP
#define UV_RAWPKT_ENABLE_PCAP 1
#endif

#ifdef _WIN32
  /* Windows - set up dll import/export decorators. */
# if defined(BUILDING_UVRAWPKT_SHARED)
    /* Building shared library. */
#   define UVRAWPKT_EXTERN __declspec(dllexport)
# elif defined(USING_UV_SHARED)
    /* Using shared library. */
#   define UVRAWPKT_EXTERN __declspec(dllimport)
# else
    /* Building static library. */
#   define UVRAWPKT_EXTERN /* nothing */
# endif
#elif __GNUC__ >= 4
# define UVRAWPKT_EXTERN __attribute__((visibility("default")))
#else
# define UVRAWPKT_EXTERN /* nothing */
#endif


struct uv_rawpkt_s;
struct uv_rawpkt_send_s;
struct uv_rawpkt_network_port_s;
struct uv_rawpkt_network_port_iterator_s;

typedef struct uv_rawpkt_s uv_rawpkt_t;
typedef struct uv_rawpkt_send_s uv_rawpkt_send_t;
typedef struct uv_rawpkt_network_port_s uv_rawpkt_network_port_t;
typedef struct uv_rawpkt_network_port_iterator_s uv_rawpkt_network_port_iterator_t;

/**
 * Callback function signature for when a raw packet has been sent
 */
typedef void (*uv_rawpkt_send_cb)(struct uv_rawpkt_send_s* handle,
                                  int status );

/**
 * Callback function signature for when a packet has been received
 */
typedef void (*uv_rawpkt_recv_cb)(struct uv_rawpkt_s* handle,
                                  ssize_t nread,
                                  const uv_buf_t* buf);

/**
 * Callback function signature for when a network port link status changed
 */
typedef void (*uv_rawpkt_link_status_cb)(struct uv_rawpkt_s* handle,
                                         int link_status);

/**
 * Callback function signature for when a network port is found or removed
 */
typedef void (*uv_rawpkt_network_port_iterator_cb)(
        struct uv_rawpkt_network_port_iterator_s* handle,
        struct uv_rawpkt_network_port_s* port_info );


/**
 * @brief uv_rawpkt_network_port_iterator_init
 * @param loop
 * @param iter
 * @return
 */
UVRAWPKT_EXTERN
int uv_rawpkt_network_port_iterator_init(uv_loop_t* loop,
                                         uv_rawpkt_network_port_iterator_t* iter);


/**
 * @brief uv_rawpkt_network_port_iterator_start
 * @param iter
 * @param found_cb
 * @param removed_cb
 * @return
 */
UVRAWPKT_EXTERN
int uv_rawpkt_network_port_iterator_start(uv_rawpkt_network_port_iterator_t* iter,
                                          uv_rawpkt_network_port_iterator_cb found_cb,
                                          uv_rawpkt_network_port_iterator_cb removed_cb);
/**
 * @brief uv_rawpkt_iter_stop
 * @param iter
 */
UVRAWPKT_EXTERN
void uv_rawpkt_network_port_iterator_stop(uv_rawpkt_network_port_iterator_t* iter);

/**
 * @brief uv_rawpkt_init
 * @param loop
 * @param rawpkt
 * @param owner_port
 * @return
 */
UVRAWPKT_EXTERN
int uv_rawpkt_init(uv_loop_t* loop,
                   uv_rawpkt_t* rawpkt);




/**
 * @brief uv_rawpkt_getmac
 * @param rawpkt
 * @param eui48
 * @return
 */
UVRAWPKT_EXTERN
int uv_rawpkt_getmac(uv_rawpkt_t* rawpkt,
                     uint8_t *eui48);

/**
 * @brief uv_rawpkt_membership
 * @param rawpkt
 * @param multicast_addr
 * @param membership
 * @return
 */
UVRAWPKT_EXTERN int uv_rawpkt_membership(uv_rawpkt_t* rawpkt,
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
UVRAWPKT_EXTERN
int uv_rawpkt_send(uv_rawpkt_send_t* req,
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
UVRAWPKT_EXTERN
int uv_rawpkt_recv_start(uv_rawpkt_t* handle,
                         uv_rawpkt_recv_cb recv_cb);


/**
 * @brief uv_rawpkt_recv_stop
 * @param handle
 * @return
 */
UVRAWPKT_EXTERN
int uv_rawpkt_recv_stop(uv_rawpkt_t* handle);

/**
 * @brief uv_rawpkt_link_status_start
 * @param handle
 * @param link_status_cb
 * @return
 */
UVRAWPKT_EXTERN
int uv_rawpkt_link_status_start(uv_rawpkt_t* handle,
                                uv_rawpkt_link_status_cb link_status_cb);

/**
 * @brief uv_rawpkt_link_status_stop
 * @param handle
 * @param link_status_cb
 * @return
 */
UVRAWPKT_EXTERN
int uv_rawpkt_link_status_stop(uv_rawpkt_t* handle);


/**
 * @brief uv__rawpkt_network_port_add_rawpkt
 * @param node
 * @param rawpkt
 * @return
 */
UVRAWPKT_EXTERN
int uv__rawpkt_network_port_add_rawpkt(uv_rawpkt_network_port_t *node,
                                       uv_rawpkt_t *rawpkt );


/**
 * @brief uv__rawpkt_network_port_remove_rawpkt
 * @param node
 * @param rawpkt
 * @return
 */
UVRAWPKT_EXTERN
int uv__rawpkt_network_port_remove_rawpkt(uv_rawpkt_network_port_t *node,
                                       uv_rawpkt_t *rawpkt );

#ifdef __cplusplus
}
#endif

#endif

