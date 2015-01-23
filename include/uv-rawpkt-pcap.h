#ifndef UV_RAWPKT_PCAP_H
#define UV_RAWPKT_PCAP_H

#include "uv-rawpkt-common.h"

#if UV_RAWPKT_ENABLE_PCAP

#ifdef __cplusplus
extern "C" {
#endif

struct pcap_if;
struct pcap;
struct pcap_pkthdr;

/**
 * @brief uv__rawpkt_pcap_open
 * @param rawpkt
 * @param network_port
 * @param snaplen
 * @param promiscuous
 * @param to_ms
 * @param buffer_size
 * @param filter
 * @return
 */
int uv__rawpkt_pcap_open(
        uv_rawpkt_t* rawpkt,
        uv_rawpkt_network_port_t *network_port,
        int snaplen,
        int promiscuous,
        int to_ms,
        int buffer_size,
        const char *filter );


/**
 * @brief uv__rawpkt_readable_pcap_handler
 * @param user
 * @param h
 * @param bytes
 */
void uv__rawpkt_readable_pcap_handler(u_char *user,
                                      const struct pcap_pkthdr *h,
                                      const u_char *bytes);

/**
 * @brief uv__rawpkt_iter_clear_seen_network_port
 * @param iter
 */
void uv__rawpkt_iter_clear_seen_network_port(
        uv_rawpkt_network_port_iterator_t* iter );

/**
 * @brief uv__rawpkt_iter_add_network_port
 * @param iter
 * @param device_name
 * @param device_description
 * @param mac
 * @return
 */
uv_rawpkt_network_port_t *uv__rawpkt_iter_add_network_port(
        uv_rawpkt_network_port_iterator_t* iter,
        const char *device_name,
        const char *device_description,
        const uint8_t *mac );

/**
 * @brief uv__rawpkt_iter_free_network_port
 * @param iter
 * @param node
 */
void uv__rawpkt_iter_free_network_port(
        uv_rawpkt_network_port_iterator_t* iter,
        uv_rawpkt_network_port_t* node );

/**
 * @brief uv__rawpkt_iter_find_network_port
 * @param iter
 * @param device_name
 * @return
 */
uv_rawpkt_network_port_t * uv__rawpkt_iter_find_network_port(
        uv_rawpkt_network_port_iterator_t* iter,
        const char *device_name);

void uv__rwpkt_network_port_closed( uv_handle_t *handle );

#ifdef __cplusplus
}
#endif

#endif

#endif

