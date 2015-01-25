#ifndef UV_RAWPKT_PCAP_H
#define UV_RAWPKT_PCAP_H

/*
  Copyright (c) 2015, J.D. Koftinoff Software, Ltd.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   3. Neither the name of J.D. Koftinoff Software, Ltd. nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

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

