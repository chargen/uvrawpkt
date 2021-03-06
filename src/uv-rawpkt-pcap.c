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

#include "uv.h"
#include "uv-rawpkt-common.h"
#include "uv-rawpkt-pcap.h"

#include "uv-rawpkt.h"

#if UV_RAWPKT_ENABLE_PCAP==1

#include <pcap.h>

int uv__rawpkt_pcap_open(
        uv_rawpkt_t* rawpkt,
        uv_rawpkt_network_port_t *network_port,
        int snaplen,
        int promiscuous,
        int to_ms,
        int buffer_size,
        const char *filter )
{
    int status=-1;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap=0;
    struct bpf_program fcode;

    pcap = pcap_create(network_port->device_name,errbuf);

    if( pcap )
    {
        status = 0;

        if( status >=0 )
        {
            status = pcap_set_snaplen(pcap, snaplen);
        }
        if( status >=0 )
        {
            status = pcap_set_promisc(pcap, promiscuous);
        }
        if( status >=0 )
        {
            pcap_setnonblock(pcap,1,errbuf);
        }
        if( status >=0 )
        {
            status = pcap_set_timeout(pcap, to_ms);
        }
        if( status >=0 )
        {
            status = pcap_set_buffer_size(pcap, buffer_size);
        }
        if( status >=0 )
        {
            pcap_setdirection(pcap,PCAP_D_IN);
        }
        if( status>=0 )
        {
            status = pcap_activate(pcap);
        }
        if( status >=0 && filter )
        {
            status = pcap_compile ( pcap, &fcode, filter, 1, 0xffffffff );

            if( status >=0 )
            {
                status = pcap_setfilter ( pcap, &fcode );
                pcap_freecode ( &fcode );
            }
            else
            {
                printf( "pcap_compile error: %s\n", pcap_geterr(pcap) );
            }
        }


        if( status >=0 )
        {
            rawpkt->pcap = (void *)pcap;
        }

        if( status < 0 )
        {
            pcap_close(pcap);
        }
    }

    return status;
}



void uv__rawpkt_iter_timer(uv_timer_t* handle)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    uv_rawpkt_network_port_t *node;
    pcap_if_t *items;
    pcap_if_t *cur;
    uv_rawpkt_network_port_iterator_t *self = (uv_rawpkt_network_port_iterator_t *)handle->data;

    uv__rawpkt_iter_clear_seen_network_port( self );

    pcap_findalldevs(&items,errbuf);

    cur=items;
    while( cur )
    {
        if( !(cur->flags & PCAP_IF_LOOPBACK))
        {
            uint8_t mac[6];
            if( uv__rawpkt_iter_pcap_read_mac(cur,mac)==0 )
            {
                node = uv__rawpkt_iter_find_network_port(self,cur->name);
                if( node==0 )
                {
                    node = uv__rawpkt_iter_add_network_port(
                                self,
                                cur->name,
                                cur->description ? cur->description : "",
                                mac);
                    if( node )
                    {
                        self->added_cb(
                                    self,
                                    node );
                    }
                }
                else
                {
                    node->seen=1;
                }
            }
        }
        cur = cur->next;
    }
    pcap_freealldevs(items);

    node=self->first;
    while( node )
    {
        if( node->seen==0 )
        {
            uv_rawpkt_network_port_t *next = node->next;
            uv_rawpkt_t *rawpkt = node->first_rawpkt;
            
            if( rawpkt )
            {
                /* If the node has any rawpkt objects, close them */
                while( rawpkt )
                {
                    uv_rawpkt_t *rawpkt_next = rawpkt->next;
                    uv_rawpkt_close(rawpkt);
                    rawpkt = rawpkt_next;
                }
            }
            else
            {
                /* If the node does not have any rawpkt objects, free the node */
                
                uv_close( (uv_handle_t *)&node->link_status_timer, uv__rwpkt_network_port_closed );
            }
            node = next;
        }
        else
        {
            node=node->next;
        }
    }
}

void uv__rwpkt_network_port_closed( uv_handle_t *handle )
{
    uv_rawpkt_network_port_t *node = (uv_rawpkt_network_port_t *)handle->data;
    uv_rawpkt_network_port_iterator_t *self = node->owner;

    self->removed_cb( self, node );
    uv__rawpkt_iter_free_network_port( self, node );
}


int uv_rawpkt_getmac(uv_rawpkt_t* rawpkt,
                     uint8_t *mac)
{
    memcpy( mac, rawpkt->owner_network_port->mac, 6 );
    return 0;
}

int uv_rawpkt_membership(uv_rawpkt_t* rawpkt,
                         uint8_t* multicast_addr,
                         uv_membership membership)
{
    /** TODO: membership */
    return -1;
}

int uv_rawpkt_send(uv_rawpkt_send_t* req,
                   uv_rawpkt_t* handle,
                   const uv_buf_t bufs[],
                   unsigned int nbufs,
                   uv_rawpkt_send_cb send_cb)
{
    pcap_t *pcap = (pcap_t *)handle->pcap;
    unsigned int i;
    for( i=0; i<nbufs; ++i )
    {
        int status = pcap_sendpacket(pcap,(const u_char *)bufs[i].base,bufs[i].len);
        if( send_cb )
        {
            send_cb( req, status );
        }
    }
    return 0;
}


#else
const char *uv_rawpkt_pcap_file = __FILE__;
#endif
