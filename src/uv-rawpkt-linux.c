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
#include "uv-rawpkt.h"

#if defined(__linux__) && UV_RAWPKT_ENABLE_PCAP==0

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

void uv__rawpkt_network_port_link_status_timer(uv_timer_t* handle)
{
    int new_status=0;
    uv_rawpkt_network_port_t *network_port = (uv_rawpkt_network_port_t *)handle->data;
    /* TODO: poll link status */

    if( new_status != network_port->link_status )
    {
        uv_rawpkt_t *rawpkt = network_port->first_rawpkt;

        network_port->link_status = new_status;

        while( rawpkt )
        {
            if( rawpkt->link_status_cb )
            {
                rawpkt->link_status_cb(rawpkt,new_status);
            }
            rawpkt=rawpkt->next;
        }
    }
}

void uv__rawpkt_readable(uv_poll_t* handle, int status, int events)
{
    uv_rawpkt_t *rawpkt = (uv_rawpkt_t *)handle->data;

    if( status==0 )
    {
        if( events & UV_READABLE )
        {
            uint8_t buf[1500];
            size_t buf_len;
            do
            {
                buf_len = recv( rawpkt->fd, buf, sizeof( buf ), 0 );
            } while ( buf_len < 0 && ( errno == EINTR ) );
        }
    }
}


int uv_rawpkt_open(uv_rawpkt_t* rawpkt,
                   uv_rawpkt_network_port_t *network_port,
                   int snaplen,
                   int promiscuous,
                   int to_ms,
                   uint16_t *ethertype,
                   uv_close_cb close_cb)
{
    int fd=-1;

    /* only support open when ethertype is set */
    if( ethertype != NULL )
    {
        rawpkt->ethertype = *ethertype;
        fd = socket( AF_PACKET, SOCK_RAW, htons( *ethertype ) );
        rawpkt->fd = fd;
    }

    /* TODO: Set promiscuous mode if necessary */

    if ( fd >= 0 )
    {
        /* set socket to be non-blocking */
        {
            int val;
            int flags;
            val = fcntl( fd, F_GETFL, 0 );
            flags = O_NONBLOCK;
            val |= flags;
            fcntl( fd, F_SETFL, val );
        }

        rawpkt->owner_network_port = network_port;
        uv__rawpkt_network_port_add_rawpkt(network_port,rawpkt);

        if( uv_poll_init_socket(
                    rawpkt->loop,&rawpkt->handle,
                    fd)==0 )
        {
            rawpkt->close_cb = close_cb;

            rawpkt->handle.data = (void *)rawpkt;

            uv_poll_start(
                        &rawpkt->handle,
                        UV_READABLE,
                        uv__rawpkt_readable);           
        }
        else
        {
            close(fd);
            fd=-1;
        }
    }

    return fd >= 0 ? 0 : -1;
}

void uv_rawpkt_closed( uv_handle_t *handle )
{
    uv_rawpkt_t *rawpkt = (uv_rawpkt_t *)handle;

    uv__rawpkt_network_port_remove_rawpkt(rawpkt->owner_network_port,rawpkt);
    if( rawpkt->close_cb )
    {
        rawpkt->close_cb( (uv_handle_t *)rawpkt );
    }
}

int uv_rawpkt_send(uv_rawpkt_send_t* req,
                   uv_rawpkt_t * rawpkt,
                   const uv_buf_t bufs[],
                   unsigned int nbufs,
                   uv_rawpkt_send_cb send_cb )
{
    int r = -1;
    ssize_t sent_len;
    struct sockaddr_ll socket_address;
#if 0
    uint8_t buffer[ETH_FRAME_LEN];
    unsigned char *etherhead = buffer;
    unsigned char *data = buffer + 14;
    struct ethhdr *eh = (struct ethhdr *)etherhead;

    socket_address.sll_family = PF_PACKET;
    socket_address.sll_protocol = htons( rawpkt->ethertype );
    socket_address.sll_ifindex = rawpkt->owner_network_port->interface_id;
    socket_address.sll_hatype = 1; /*ARPHRD_ETHER; */
    socket_address.sll_pkttype = PACKET_OTHERHOST;
    socket_address.sll_halen = ETH_ALEN;
    memcpy( socket_address.sll_addr, rawpkt->owner_network_port->mac, ETH_ALEN );
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    do
    {
        sent_len
            = sendto(
                    rawpkt->fd, buffer,
                    payload_len + 14,
                    0,
                    (struct sockaddr *)&socket_address,
                    sizeof( socket_address ) );
    } while ( sent_len < 0 && ( errno == EINTR ) );
#endif
    if ( sent_len >= 0 )
    {
        r=0;
    }

    if( send_cb )
    {
        send_cb(req,r);
    }

    return r;
}

void uv_rawpkt_close(uv_rawpkt_t* rawpkt)
{
    uv_close( (uv_handle_t *)&rawpkt->handle, uv_rawpkt_closed );
}



void uv__rawpkt_iter_timer(uv_timer_t* handle)
{
    uv_rawpkt_network_port_iterator_t *iter = (uv_rawpkt_network_port_iterator_t *)handle->data;
    int i;

    /* TODO scan through all interfaces */
    /* get MAC adderess for each and get interface_id for each */
    for ( i = 0; i < 6; ++i )
    {
//        self->m_my_mac[i] = (uint8_t)ifr.ifr_hwaddr.sa_data[i];
    }

}

#else
const char *uv_rawpkt_linux_file = __FILE__;
#endif

