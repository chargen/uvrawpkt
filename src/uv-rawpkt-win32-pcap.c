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

#if defined(_WIN32) && UV_RAWPKT_ENABLE_PCAP==1

#include <iphlpapi.h>
#include <winsock2.h>
#include <pcap.h>
#include <Win32-Extensions.h>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "wpcap.lib" )
#pragma comment(lib, "ws2_32.lib" )
#pragma comment(lib, "psapi.lib" )


void uv__rawpkt_network_port_link_status_timer(uv_timer_t* handle)
{
    int new_status=0;
    uv_rawpkt_network_port_t *network_port = (uv_rawpkt_network_port_t *)handle->data;
    /* TODO: poll link status. See NotifyIpInterfaceChange  */

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

void uv__rawpkt_read_timer(uv_timer_t* handle )
{
    if( handle )
    {
        uv_rawpkt_t *rawpkt = (uv_rawpkt_t *)handle->data;
        if( rawpkt )
        {
            pcap_t *pcap = (pcap_t *)rawpkt->pcap;
            if( pcap )
            {
                while( pcap_dispatch(
                           pcap,
                           -1,
                           uv__rawpkt_readable_pcap_handler,
                           (u_char *)rawpkt) > 0 )
                {
                    ;
                }
            }
        }
    }
}




void uv__rawpkt_readable_pcap_handler(u_char *user,
                                      const struct pcap_pkthdr *h,
                                      const u_char *bytes)
{
    uv_rawpkt_t *rawpkt = (uv_rawpkt_t *)user;

    uv_buf_t buf;
    buf.base = (char *)bytes;
    buf.len = h->caplen;

    if( rawpkt->recv_cb )
    {
        rawpkt->recv_cb(rawpkt,1,&buf);
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
    pcap_t *pcap = 0;
    char filter[1024]="";
    int status=-1;
    int buffer_size=1*1024*1024;

    if( ethertype )
    {
        sprintf_s( filter, sizeof(filter), "ether proto 0x%04x", (int)*ethertype );
    }
    rawpkt->owner_network_port = network_port;

    status = uv__rawpkt_pcap_open(
                rawpkt,
                network_port,
                snaplen,
                promiscuous,
                to_ms,
                buffer_size,
                filter);

    if( status>=0 )
    {
        pcap =(pcap_t *)rawpkt->pcap;

        if( status>=0 )
        {
            status = uv_timer_init(rawpkt->loop,&rawpkt->recv_timer);
            rawpkt->recv_timer.data = (void*)rawpkt;

            if( status >=0 )
            {
                rawpkt->close_cb = close_cb;

                uv__rawpkt_network_port_add_rawpkt(network_port,rawpkt);

                status = uv_timer_start(&rawpkt->recv_timer,uv__rawpkt_read_timer,10,10);

                if( status<0 )
                {
                    uv__rawpkt_network_port_remove_rawpkt(network_port,rawpkt);
                }
            }
        }

        if( status<0 )
        {
            pcap_close(pcap);
        }
    }

    return status;
}

void uv_rawpkt_closed( uv_handle_t *handle )
{
    uv_rawpkt_t *rawpkt = (uv_rawpkt_t *)handle;

    uv_timer_stop(&rawpkt->recv_timer);

    if( rawpkt->pcap )
    {
        pcap_close( rawpkt->pcap );
    }

    uv__rawpkt_network_port_remove_rawpkt(rawpkt->owner_network_port,rawpkt);
    if( rawpkt->close_cb )
    {
        rawpkt->close_cb( (uv_handle_t *)rawpkt );
    }
}

void uv_rawpkt_close(uv_rawpkt_t* rawpkt)
{
    uv_close( (uv_handle_t *)&rawpkt->recv_timer, uv_rawpkt_closed );
}

int uv__rawpkt_iter_pcap_read_mac( pcap_if_t *pcap_if,
                                   uint8_t *mac )
{
    int r=-1;
    PIP_ADAPTER_INFO info = NULL, ninfo;
    ULONG ulOutBufLen = 0;
    DWORD dwRetVal = 0;
    if ( GetAdaptersInfo( info, &ulOutBufLen ) == ERROR_BUFFER_OVERFLOW )
    {
        info = (PIP_ADAPTER_INFO)malloc( ulOutBufLen );
        if ( info != NULL )
        {
            if ( ( dwRetVal = GetAdaptersInfo( info, &ulOutBufLen ) ) == NO_ERROR )
            {
                ninfo = info;
                while ( ninfo != NULL )
                {
                    if ( strstr( pcap_if->name, ninfo->AdapterName ) > 0 )
                    {
                        if ( ninfo->AddressLength == 6 )
                        {
                            memcpy( mac, ninfo->Address, 6 );
                            r=0;
                            break;
                        }
                    }
                    ninfo = ninfo->Next;
                }
            }
            free( info );
        }
    }
    return r;
}

#else
const char *uv_rawpkt_win32_pcap_file = __FILE__;
#endif

