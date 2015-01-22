#include "uv.h"
#include "uv-rawpkt.h"

#if defined(_WIN32)

#include <iphlpapi.h>
#include <winsock2.h>
#include <pcap.h>
#include <Win32-Extensions.h>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "wpcap.lib" )
#pragma comment(lib, "ws2_32.lib" )
#pragma comment(lib, "psapi.lib" )

static void CALLBACK uv__rawpkt_win32_event(void *data, BOOLEAN didTimeout )
{
    uv_async_t *async = (uv_async_t*)data;
    uv_rawpkt_t *rawpkt = (uv_rawpkt_t*)data;
    uv_rawpkt_network_port_t *network_port=rawpkt->owner_network_port;
    uv_rawpkt_network_port_iterator_t *network_port_iterator = network_port->owner;
    (void)didTimeout;

    /* go through all rawpkt handles for all network ports and notify them to try
     * read and dispatch packets
     */
    network_port = network_port_iterator->first;
    while( network_port )
    {
        rawpkt=network_port->first_rawpkt;

        while( rawpkt )
        {
            uv_async_send(&rawpkt->handle);
            rawpkt=rawpkt->next;
        }

        network_port = network_port->next;
    }
}

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

void uv__rawpkt_readable(uv_async_t* handle )
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
                           1,
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
            status = uv_async_init(rawpkt->loop,
                                   &rawpkt->handle,
                                   uv__rawpkt_readable);
            rawpkt->handle.data = (void*)rawpkt;

            if( status >=0 )
            {
                if( RegisterWaitForSingleObject(
                            &rawpkt->wait,
                            pcap_getevent(pcap),
                            uv__rawpkt_win32_event,
                            &rawpkt->handle,
                            INFINITE,
                            WT_EXECUTEINWAITTHREAD
                            ) != 0 )
                {
                    uv__rawpkt_network_port_add_rawpkt(network_port,rawpkt);
                }
                else
                {
                    UnregisterWait(rawpkt->wait);
                    status=-1;
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
    UnregisterWait(rawpkt->wait);
    uv__rawpkt_network_port_remove_rawpkt(rawpkt->owner_network_port,rawpkt);
    if( rawpkt->close_cb )
    {
        rawpkt->close_cb( (uv_handle_t *)rawpkt );
    }
}

void uv_rawpkt_close(uv_rawpkt_t* rawpkt)
{
    uv_close( (uv_handle_t *)&rawpkt->handle, uv_rawpkt_closed );
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

