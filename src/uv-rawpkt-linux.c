#include "uv.h"
#include "uv-rawpkt.h"

#if defined(__linux__)

#include <linux/if_packet.h>

#include <pcap.h>

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
    pcap_t *pcap = (pcap_t *)rawpkt->pcap;

    if( status==0 )
    {
        if( events & UV_READABLE )
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
        sprintf ( filter, "ether proto 0x%04x", *ethertype );
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

        uv__rawpkt_network_port_add_rawpkt(network_port,rawpkt);
        int fd = pcap_get_selectable_fd(pcap);

        if( uv_poll_init_socket(
                    rawpkt->loop,&rawpkt->handle,
                    fd)==0 )
        {
            rawpkt->handle.data = (void *)rawpkt;

            uv_poll_start(
                        &rawpkt->handle,
                        UV_READABLE,
                        uv__rawpkt_readable);
            return 0;
        }
        else
        {
            return -1;
        }
    }

    return status;
}

void uv_rawpkt_closed( uv_handle_t *handle )
{
    uv_rawpkt_t *rawpkt = (uv_rawpkt_t *)handle;
    if( rawpkt->pcap )
    {
        pcap_close( rawpkt->pcap );
    }
    
    uv__rawpkt_network_port_remove_rawpkt(rawpkt->owner_network_port,rawpkt);
    if( rawpkt->close_cb )
    {
        rawpkt->close_cb( (uv_handle_t *)rawpkt );
    }
    free(rawpkt);
}

void uv_rawpkt_close(uv_rawpkt_t* rawpkt)
{
    uv_close( (uv_handle_t *)&rawpkt->handle, uv_rawpkt_closed );
}


int uv__rawpkt_iter_pcap_read_mac( pcap_if_t *pcap_if,
                                   uint8_t *mac )
{
    int r=-1;
    pcap_addr_t *alladdrs;
    pcap_addr_t *a;
    alladdrs = pcap_if->addresses;
    for ( a = alladdrs; a != NULL; a = a->next )
    {
        if ( a->addr->sa_family == AF_PACKET )
        {
            uint8_t const *macpos;
            struct sockaddr_ll *ll = (struct sockaddr_ll *)a->addr;
            macpos = ll->sll_addr;

            memcpy( mac, macpos, 6 );
            if( mac[0]!=0 || mac[1]!=0 || mac[2]!=0
                    || mac[3]!=0 || mac[4]!=0 || mac[5]!=0 )
            {
                r=0;
            }
            break;
        }
    }
    return r;
}


#else
const char *uv_rawpkt_linux_file = __FILE__;
#endif

