#include "uv.h"
#include "uv-rawpkt.h"

#if UV_RAWPKT_ENABLE_PCAP

#include <pcap.h>

int uv_rawpkt_network_port_iterator_init(uv_loop_t* loop,
                                         uv_rawpkt_network_port_iterator_t* iter)
{
    bzero(iter,sizeof(*iter));
    iter->loop = loop;
    return uv_timer_init(loop,&iter->scan_timer);
}

int uv_rawpkt_network_port_iterator_start(uv_rawpkt_network_port_iterator_t* iter,
                                          uv_rawpkt_network_port_iterator_cb found_cb,
                                          uv_rawpkt_network_port_iterator_cb removed_cb)
{
    iter->added_cb = found_cb;
    iter->removed_cb = removed_cb;
    iter->scan_timer.data = (void *)iter;
    return uv_timer_start(&iter->scan_timer,uv__rawpkt_iter_timer,0,1000);
}

void uv_rawpkt_network_port_iterator_stop(uv_rawpkt_network_port_iterator_t* iter)
{
    uv_timer_stop(&iter->scan_timer);
}

int uv_rawpkt_init(uv_loop_t* loop, uv_rawpkt_t* rawpkt )
{
    bzero(rawpkt,sizeof(uv_rawpkt_t));
    rawpkt->loop = loop;
    rawpkt->link_status=0;
    return uv_timer_init(loop,&rawpkt->link_status_timer);
}



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
    int dl;

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

            self->removed_cb( self, node );
            uv__rawpkt_iter_free_network_port( self, node );
            node = next;
        }
        else
        {
            node=node->next;
        }
    }
}

int uv_rawpkt_getmac(uv_rawpkt_t* rawpkt,
                     uint8_t *mac)
{
    pcap_t *pcap = (pcap_t *)rawpkt->pcap;
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
        pcap_sendpacket(pcap,(const u_char *)bufs[i].base,bufs[i].len);
    }
    return 0;
}

int uv_rawpkt_recv_start(uv_rawpkt_t* handle,
                         uv_rawpkt_recv_cb recv_cb)
{
    handle->recv_cb = recv_cb;
    return 0;
}

int uv_rawpkt_recv_stop(uv_rawpkt_t* handle)
{
    handle->recv_cb = 0;
    return 0;
}

int uv_rawpkt_link_status_start(uv_rawpkt_t* handle,
                                uv_rawpkt_link_status_cb link_status_cb)
{
    handle->link_status_cb = link_status_cb;
    return 0;
}

int uv_rawpkt_link_status_stop(uv_rawpkt_t* handle)
{
    handle->link_status_cb = 0;
    return 0;
}
#else
const char *uv_rawpkt_pcap_file = __FILE__;
#endif
