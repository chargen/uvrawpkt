#include "uv.h"
#include "uv-rawpkt.h"

#if defined(__APPLE__)
#include <net/if_dl.h>
#include <pcap.h>


static int uv_rawpkt_pcap_open(
        uv_rawpkt_t* rawpkt,
        const char* device_name,
        int snaplen,
        int promiscuous,
        int to_ms,
        int buffer_size,
        const char *filter );

static int uv_rawpkt_iter_pcap_read_mac( pcap_if_t *pcap_if,
                                         uint8_t *mac );

static void uv_rawpkt_link_status_timer(uv_timer_t* handle);
static void uv_rawpkt_readable(uv_poll_t* handle, int status, int events);
static void uv_rawpkt_readable_pcap_handler(u_char *user,
                                            const struct pcap_pkthdr *h,
                                            const u_char *bytes);


static void uv_rawpkt_iter_timer(uv_timer_t* handle);
static void uv_rawpkt_iter_clear_seen_node(
        uv_rawpkt_iter_t* iter );
static uv_rawpkt_iter_node_t *uv_rawpkt_iter_add_node(
        uv_rawpkt_iter_t* iter,
        const char *device_name,
        const char *device_description,
        const uint8_t *mac );
static void uv_rawpkt_iter_free_node(
        uv_rawpkt_iter_t* iter,
        uv_rawpkt_iter_node_t* node );
static uv_rawpkt_iter_node_t * uv_rawpkt_iter_find_node(
        uv_rawpkt_iter_t* iter,
        const char *device_name);


void uv_rawpkt_link_status_timer(uv_timer_t* handle)
{
    int new_status=0;
    uv_rawpkt_t *rawpkt = (uv_rawpkt_t *)handle->data;
    /* TODO: poll link status */

    if( new_status != rawpkt->link_status )
    {
        rawpkt->link_status = new_status;
        if( rawpkt->link_status_cb )
        {
            rawpkt->link_status_cb(rawpkt,rawpkt->link_status);
        }
    }
}

void uv_rawpkt_readable(uv_poll_t* handle, int status, int events)
{
    uv_rawpkt_t *rawpkt = (uv_rawpkt_t *)handle->data;
    pcap_t *pcap = (pcap_t *)rawpkt->pcap;

    if( status==0 )
    {
        if( events & UV_READABLE )
        {
            struct pcap_pkthdr pkthdr;

            while( pcap_dispatch(pcap,1,uv_rawpkt_readable_pcap_handler,(u_char *)rawpkt) > 0 )
            {
                ;
            }
        }
    }
}

void uv_rawpkt_readable_pcap_handler(u_char *user,
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


void uv_rawpkt_iter_clear_seen_node(
        uv_rawpkt_iter_t* iter )
{
    uv_rawpkt_iter_node_t *cur=iter->first;

    while( cur )
    {
        cur->seen=0;
        cur = cur->next;
    }

}

uv_rawpkt_iter_node_t *uv_rawpkt_iter_add_node(
        uv_rawpkt_iter_t* iter,
        const char *device_name,
        const char *device_description,
        const uint8_t *mac )
{
    uv_rawpkt_iter_node_t *node = calloc(sizeof(uv_rawpkt_iter_node_t),1);
    if( node )
    {
        node->device_description = strdup(device_description);
        node->device_name = strdup(device_name);
        memcpy( node->mac, mac, 6 );
        node->seen=1;
        if( iter->first==0 )
        {
            iter->first = node;
            iter->last = node;
        }
        else
        {
            node->prev = iter->last;
            iter->last->next = node;
            iter->last = node;
        }
    }
    return node;
}

void uv_rawpkt_iter_free_node(
        uv_rawpkt_iter_t* iter,
        uv_rawpkt_iter_node_t* node )
{
    if( node )
    {
        if( iter->first==node )
        {
            iter->first=node->next;
        }
        if( iter->last==node )
        {
            iter->last=node->prev;
        }
        if( node->prev )
        {
            node->prev->next = node->next;
        }
        if( node->next )
        {
            node->next->prev = node->prev;
        }

        free(node->device_description);
        free(node->device_name);
    }
}


uv_rawpkt_iter_node_t * uv_rawpkt_iter_find_node(
        uv_rawpkt_iter_t* iter,
        const char *device_name )
{
    uv_rawpkt_iter_node_t *result=0;
    uv_rawpkt_iter_node_t *cur=iter->first;

    while( cur )
    {
        if( strcmp( cur->device_name, device_name)==0 )
        {
            result=cur;
            break;
        }
        cur = cur->next;
    }

    return result;
}

int uv_rawpkt_iter_pcap_read_mac( pcap_if_t *pcap_if,
                                  uint8_t *mac )
{
    int r=-1;
    pcap_addr_t *alladdrs;
    pcap_addr_t *a;
    alladdrs = pcap_if->addresses;
    for ( a = alladdrs; a != NULL; a = a->next )
    {
        if ( a->addr->sa_family == AF_LINK )
        {
            uint8_t const *macpos;
            struct sockaddr_dl *dl = (struct sockaddr_dl *)a->addr;
            macpos = (uint8_t const *)dl->sdl_data + dl->sdl_nlen;

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

void uv_rawpkt_iter_timer(uv_timer_t* handle)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    uv_rawpkt_iter_node_t *node;
    pcap_if_t *items;
    pcap_if_t *cur;
    uv_rawpkt_iter_t *self = (uv_rawpkt_iter_t *)handle->data;

    uv_rawpkt_iter_clear_seen_node( self );

    pcap_findalldevs(&items,errbuf);

    cur=items;
    while( cur )
    {
        if( !(cur->flags & PCAP_IF_LOOPBACK))
        {
            uint8_t mac[6];
            if( uv_rawpkt_iter_pcap_read_mac(cur,mac)==0 )
            {
                node = uv_rawpkt_iter_find_node(self,cur->name);
                if( node==0 )
                {
                    node = uv_rawpkt_iter_add_node(
                                self,
                                cur->name,
                                cur->description ? cur->description : "",
                                mac);
                    if( node )
                    {
                        self->added_cb(
                                    self,
                                    node->device_name,
                                    node->device_description,
                                    mac );
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
            uv_rawpkt_iter_node_t *next = node->next;

            self->removed_cb( self, node->device_name, node->device_description, node->mac );
            uv_rawpkt_iter_free_node( self, node );
            node = next;
        }
        else
        {
            node=node->next;
        }
    }
}

int uv_rawpkt_iter_init(uv_loop_t* loop,
                        uv_rawpkt_iter_t* iter)
{
    bzero(iter,sizeof(*iter));
    return uv_timer_init(loop,&iter->scan_timer);
}

int uv_rawpkt_iter_start(uv_rawpkt_iter_t* iter,
                         uv_rawpkt_iter_cb found_cb,
                         uv_rawpkt_iter_cb removed_cb)
{
    iter->added_cb = found_cb;
    iter->removed_cb = removed_cb;
    iter->scan_timer.data = (void *)iter;
    return uv_timer_start(&iter->scan_timer,uv_rawpkt_iter_timer,0,1000);
}

void uv_rawpkt_iter_stop(uv_rawpkt_iter_t* iter)
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



int uv_rawpkt_pcap_open(
        uv_rawpkt_t* rawpkt,
        const char* device_name,
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

    pcap = pcap_create(device_name,errbuf);

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

int uv_rawpkt_open(uv_rawpkt_t* rawpkt,
                   const char* device_name,
                   int snaplen,
                   int promiscuous,
                   int to_ms,
                   uint16_t *ethertype,
                   const uint8_t *mac )
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = 0;
    char filter[1024]="";
    int status=-1;
    int buffer_size=1*1024*1024;

    if( ethertype )
    {
        sprintf ( filter, "ether proto 0x%04x", *ethertype );
    }

    status = uv_rawpkt_pcap_open(
                rawpkt,
                device_name,
                snaplen,
                promiscuous,
                to_ms,
                buffer_size,
                filter);

    if( status>=0 )
    {
        pcap =(pcap_t *)rawpkt->pcap;
        int fd = pcap_get_selectable_fd(pcap);
        rawpkt->link_status_timer.data = (void *)rawpkt;
        memcpy( rawpkt->mac, mac, 6 );
        if( uv_poll_init_socket(
                    rawpkt->loop,&rawpkt->handle,
                    fd)==0 )
        {
            rawpkt->handle.data = (void *)rawpkt;
            strcpy(rawpkt->device_name,device_name);
            uv_timer_start(
                        &rawpkt->link_status_timer,
                        uv_rawpkt_link_status_timer,
                        0,
                        1000);
            uv_poll_start(
                        &rawpkt->handle,
                        UV_READABLE,
                        uv_rawpkt_readable);
            return 0;
        }
        else
        {
            return -1;
        }
    }

    return status;
}

void uv_rawpkt_close(uv_rawpkt_t* rawpkt,
                     uv_close_cb close_cb)
{
    uv_poll_stop(&rawpkt->handle);
    uv_timer_stop(&rawpkt->link_status_timer);
    uv_close( (uv_handle_t *)&rawpkt->handle, close_cb );
}

int uv_rawpkt_getmac(uv_rawpkt_t* rawpkt,
                     uint8_t *mac)
{
    pcap_t *pcap = (pcap_t *)rawpkt->pcap;
    memcpy( mac, rawpkt->mac, 6 );
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
const char *uv_rawpkt_macosx_pcap_file = __FILE__;
#endif

