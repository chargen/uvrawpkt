#include "uv.h"
#include "uv-rawpkt.h"

#if defined(__APPLE__)
#include <net/if_dl.h>
#include <pcap.h>

static void uv_rawpkt_iter_timer(uv_timer_t* handle);
static void uv_rawpkt_iter_clear_seen_node(
        uv_rawpkt_iter_t* iter );
static uv_rawpkt_iter_node_t *uv_rawpkt_iter_add_node(
        uv_rawpkt_iter_t* iter,
        const char *device_name,
        const char *device_description);
static void uv_rawpkt_iter_free_node(
        uv_rawpkt_iter_t* iter,
        uv_rawpkt_iter_node_t* node );
static uv_rawpkt_iter_node_t * uv_rawpkt_iter_find_node(
        uv_rawpkt_iter_t* iter,
        const char *device_name);

static void uv_rawpkt_iter_clear_seen_node(
        uv_rawpkt_iter_t* iter )
{
    uv_rawpkt_iter_node_t *cur=iter->first;

    while( cur )
    {
        cur->seen=0;
        cur = cur->next;
    }

}

static uv_rawpkt_iter_node_t *uv_rawpkt_iter_add_node(
        uv_rawpkt_iter_t* iter,
        const char *device_name,
        const char *device_description)
{
    uv_rawpkt_iter_node_t *node = calloc(sizeof(uv_rawpkt_iter_node_t),1);
    if( node )
    {
        node->device_description = strdup(device_description);
        node->device_name = strdup(device_name);
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

static void uv_rawpkt_iter_free_node(
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


static uv_rawpkt_iter_node_t * uv_rawpkt_iter_find_node(
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

static void uv_rawpkt_iter_timer(uv_timer_t* handle)
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
        if( !(cur->flags & PCAP_IF_LOOPBACK) )
        {
            node = uv_rawpkt_iter_find_node(self,cur->name);
            if( node==0 )
            {
                node = uv_rawpkt_iter_add_node(
                            self,
                            cur->name,
                            cur->description ? cur->description : "");
                if( node )
                {
                    self->added_cb(
                                self,
                                node->device_name,
                                node->device_description );
                }
            }
            else
            {
                node->seen=1;
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

            self->removed_cb( self, node->device_name, node->device_description );
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
    return -1;
}

int uv_rawpkt_open(uv_rawpkt_t* rawpkt,
                   const char* device_name,
                   int promiscuous,
                   uint16_t *ethertype )
{
    return -1;
}

void uv_rawpkt_close(uv_rawpkt_t* rawpkt,
                     uv_close_cb close_cb)
{
}

int uv_rawpkt_getmac(uv_rawpkt_t* rawpkt,
                     uint8_t *eui48)
{
    return -1;
}

int uv_rawpkt_membership(uv_rawpkt_t* rawpkt,
                         uint8_t* multicast_addr,
                         uv_membership membership)
{
    return -1;
}

int uv_rawpkt_send(uv_rawpkt_send_t* req,
                   uv_rawpkt_t* handle,
                   const uv_buf_t bufs[],
                   unsigned int nbufs,
                   uv_rawpkt_send_cb send_cb)
{
    return -1;
}

int uv_rawpkt_recv_start(uv_rawpkt_t* handle,
                         uv_alloc_cb alloc_cb,
                         uv_rawpkt_recv_cb recv_cb)
{
    return -1;
}

int uv_rawpkt_recv_stop(uv_rawpkt_t* handle)
{
    return -1;
}

int uv_rawpkt_link_status_start(uv_rawpkt_t* handle,
                                uv_rawpkt_link_status_cb link_status_cb)
{
    return -1;
}

int uv_rawpkt_link_status_stop(uv_rawpkt_t* handle,
                               uv_rawpkt_link_status_cb link_status_cb)
{
    return -1;
}

#else
const char *uv_rawpkt_macosx_pcap_file = __FILE__;
#endif

