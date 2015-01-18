#include "uv.h"
#include "uv-rawpkt.h"

void uv__rawpkt_iter_clear_seen_network_port(
        uv_rawpkt_network_port_iterator_t* iter )
{
    uv_rawpkt_network_port_t *cur=iter->first;

    while( cur )
    {
        cur->seen=0;
        cur = cur->next;
    }

}

uv_rawpkt_network_port_t *uv__rawpkt_iter_add_network_port(
        uv_rawpkt_network_port_iterator_t* iter,
        const char *device_name,
        const char *device_description,
        const uint8_t *mac )
{
    uv_rawpkt_network_port_t *node = calloc(sizeof(uv_rawpkt_network_port_t),1);
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

void uv__rawpkt_iter_free_network_port(
        uv_rawpkt_network_port_iterator_t* iter,
        uv_rawpkt_network_port_t* node )
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


uv_rawpkt_network_port_t * uv__rawpkt_iter_find_network_port(
        uv_rawpkt_network_port_iterator_t* iter,
        const char *device_name )
{
    uv_rawpkt_network_port_t *result=0;
    uv_rawpkt_network_port_t *cur=iter->first;

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

int uv__rawpkt_network_port_add_rawpkt(uv_rawpkt_network_port_t *network_port,
                                       uv_rawpkt_t *rawpkt )
{
    if( network_port->first_rawpkt==0 )
    {
        network_port->first_rawpkt = rawpkt;
        network_port->last_rawpkt = rawpkt;
    }
    else
    {
        network_port->last_rawpkt->next = rawpkt;
        rawpkt->prev = network_port->last_rawpkt;
        network_port->last_rawpkt = rawpkt;
    }
    return 0;
}

int uv__rawpkt_network_port_remove_rawpkt(uv_rawpkt_network_port_t *node,
                                       uv_rawpkt_t *rawpkt )
{
    if( node->first_rawpkt == rawpkt )
    {
        node->first_rawpkt = rawpkt->next;
    }
    if( node->last_rawpkt == rawpkt )
    {
        node->last_rawpkt = rawpkt->prev;
    }
    if( rawpkt->prev )
    {
        rawpkt->prev->next = rawpkt->next;
    }
    if( rawpkt->next )
    {
        rawpkt->next->prev = rawpkt->prev;
    }
    return 0;
}
