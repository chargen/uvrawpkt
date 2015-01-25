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
        uv_timer_init(iter->loop,&node->link_status_timer);
        node->link_status_timer.data = (void *)node;
        uv_timer_start(
                    &node->link_status_timer,
                    uv__rawpkt_network_port_link_status_timer,
                    0,
                    1000);
#if defined(_WIN32)
        node->device_description = _strdup(device_description);
        node->device_name = _strdup(device_name);
#else
        node->device_description = strdup(device_description);
        node->device_name = strdup(device_name);
#endif
        memcpy( node->mac, mac, 6 );
        node->owner = iter;
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
        free(node);
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
