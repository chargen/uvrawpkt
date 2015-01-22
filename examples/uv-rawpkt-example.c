#include "uv.h"
#include "uv-rawpkt.h"
#include <stdio.h>

static void found_interface(
        uv_rawpkt_network_port_iterator_t *iter,
        uv_rawpkt_network_port_t *port_info );

static void removed_interface(
        uv_rawpkt_network_port_iterator_t *iter,
        uv_rawpkt_network_port_t *port_info );

struct port_context_s
{
    struct port_context_s *next;
    struct port_context_s *prev;
    uv_rawpkt_t rawpkt;
};
typedef struct port_context_s port_context_t;

port_context_t *portcontext_first = 0;
port_context_t *portcontext_last = 0;

static void received_packet( uv_rawpkt_t *rawpkt,
                             ssize_t nread,
                             const uv_buf_t *buf );

static void rawpkt_closed( uv_handle_t *handle );


static void rawpkt_closed( uv_handle_t *handle )
{
    uv_rawpkt_t *rawpkt = (uv_rawpkt_t *)handle;

    printf( "Closed : %s\n", rawpkt->owner_network_port->device_name );
}

static void received_packet( uv_rawpkt_t *rawpkt,
                             ssize_t nread,
                             const uv_buf_t *buf )
{
    int bufnum=0;
    port_context_t *context = (port_context_t *)rawpkt->data;
    const uint8_t *mac = rawpkt->owner_network_port->mac;
    printf("From: %02X:%02X:%02X:%02X:%02X:%02X :",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    for( bufnum=0; bufnum<nread; ++bufnum )
    {
        size_t i;
        uint8_t *p = (uint8_t *)buf[bufnum].base;

        for( i=0; i<buf[bufnum].len; ++i )
        {
            printf("%02X ",(uint16_t)p[i]);
        }
        printf( "\n" );
    }
    fflush(stdout);
}

static void found_interface( uv_rawpkt_network_port_iterator_t *iter,
                             uv_rawpkt_network_port_t *network_port )
{
    port_context_t *context=0;

    printf( "Found  : %s: %s %02X:%02X:%02X:%02X:%02X:%02X\n",
            network_port->device_name,
            network_port->device_description,
            network_port->mac[0],
            network_port->mac[1],
            network_port->mac[2],
            network_port->mac[3],
            network_port->mac[4],
            network_port->mac[5] );
    fflush(stdout);

    {
        context=calloc(sizeof(port_context_t),1);
        if( context )
        {
            int status=-1;
            status = uv_rawpkt_init(iter->loop,&context->rawpkt);
            context->rawpkt.data = (void *)context;

            if( status>=0 )
            {
                uint16_t ethertype=0x0800;
                status = uv_rawpkt_open(
                            &context->rawpkt,
                            network_port,
                            128,
                            1,
                            1,
                            &ethertype,
                            rawpkt_closed
                            );
            }

            if( status>=0 )
            {
                uv_rawpkt_recv_start(
                            &context->rawpkt,
                            received_packet );
            }

            if( status>=0 )
            {
                if( portcontext_first == 0 )
                {
                    portcontext_first=context;
                    portcontext_last=context;
                }
                else
                {
                    context->next = 0;
                    context->prev = portcontext_last;
                    portcontext_last->next = context;
                    portcontext_last = context;
                }
            }

            if( status<0 )
            {
                free(context);
            }
        }
    }
}

static void removed_interface( uv_rawpkt_network_port_iterator_t *iter,
                               uv_rawpkt_network_port_t *port_info )
{
    port_context_t *cur = portcontext_first;

    printf( "Removed: %s: %s %02X:%02X:%02X:%02X:%02X:%02X\n",
            port_info->device_name,
            port_info->device_description,
            port_info->mac[0],
            port_info->mac[1],
            port_info->mac[2],
            port_info->mac[3],
            port_info->mac[4],
            port_info->mac[5] );
    fflush(stdout);

    while( cur )
    {
        if( memcmp( cur->rawpkt.owner_network_port->mac,
                    port_info->mac, 6 )==0 )
        {
            if( cur->prev )
            {
                cur->prev->next = cur->next;
            }
            if( cur->next )
            {
                cur->next->prev = cur->prev;
            }
            if( portcontext_first == cur )
            {
                portcontext_first = cur->next;
            }
            if( portcontext_last == cur )
            {
                portcontext_last = cur->prev;
            }

            uv_rawpkt_close(&cur->rawpkt);
            break;
        }
        cur = cur->next;
    }
}

void finish( uv_signal_t *handle, int sig )
{
    uv_rawpkt_network_port_iterator_t *network_port_iterator =
            (uv_rawpkt_network_port_iterator_t *)handle->data;
    uv_signal_stop(handle);
    uv_rawpkt_network_port_iterator_stop( network_port_iterator );
    uv_rawpkt_network_port_iterator_close( network_port_iterator, 0 );
}

int main()
{
    uv_loop_t *loop = uv_default_loop();
    uv_signal_t sigint_handle;
    uv_rawpkt_network_port_iterator_t rawpkt_iter;
    uv_rawpkt_network_port_iterator_init(loop,&rawpkt_iter);
    uv_rawpkt_network_port_iterator_start(
                &rawpkt_iter,
                found_interface,
                removed_interface);
    uv_signal_init(loop,&sigint_handle);
    sigint_handle.data = &rawpkt_iter;
    uv_signal_start(&sigint_handle,finish,SIGINT);
    uv_run( loop, UV_RUN_DEFAULT );
}
