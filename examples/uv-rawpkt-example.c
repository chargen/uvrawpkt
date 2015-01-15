#include "uv.h"
#include "uv-rawpkt.h"
#include <stdio.h>

static void found_interface( uv_rawpkt_iter_t *iter, const char *name, const char *description, const uint8_t *mac );
static void removed_interface( uv_rawpkt_iter_t *iter, const char *name, const char *description, const uint8_t *mac );

struct port_context_s
{
    struct port_context_s *next;
    struct port_context_s *prev;
    uv_rawpkt_t rawpkt;
};
typedef struct port_context_s port_context_t;

port_context_t *portcontext_first = 0;
port_context_t *portcontext_last = 0;

static void received_packet( uv_rawpkt_t *rawpkt, ssize_t nread, const uv_buf_t *buf );

static void received_packet( uv_rawpkt_t *rawpkt, ssize_t nread, const uv_buf_t *buf )
{
    int bufnum=0;
    port_context_t *context = (port_context_t *)rawpkt->data;
    const uint8_t *mac = rawpkt->mac;
    printf("From: %02X:%02X:%02X:%02X:%02X:%02X :",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    for( bufnum=0; bufnum<nread; ++bufnum )
    {
        int i;
        uint8_t *p = (uint8_t *)buf[bufnum].base;

        for( i=0; i<buf[bufnum].len; ++i )
        {
            printf("%02X ",(uint16_t)p[i]);
        }
        printf( "\n" );
    }
    fflush(stdout);
}

static void found_interface( uv_rawpkt_iter_t *iter, const char *name, const char *description, const uint8_t *mac )
{
    port_context_t *context=0;

    printf( "Found  : %s: %s %02X:%02X:%02X:%02X:%02X:%02X\n", name, description, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
    fflush(stdout);

    {
        context=calloc(sizeof(port_context_t),1);
        if( context )
        {
            int status=-1;
            status = uv_rawpkt_init(uv_default_loop(),&context->rawpkt);
            context->rawpkt.data = (void *)context;

            if( status>=0 )
            {
                uint16_t ethertype=0x0800;
                status = uv_rawpkt_open(
                            &context->rawpkt,
                            name,
                            65536,
                            0,
                            10,
                            &ethertype,
                            mac
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

static void removed_interface( uv_rawpkt_iter_t *iter, const char *name, const char *description, const uint8_t *mac )
{
    port_context_t *cur = portcontext_first;
    printf( "Removed: %s: %s %02X:%02X:%02X:%02X:%02X:%02X\n", name, description, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
    fflush(stdout);

    while( cur )
    {
        if( memcmp( cur->rawpkt.mac, mac, 6 )==0 )
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

            uv_rawpkt_close(&cur->rawpkt,0);
            break;
        }
        cur = cur->next;
    }
}

int main()
{
    uv_loop_t *loop = uv_default_loop();
    uv_rawpkt_iter_t rawpkt_iter;
    uv_rawpkt_iter_init(loop,&rawpkt_iter);
    uv_rawpkt_iter_start( &rawpkt_iter,
                          found_interface,
                          removed_interface);
    uv_run( loop, UV_RUN_DEFAULT );
}
