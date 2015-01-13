#include "uv.h"
#include "uv-rawpkt.h"
#include <stdio.h>

static void found_interface( uv_rawpkt_iter_t *iter, const char *name, const char *description );
static void removed_interface( uv_rawpkt_iter_t *iter, const char *name, const char *description );


static void found_interface( uv_rawpkt_iter_t *iter, const char *name, const char *description )
{
    printf( "Found: %s: %s\n", name, description );
}

static void removed_interface( uv_rawpkt_iter_t *iter, const char *name, const char *description )
{
    printf( "Removed: %s: %s\n", name, description );
}

int main()
{
    uv_loop_t *loop = uv_default_loop();
    uv_rawpkt_iter_t rawpkt_iter;
    uv_rawpkt_iter_init(loop,&rawpkt_iter);
    uv_rawpkt_iter_start( &rawpkt_iter, found_interface, removed_interface);
    uv_run( loop, UV_RUN_DEFAULT );
}
