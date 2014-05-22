#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <czmq.h>
#include "util.h"
#include "log.h"

static zctx_t *zmqHubCtx = NULL;

void *
zmqHubContext (void) {
    return zmqHubContext;
}

int
initZmqhub (void) {
    int ret;

    zmqHubCtx = zctx_new ();
    if (zmqHubCtx == NULL)
        ret = -1;
    zctx_set_linger (zmqHubCtx, 0);
    zctx_set_iothreads (zmqHubCtx, 5);

    return 0;
}

void
destroyZmqhub (void) {
    if (zmqHubCtx == NULL)
        return;
    
    zctx_destroy (&zmqHubCtx);
    zmqHubCtx = NULL;
}
