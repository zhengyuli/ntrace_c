#include <stdlib.h>
#include <czmq.h>
#include "log.h"
#include "session_breakdown_processor.h"

/* Publish session breakdown callback */
void
publishSessionBreakdown (char *sessionBreakdown, void *pubSock) {
    int ret;
    u_int retries = 3;

    if (pubSock ==NULL)
        return;

    do {
        ret = zstr_send (pubSock, sessionBreakdown);
        retries -= 1;
    } while ((ret < 0) && retries);

    if (ret < 0)
        LOGE ("Send session breakdown error.\n");
    else
        LOGD ("\nSession breakdown:\n%s\n", sessionBreakdown);
}
