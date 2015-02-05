#include <stdlib.h>
#include <czmq.h>
#include "log.h"
#include "publish_session_breakdown.h"

/* Publish session breakdown callback */
void
publishSessionBreakdown (char *sessionBreakdown, void *pubSock) {
    if (pubSock ==NULL)
        return;
    
    zstr_send (pubSock, sessionBreakdown);
    LOGD ("\nSession breakdown:\n%s\n", sessionBreakdown);
}
