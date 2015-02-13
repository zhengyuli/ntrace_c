#include <stdlib.h>
#include <czmq.h>
#include "log.h"
#include "session_breakdown_processor.h"

/* Publish session breakdown callback */
void
publishSessionBreakdown (char *sessionBreakdown, void *pubSock) {
    if (pubSock ==NULL)
        return;
    
    zstr_send (pubSock, sessionBreakdown);
    LOGD ("\nSession breakdown:\n%s\n", sessionBreakdown);
}
