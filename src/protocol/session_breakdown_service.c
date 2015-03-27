#include <stdlib.h>
#include <czmq.h>
#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "session_breakdown_service.h"

/* Session breakdown service */
void *
sessionBreakdownService (void *args) {
    int ret;
    void *sessionBreakdownRecvSock;
    void *sessionBreakdownPushSock;
    char *sessionBreakdown;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Get sessionBreakdownRecvSock */
    sessionBreakdownRecvSock = getSessionBreakdownRecvSock ();
    /* Get sessionBreakdownPushSock */
    sessionBreakdownPushSock = getSessionBreakdownPushSock ();

    while (!SIGUSR1IsInterrupted () && !zctx_interrupted) {
        /* Receive session breakdown */
        sessionBreakdown = zstr_recv (sessionBreakdownRecvSock);
        if (sessionBreakdown == NULL) {
            if (!SIGUSR1IsInterrupted ())
                LOGE ("Receive sessionBreakdown fatal error.\n");
            break;
        }

        zstr_send (sessionBreakdownPushSock, sessionBreakdown);
        
        LOGD ("\nSession breakdown:\n%s\n", sessionBreakdown);
        free (sessionBreakdown);
    }

    LOGI ("SessionBreakdownService will exit ... .. .\n");
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT);

    return NULL;
}
