#include <stdlib.h>
#include <czmq.h>
#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "mining_service.h"

/* Session breakdown mining service */
void *
miningService (void *args) {
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

    while (!SIGUSR1IsInterrupted ()) {
        /* Receive session breakdown */
        sessionBreakdown = zstr_recv (sessionBreakdownRecvSock);
        if (sessionBreakdown == NULL) {
            if (!SIGUSR1IsInterrupted ())
                LOGE ("Receive sessionBreakdown fatal error.\n");
            break;
        }

        zstr_send (sessionBreakdownPushSock, sessionBreakdown);
        free (sessionBreakdown);
    }

    LOGI ("MiningService will exit ... .. .\n");
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus ("MiningService", TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
