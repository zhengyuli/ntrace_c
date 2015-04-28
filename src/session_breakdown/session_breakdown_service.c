#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <czmq.h>
#include "list.h"
#include "util.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"
#include "session_breakdown_service.h"

/* Session breakdown output devices list */
static listHead sessionBreakdownOutputDevices;

typedef struct _sessionBreakdownOutputDev sessionBreakdownOutputDev;
typedef sessionBreakdownOutputDev *sessionBreakdownOutputDevPtr;
/*
 * Session breakdown output dev, every dev has three interfaces, you can
 * add new session breakdown output dev to sessionBreakdownOutputDevices
 * list with sessionBreakdownOutputDevAdd interface.
 */
struct _sessionBreakdownOutputDev {
    /* SessionBreakdown output dev private data */
    void *data;

    /* SessionBreakdown output dev init operation */
    int (*init) (sessionBreakdownOutputDevPtr dev);
    /* SessionBreakdown output dev destroy operation */
    void (*destroy) (sessionBreakdownOutputDevPtr dev);
    /* SessionBreakdown output dev write operation */
    void (*write) (void *sessionBreakdown, u_int len,
                   sessionBreakdownOutputDevPtr dev);
    /**< SessionBreakdown output dev list node of global SessionBreakdown output devices */
    listHead node;
};

/*===========================SessionBreakdown output file dev===========================*/

typedef struct _sessionBreakdownOutputFile sessionBreakdownOutputFile;
typedef sessionBreakdownOutputFile *sessionBreakdownOutputFilePtr;

struct _sessionBreakdownOutputFile {
    FILE *file;                         /**< SessionBreakdown output file descriptor */
    char *filePath;                     /**< SessionBreakdown output file path */
};

static int
initSessionBreakdownOutputFile (sessionBreakdownOutputDevPtr dev) {
    sessionBreakdownOutputFilePtr outputFile
            = (sessionBreakdownOutputFilePtr) malloc (sizeof (sessionBreakdownOutputFile));
    if (outputFile == NULL) {
        LOGE ("Malloc sessionBreakdownOutputFile error.\n");
        return -1;
    }

    outputFile->filePath = strdup (getPropertiesOutputFile ());
    if (outputFile->filePath == NULL) {
        LOGE ("Strdup session breakdown output file path error.\n");
        free (outputFile);
        return -1;
    }
    outputFile->file = fopen (outputFile->filePath, "w");
    if (outputFile->file == NULL) {
        LOGE ("Open session breakdown output file error: %s.\n", strerror (errno));
        free (outputFile->filePath);
        free (outputFile);
        return -1;
    }

    dev->data = outputFile;
    return 0;
}

static void
destroySessionBreakdownOutputFile (sessionBreakdownOutputDevPtr dev) {
    sessionBreakdownOutputFilePtr outputFile =
            (sessionBreakdownOutputFilePtr) dev->data;

    fclose (outputFile->file);
    outputFile->file = NULL;
    free (outputFile->filePath);
    outputFile->filePath = NULL;
    free (outputFile);
}

static int
resetSessionBreakdownOutputFile (sessionBreakdownOutputDevPtr dev) {
    destroySessionBreakdownOutputFile (dev);
    return initSessionBreakdownOutputFile (dev);
}

static void
writeSessionBreakdownOutputFile (void *sessionBreakdown, u_int len,
                                 sessionBreakdownOutputDevPtr dev) {
    int ret;
    sessionBreakdownOutputFilePtr outputFile;

    outputFile = (sessionBreakdownOutputFilePtr) dev->data;
    ret = fwrite (sessionBreakdown, len, 1, outputFile->file);
    if (ret != 1) {
        ret = resetSessionBreakdownOutputFile (dev);
        if (ret < 0)
            LOGE ("Reset session breakdown output file error.\n");
        return;
    }

    ret = fputc ('\n', outputFile->file);
    if (ret != (int) '\n') {
        ret = resetSessionBreakdownOutputFile (dev);
        if (ret < 0)
            LOGE ("Reset session breakdown output file error.\n");
        return;
    }
}

/*===========================SessionBreakdown output file dev===========================*/

/*============================SessionBreakdown output net dev===========================*/

typedef struct _sessionBreakdownOutputNet sessionBreakdownOutputNet;
typedef sessionBreakdownOutputNet *sessionBreakdownOutputNetPtr;

struct _sessionBreakdownOutputNet {
    void *pushSock;
};

static int
initSessionBreakdownOutputNet (sessionBreakdownOutputDevPtr dev) {
    sessionBreakdownOutputNetPtr outputNet =
            (sessionBreakdownOutputNetPtr) malloc (sizeof (sessionBreakdownOutputNet));
    if (outputNet == NULL) {
        LOGE ("Malloc sessionBreakdownOutputNet error.\n");
        return -1;
    }

    outputNet->pushSock = getSessionBreakdownPushSock ();

    dev->data = outputNet;
    return 0;
}

static void
destroySessionBreakdownOutputNet (sessionBreakdownOutputDevPtr dev) {
    return;
}

static void
writeSessionBreakdownOutputNet (void *sessionBreakdown, u_int len,
                                sessionBreakdownOutputDevPtr dev) {
    int ret;
    sessionBreakdownOutputNetPtr outputNet;
    zframe_t *frame;

    outputNet = (sessionBreakdownOutputNetPtr) dev->data;

    frame = zframe_new (sessionBreakdown, len);
    if (frame == NULL) {
        LOGE ("Create session breakdown zframe error.\n");
        return;
    }

    ret = zframe_send (&frame, outputNet->pushSock, 0);
    if (ret < 0) {
        LOGE ("Send session breakdown error.\n");
        if (frame)
            zframe_destroy (&frame);
    }
}

/*============================SessionBreakdown output net dev===========================*/

static int
sessionBreakdownOutputDevAdd (sessionBreakdownOutputDevPtr dev) {
    int ret;

    ret = dev->init (dev);
    if (ret < 0) {
        LOGE ("Init session breakdown output dev error.\n");
        return -1;
    }

    listAdd (&dev->node, &sessionBreakdownOutputDevices);

    return 0;
}

static void
sessionBreakdownOutputDevDestroy (void) {
    sessionBreakdownOutputDevPtr entry;
    listHeadPtr pos, npos;

    listForEachEntrySafe (entry, pos, npos, &sessionBreakdownOutputDevices, node) {
        entry->destroy (entry);
        listDel (&entry->node);
    }
}

static void
sessionBreakdownOutputDevWrite (listHeadPtr sessionBreakdownOutputDevices,
                                void *sessionBreakdown, u_int len) {
    sessionBreakdownOutputDevPtr dev;
    listHeadPtr pos;

    listForEachEntry (dev, pos, sessionBreakdownOutputDevices, node) {
        dev->write (sessionBreakdown, len, dev);
    }
}

/* Session breakdown service */
void *
sessionBreakdownService (void *args) {
    int ret;
    void *sessionBreakdownRecvSock;
    zframe_t *sessionBreakdown;
    u_long_long sessionBreakdownCount = 0;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Display task schedule policy info */
    displayTaskSchedPolicyInfo ("SessionBreakdownService");

    /* Init session breakdown output file dev */
    sessionBreakdownOutputDev sessionBreakdownOutputFileDev = {
        .data = NULL,
        .init = initSessionBreakdownOutputFile,
        .destroy = destroySessionBreakdownOutputFile,
        .write = writeSessionBreakdownOutputFile,
    };

    /* Init session breakdown output net dev */
    sessionBreakdownOutputDev sessionBreakdownOutputNetDev = {
        .data = NULL,
        .init = initSessionBreakdownOutputNet,
        .destroy = destroySessionBreakdownOutputNet,
        .write = writeSessionBreakdownOutputNet,
    };

    initListHead (&sessionBreakdownOutputDevices);

    /* Add session breakdown output file dev */
    if (getPropertiesOutputFile ()) {
        ret = sessionBreakdownOutputDevAdd (&sessionBreakdownOutputFileDev);
        if (ret < 0)
            goto destroySessionBreakdownOutputDev;
    }

    /* Add session breakdown output net dev */
    ret = sessionBreakdownOutputDevAdd (&sessionBreakdownOutputNetDev);
    if (ret < 0)
        goto destroySessionBreakdownOutputDev;

    /* Get sessionBreakdownRecvSock */
    sessionBreakdownRecvSock = getSessionBreakdownRecvSock ();

    while (!SIGUSR1IsInterrupted ()) {
        /* Receive session breakdown */
        sessionBreakdown = zframe_recv (sessionBreakdownRecvSock);
        if (sessionBreakdown == NULL) {
            if (!SIGUSR1IsInterrupted ())
                LOGE ("Receive session breakdown zframe with fatal error.\n");
            break;
        }

        sessionBreakdownOutputDevWrite (&sessionBreakdownOutputDevices,
                                        zframe_data (sessionBreakdown),
                                        zframe_size (sessionBreakdown));
        sessionBreakdownCount++;
        zframe_destroy (&sessionBreakdown);
    }

    /* Display session breakdown statistic info */
    LOGI ("SessionBreakdownCount: %llu\n", sessionBreakdownCount);

    LOGI ("SessionBreakdownService will exit ... .. .\n");
destroySessionBreakdownOutputDev:
    sessionBreakdownOutputDevDestroy ();
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus (TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
