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
#include "analysis_record_service.h"

/* Analysis record output devices list */
static listHead analysisRecordOutputDevices;

typedef struct _analysisRecordOutputDev analysisRecordOutputDev;
typedef analysisRecordOutputDev *analysisRecordOutputDevPtr;
/*
 * Analysis record output dev, every dev has three interfaces, you can
 * add new analysis record output dev to analysisRecordOutputDevices
 * list with analysisRecordOutputDevAdd interface.
 */
struct _analysisRecordOutputDev {
    /* AnalysisRecord output dev private data */
    void *data;

    /* AnalysisRecord output dev init operation */
    int (*init) (analysisRecordOutputDevPtr dev);
    /* AnalysisRecord output dev destroy operation */
    void (*destroy) (analysisRecordOutputDevPtr dev);
    /* AnalysisRecord output dev write operation */
    void (*write) (void *analysisRecord, u_int len,
                   analysisRecordOutputDevPtr dev);
    /* AnalysisRecord output dev list node of global AnalysisRecord output devices */
    listHead node;
};

/*===========================AnalysisRecord output file dev===========================*/

typedef struct _analysisRecordOutputFile analysisRecordOutputFile;
typedef analysisRecordOutputFile *analysisRecordOutputFilePtr;

struct _analysisRecordOutputFile {
    FILE *file;                         /**< AnalysisRecord output file descriptor */
    char *filePath;                     /**< AnalysisRecord output file path */
};

static int
initAnalysisRecordOutputFile (analysisRecordOutputDevPtr dev) {
    analysisRecordOutputFilePtr outputFile
            = (analysisRecordOutputFilePtr) malloc (sizeof (analysisRecordOutputFile));
    if (outputFile == NULL) {
        LOGE ("Malloc analysisRecordOutputFile error.\n");
        return -1;
    }

    outputFile->filePath = strdup (getPropertiesOutputFile ());
    if (outputFile->filePath == NULL) {
        LOGE ("Strdup analysis record output file path error.\n");
        free (outputFile);
        return -1;
    }
    outputFile->file = fopen (outputFile->filePath, "w");
    if (outputFile->file == NULL) {
        LOGE ("Open analysis record output file error: %s.\n", strerror (errno));
        free (outputFile->filePath);
        free (outputFile);
        return -1;
    }

    dev->data = outputFile;
    return 0;
}

static void
destroyAnalysisRecordOutputFile (analysisRecordOutputDevPtr dev) {
    analysisRecordOutputFilePtr outputFile =
            (analysisRecordOutputFilePtr) dev->data;

    fclose (outputFile->file);
    outputFile->file = NULL;
    free (outputFile->filePath);
    outputFile->filePath = NULL;
    free (outputFile);
}

static int
resetAnalysisRecordOutputFile (analysisRecordOutputDevPtr dev) {
    destroyAnalysisRecordOutputFile (dev);
    return initAnalysisRecordOutputFile (dev);
}

static void
writeAnalysisRecordOutputFile (void *analysisRecord, u_int len,
                               analysisRecordOutputDevPtr dev) {
    int ret;
    analysisRecordOutputFilePtr outputFile;

    outputFile = (analysisRecordOutputFilePtr) dev->data;
    ret = fwrite (analysisRecord, len, 1, outputFile->file);
    if (ret != 1) {
        ret = resetAnalysisRecordOutputFile (dev);
        if (ret < 0)
            LOGE ("Reset analysis record output file error.\n");
        return;
    }

    ret = fputc ('\n', outputFile->file);
    if (ret != (int) '\n') {
        ret = resetAnalysisRecordOutputFile (dev);
        if (ret < 0)
            LOGE ("Reset analysis record output file error.\n");
        return;
    }
}

/*===========================AnalysisRecord output file dev===========================*/

/*============================AnalysisRecord output net dev===========================*/

typedef struct _analysisRecordOutputNet analysisRecordOutputNet;
typedef analysisRecordOutputNet *analysisRecordOutputNetPtr;

struct _analysisRecordOutputNet {
    void *pushSock;
};

static int
initAnalysisRecordOutputNet (analysisRecordOutputDevPtr dev) {
    analysisRecordOutputNetPtr outputNet =
            (analysisRecordOutputNetPtr) malloc (sizeof (analysisRecordOutputNet));
    if (outputNet == NULL) {
        LOGE ("Malloc analysisRecordOutputNet error.\n");
        return -1;
    }

    outputNet->pushSock = getAnalysisRecordPushSock ();

    dev->data = outputNet;
    return 0;
}

static void
destroyAnalysisRecordOutputNet (analysisRecordOutputDevPtr dev) {
    return;
}

static void
writeAnalysisRecordOutputNet (void *analysisRecord, u_int len,
                              analysisRecordOutputDevPtr dev) {
    int ret;
    analysisRecordOutputNetPtr outputNet;
    zframe_t *frame;

    outputNet = (analysisRecordOutputNetPtr) dev->data;

    frame = zframe_new (analysisRecord, len);
    if (frame == NULL) {
        LOGE ("Create analysis record zframe error.\n");
        return;
    }

    ret = zframe_send (&frame, outputNet->pushSock, 0);
    if (ret < 0)
        LOGE ("Send analysis record error.\n");
}

/*============================AnalysisRecord output net dev===========================*/

static int
analysisRecordOutputDevAdd (analysisRecordOutputDevPtr dev) {
    int ret;

    ret = dev->init (dev);
    if (ret < 0) {
        LOGE ("Init analysis record output dev error.\n");
        return -1;
    }

    listAdd (&dev->node, &analysisRecordOutputDevices);

    return 0;
}

static void
analysisRecordOutputDevDestroy (void) {
    analysisRecordOutputDevPtr entry;
    listHeadPtr pos, npos;

    listForEachEntrySafe (entry, pos, npos, &analysisRecordOutputDevices, node) {
        entry->destroy (entry);
        listDel (&entry->node);
    }
}

static void
analysisRecordOutputDevWrite (listHeadPtr analysisRecordOutputDevices,
                              void *analysisRecord, u_int len) {
    analysisRecordOutputDevPtr dev;
    listHeadPtr pos;

    listForEachEntry (dev, pos, analysisRecordOutputDevices, node) {
        dev->write (analysisRecord, len, dev);
    }
}

/* Analysis record service */
void *
analysisRecordService (void *args) {
    int ret;
    void *analysisRecordRecvSock;
    zframe_t *analysisRecord;
    u_long_long analysisRecordCount = 0;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    /* Display task schedule policy info */
    displayTaskSchedPolicyInfo ("AnalysisRecordService");

    /* Init analysis record output file dev */
    analysisRecordOutputDev analysisRecordOutputFileDev = {
        .data = NULL,
        .init = initAnalysisRecordOutputFile,
        .destroy = destroyAnalysisRecordOutputFile,
        .write = writeAnalysisRecordOutputFile,
    };

    /* Init analysis record output net dev */
    analysisRecordOutputDev analysisRecordOutputNetDev = {
        .data = NULL,
        .init = initAnalysisRecordOutputNet,
        .destroy = destroyAnalysisRecordOutputNet,
        .write = writeAnalysisRecordOutputNet,
    };

    initListHead (&analysisRecordOutputDevices);

    /* Add analysis record output file dev */
    if (getPropertiesOutputFile ()) {
        ret = analysisRecordOutputDevAdd (&analysisRecordOutputFileDev);
        if (ret < 0)
            goto destroyAnalysisRecordOutputDev;
    }

    /* Add analysis record output net dev */
    ret = analysisRecordOutputDevAdd (&analysisRecordOutputNetDev);
    if (ret < 0)
        goto destroyAnalysisRecordOutputDev;

    /* Get analysisRecordRecvSock */
    analysisRecordRecvSock = getAnalysisRecordRecvSock ();

    while (!taskShouldExit ()) {
        /* Receive analysis record */
        analysisRecord = zframe_recv (analysisRecordRecvSock);
        if (analysisRecord == NULL) {
            if (!taskShouldExit ())
                LOGE ("Receive analysis record zframe with fatal error.\n");
            break;
        }

        analysisRecordOutputDevWrite (&analysisRecordOutputDevices,
                                      zframe_data (analysisRecord),
                                      zframe_size (analysisRecord));
        analysisRecordCount++;
        zframe_destroy (&analysisRecord);
    }

    /* Display analysis record statistic info */
    LOGI ("AnalysisRecordCount: %llu\n", analysisRecordCount);

    LOGI ("AnalysisRecordService will exit ... .. .\n");
destroyAnalysisRecordOutputDev:
    analysisRecordOutputDevDestroy ();
    destroyLogContext ();
exit:
    if (!taskShouldExit ())
        sendTaskStatus (TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
