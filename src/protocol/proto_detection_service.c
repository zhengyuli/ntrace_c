#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>
#include <libndpi-1.5.2/libndpi/ndpi_api.h>
#include "config.h"
#include "properties.h"
#include "signals.h"
#include "log.h"
#include "proto_detection_service.h"

#define DETECTION_TICK_RESOLUTION 1000

static struct ndpi_detection_module_struct *ndpiModule = NULL;
static u_int idStructSize = 0;
static u_int flowStructSize = 0;

static pcap_t * pcapDev = NULL;
static int datalinkType = -1;

static void *
mallocWrapper(unsigned long size) {
return malloc (size);
}

static void freeWrapper(void *freeable) {
    free (freeable);
}

static int
setupDetection (void) {
    NDPI_PROTOCOL_BITMASK protoBitmap;

    ndpiModule = ndpi_init_detection_module (
        DETECTION_TICK_RESOLUTION, mallocWrapper, freeWrapper, NULL);
    if (ndpiModule == NULL) {
        LOGE ("Init ndpi detection module error.\n");
        return -1;
    }

    NDPI_BITMASK_RESET (protoBitmap);
    NDPI_BITMASK_ADD (protoBitmap, NDPI_PROTOCOL_HTTP);
    NDPI_BITMASK_ADD (protoBitmap, NDPI_PROTOCOL_MYSQL);
    ndpi_set_protocol_detection_bitmask2 (ndpiModule, &protoBitmap);

    idStructSize = ndpi_detection_get_sizeof_ndpi_id_struct ();
    flowStructSize = ndpi_detection_get_sizeof_ndpi_flow_struct ();

    return 0;
}



/*
 * Proto detection service.
 */
void *
protoDetectionService (void *args) {
    int ret;

    /* Reset signals flag */
    resetSignalsFlag ();

    /* Init log context */
    ret = initLogContext (getPropertiesLogLevel ());
    if (ret < 0) {
        fprintf (stderr, "Init log context error.\n");
        goto exit;
    }

    LOGI ("ProtoDetectionService will exit ... .. .\n");
destroyLogContext:
    destroyLogContext ();
exit:
    if (!SIGUSR1IsInterrupted ())
        sendTaskStatus ("ProtoDetectionService", TASK_STATUS_EXIT_ABNORMALLY);

    return NULL;
}
