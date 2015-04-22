#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include "config.h"
#include "log.h"
#include "proto_detector.h"

typedef struct _protoDetectorContext protoDetectorContext;
typedef protoDetectorContext *protoDetectorContextPtr;

struct _protoDetectorContext {
    void *handle;
    protoDetectorPtr detector;
};

/* Default builtin detector */
extern protoDetector httpDetector;
extern protoDetector mysqlDetector;

static protoDetectorContext protoDetectorContextTable [MAX_PROTO_DETECTOR_NUM];
static u_int registeredDetectorSize = 0;

static void
loadDetectors (void) {
    DIR *dir;
    struct dirent *entry;
    char filePath [256];
    void *handle;
    protoDetectorPtr detector;

    protoDetectorContextTable [registeredDetectorSize].handle = NULL;
    protoDetectorContextTable [registeredDetectorSize].detector = &httpDetector;
    registeredDetectorSize++;

    protoDetectorContextTable [registeredDetectorSize].handle = NULL;
    protoDetectorContextTable [registeredDetectorSize].detector = &mysqlDetector;
    registeredDetectorSize++;

    /* Load proto detectors in AGENT_DETECTOR_DIR dynamically */
    dir = opendir (AGENT_DETECTOR_DIR);
    if (dir == NULL) {
        LOGE ("Opendir %s error: %s.\n", AGENT_DETECTOR_DIR, strerror (errno));
        return;
    }

    while ((entry = readdir (dir)) != NULL) {
        if (registeredDetectorSize >= MAX_PROTO_DETECTOR_NUM)
            break;

        if (strstr (entry->d_name, ".so")) {
            snprintf (filePath, sizeof (filePath), "%s/%s", AGENT_DETECTOR_DIR, entry->d_name);
            handle = dlopen (filePath, RTLD_NOW|RTLD_GLOBAL);
            if (handle == NULL) {
                LOGE ("Open %s error: %s.\n", filePath, dlerror ());
                continue;
            }

            detector = (protoDetectorPtr) dlsym (handle, "detector");
            if (detector == NULL) {
                LOGE ("Load detector entry error: %s.\n", dlerror ());
                dlclose (handle);
                continue;
            }

            protoDetectorContextTable [registeredDetectorSize].handle = handle;
            protoDetectorContextTable [registeredDetectorSize].detector = detector;
            registeredDetectorSize++;
            LOGI ("Load proto detector from %s successfully.\n", entry->d_name);
        }
    }

    closedir (dir);
}

char *
protoDetect (streamDirection direction, u_char *data, u_int dataLen) {
    u_int i;
    protoDetectorPtr detector;
    char *protoName;

    for (i = 0; i < registeredDetectorSize; i++) {
        detector = protoDetectorContextTable [i].detector;
        protoName = (*detector->sessionDetectProto) (direction, data, dataLen);
        if (protoName)
            return protoName;
    }

    return NULL;
}

int
initProtoDetector (void) {
    int ret;
    u_int i, k;
    protoDetectorPtr detector;

    loadDetectors ();

    for (i = 0; i < registeredDetectorSize; i++) {
        detector = protoDetectorContextTable [i].detector;

        if (detector->initProtoDetector) {
            ret = (*detector->initProtoDetector) ();
            if (ret < 0) {
                LOGE ("Init proto: %s error.\n", detector->proto);
                /* Destroy proto detectors have been initialized */
                for (k = 0; k < i; k++) {
                    detector = protoDetectorContextTable [k].detector;
                    if (detector->destroyProtoDetector)
                        (*detector->destroyProtoDetector) ();
                }
                /* Destroy proto detector context table */
                for (k = 0; k < registeredDetectorSize; k++) {
                    if (protoDetectorContextTable [k].handle)
                        dlclose (protoDetectorContextTable [k].handle);
                    protoDetectorContextTable [k].handle = NULL;
                    protoDetectorContextTable [k].detector = NULL;
                }
                registeredDetectorSize = 0;
                return -1;
            }
        }
    }

    LOGI ("Registered proto detectors:{\n");
    for (i = 0; i < registeredDetectorSize; i++)
        LOGI ("    %s\n", protoDetectorContextTable [i].detector->proto);
    LOGI ("}\n");

    return 0;
}

void
destroyProtoDetector (void) {
    u_int i;
    protoDetectorPtr detector;

    for (i = 0; i < registeredDetectorSize; i++) {
        detector = protoDetectorContextTable [i].detector;
        if (detector->destroyProtoDetector)
            (*detector->destroyProtoDetector) ();
        if (protoDetectorContextTable [i].handle)
            dlclose (protoDetectorContextTable [i].handle);
        protoDetectorContextTable [i].handle = NULL;
        protoDetectorContextTable [i].detector = NULL;
    }
    registeredDetectorSize = 0;
}
