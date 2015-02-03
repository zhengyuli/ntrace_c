#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <jansson.h>
#include "config.h"
#include "util.h"
#include "hash.h"
#include "log.h"
#include "proto_analyzer.h"

typedef struct _protoAnalyzerContext protoAnalyzerContext;
typedef protoAnalyzerContext *protoAnalyzerContextPtr;

struct _protoAnalyzerContext {
    void *handle;
    protoAnalyzerPtr analyzer;
};

/* Default builtin analyzer */
extern protoAnalyzer defaultAnalyzer;
extern protoAnalyzer httpAnalyzer;
extern protoAnalyzer mysqlAnalyzer;

static protoAnalyzerContext protoAnalyzerContextTable [1024];
static u_int registeredProtoSize = 0;

protoAnalyzerPtr
getProtoAnalyzer (char *proto) {
    int i;
    protoAnalyzerPtr analyzer;

    for (i = 0; i < registeredProtoSize; i++) {
        analyzer = protoAnalyzerContextTable [i].analyzer;
        if (strEqualIgnoreCase (analyzer->proto, proto))
            return analyzer;
    }

    return NULL;
}

static void
loadAnalyzers (void) {
    DIR *dir;
    struct dirent *entry;
    char filePath [256];
    void *handle;
    protoAnalyzerPtr analyzer;

    /* Load default builtin proto analyzer */
    protoAnalyzerContextTable [registeredProtoSize].handle = NULL;
    protoAnalyzerContextTable [registeredProtoSize].analyzer = &defaultAnalyzer;
    registeredProtoSize++;

    protoAnalyzerContextTable [registeredProtoSize].handle = NULL;
    protoAnalyzerContextTable [registeredProtoSize].analyzer = &httpAnalyzer;
    registeredProtoSize++;

    protoAnalyzerContextTable [registeredProtoSize].handle = NULL;
    protoAnalyzerContextTable [registeredProtoSize].analyzer = &mysqlAnalyzer;
    registeredProtoSize++;
    
    /* Load proto analyzers in AGENT_ANALYZER_DIR dynamically */
    dir = opendir (AGENT_ANALYZER_DIR);
    if (dir == NULL) {
        LOGE ("Opendir %s error: %s.\n", AGENT_ANALYZER_DIR, strerror (errno));
        return;
    }

    while ((entry = readdir (dir)) != NULL)
    {
        if (strstr (entry->d_name, ".so")) {
            snprintf (filePath, sizeof (filePath), "%s/%s", AGENT_ANALYZER_DIR, entry->d_name);
            handle = dlopen (filePath, RTLD_NOW|RTLD_GLOBAL);
            if (handle == NULL) {
                LOGE ("Open %s error: %s.\n", filePath, dlerror ());
                continue;
            }

            analyzer = (protoAnalyzerPtr) dlsym (handle, "analyzer");
            if (analyzer == NULL) {
                LOGE ("Load analyzer entry error: %s.\n", dlerror ());
                dlclose (handle);
                continue;
            }

            protoAnalyzerContextTable [registeredProtoSize].handle = handle;
            protoAnalyzerContextTable [registeredProtoSize].analyzer = analyzer;
            registeredProtoSize++;
            LOGI ("Load proto analyzer from %s successfully.\n", entry->d_name);
        }
    }

    closedir (dir);
}

int
initProtoAnalyzer (void) {
    int ret;
    u_int i, k;
    protoAnalyzerPtr analyzer;

    loadAnalyzers ();
    
    for (i = 0; i < registeredProtoSize; i++) {
        analyzer = protoAnalyzerContextTable [i].analyzer;
        if (analyzer->initProtoAnalyzer) {
            ret = (*analyzer->initProtoAnalyzer) ();
            if (ret < 0) {
                LOGE ("Init proto: %s error.\n", analyzer->proto);
                /* Destroy proto analyzers have been initialized */
                for (k = 0; k < i; k++) {
                    analyzer = protoAnalyzerContextTable [k].analyzer;
                    if (analyzer->destroyProtoAnalyzer)
                        (*analyzer->destroyProtoAnalyzer) ();
                }
                /* Destroy proto analyzer context table */
                for (k = 0; k < registeredProtoSize; k++) {
                    if (protoAnalyzerContextTable [k].handle)
                        dlclose (protoAnalyzerContextTable [k].handle);
                    protoAnalyzerContextTable [k].handle = NULL;
                    protoAnalyzerContextTable [k].analyzer = NULL;
                }
                registeredProtoSize = 0;
                return -1;
            }
        }
    }
    
    return 0;
}

void
destroyProtoAnalyzer (void) {
    u_int i;
    protoAnalyzerPtr analyzer;

    for (i = 0; i < registeredProtoSize; i++) {
        analyzer = protoAnalyzerContextTable [i].analyzer;
        if (analyzer->destroyProtoAnalyzer)
            (*analyzer->destroyProtoAnalyzer) ();
        if (protoAnalyzerContextTable [i].handle)
            dlclose (protoAnalyzerContextTable [i].handle);
        protoAnalyzerContextTable [i].handle = NULL;
        protoAnalyzerContextTable [i].analyzer = NULL;
    }
    registeredProtoSize = 0;
}
