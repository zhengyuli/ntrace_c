#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>
#include "util.h"
#include "hash.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"

#define TASK_RESTART_MAX_RETRIES 3

/* Task manager hash table */
static hashTablePtr taskManagerHashTable = NULL;
/* Mutext lock for task status push/pull sock */
static pthread_mutex_t taskStatusSendSockLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t taskStatusRecvSockLock = PTHREAD_MUTEX_INITIALIZER;

static taskItemPtr
newTaskItem (void) {
    taskItemPtr item;

    item = (taskItemPtr) malloc (sizeof (taskItem));
    if (item == NULL)
        return NULL;

    item->tid = 0;
    return item;
}

static void
freeTaskItem (taskItemPtr item) {
    free (item);
}

static void
freeTaskItemForHash (void *data) {
    freeTaskItem ((taskItemPtr) data);
}

int
newTask (taskFunc func, void *args) {
    int ret;
    taskItemPtr tsk;
    pthread_t tid;
    char key [32];

    tsk = newTaskItem ();
    if (tsk == NULL)
        return -1;

    ret = pthread_create (&tid, NULL, func, args);
    if (ret < 0) {
        freeTaskItem (tsk);
        return -1;
    }

    tsk->tid = tid;
    tsk->func = func;
    tsk->args = args;
    snprintf (key, sizeof (key), "%lu", tid);
    ret = hashInsert (taskManagerHashTable, key, tsk, freeTaskItemForHash);
    if (ret < 0) {
        pthread_kill (tid, SIGUSR1);
        return -1;
    }

    return 0;
}

static int
restartTask (pthread_t oldTid) {
    int ret;
    pthread_t newTid;
    char oldKey [32], newKey [32];
    taskItemPtr task;

    snprintf (oldKey, sizeof (oldKey), "%lu", oldTid);
    task = hashLookup (taskManagerHashTable, oldKey);
    if (task == NULL)
        return -1;

    ret = pthread_create (&newTid, NULL, task->func, task->args);
    if (ret < 0)
        return -1;

    task->tid = newTid;
    snprintf (newKey, sizeof (newKey), "%lu", newTid);
    ret = hashRename (taskManagerHashTable, oldKey, newKey);
    if (ret < 0) {
        pthread_kill (newTid, SIGUSR1);
        return -1;
    }

    return 0;
}

static boolean
stopTaskForEachHashItem (void *data, void *args) {
    taskItemPtr tsk;

    tsk = (taskItemPtr) data;
    pthread_kill (tsk->tid, SIGUSR1);

    return true;
}

void
stopAllTask (void) {
    hashForEachItemDelInCase (taskManagerHashTable, stopTaskForEachHashItem, NULL);
    /* Wait for all tasks exit completely */
    sleep (1);
}

void
sendTaskStatus (taskStatus status) {
    char exitMsg [128];

    snprintf (exitMsg, sizeof (exitMsg), "%u:%lu", status, pthread_self ());

    pthread_mutex_lock (&taskStatusSendSockLock);
    zstr_send (getTaskStatusSendSock (), exitMsg);
    pthread_mutex_unlock (&taskStatusSendSockLock);
}

int
taskStatusHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    int retries, ret;
    char *statusMsg;
    u_int status;
    pthread_t tid;

    pthread_mutex_lock (&taskStatusRecvSockLock);
    statusMsg = zstr_recv_nowait (getTaskStatusRecvSock ());
    pthread_mutex_unlock (&taskStatusRecvSockLock);
    if (statusMsg == NULL)
        return 0;

    sscanf (statusMsg, "%u:%lu", &status, &tid);
    switch (status) {
        case TASK_STATUS_EXIT:
            LOGD ("Task %lu exit abnormally.\n");
            retries = TASK_RESTART_MAX_RETRIES;
            while (retries) {
                ret = restartTask (tid);
                if (ret < 0) {
                    LOGE ("Try to restart task... .. .\n");
                    retries--;
                } else
                    break;
            }
            if (ret < 0) {
                LOGE ("Restart task failed.\n");
                ret = -1;
            } else {
                LOGD ("Restart task successfully.\n");
                ret = 0;
            }
            break;

        default:
            LOGE ("Unknown task status.\n");
            ret = 0;
            break;
    }

    free (statusMsg);
    return ret;
}

int
initTaskManager (void) {
    taskManagerHashTable = hashNew (0);
    if (taskManagerHashTable == NULL) {
        LOGE ("Create taskManagerHashTable error.\n");
        return -1;
    }

    return 0;
}

void
destroyTaskManager (void) {
    hashDestroy (taskManagerHashTable);
    taskManagerHashTable = NULL;
}
