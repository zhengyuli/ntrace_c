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

#define TASK_STATUS_MESSAGE_FORMAT_STRING "%u:%lu"
#define TASK_RESTART_MAX_RETRIES 3

/* Task manager hash table */
static hashTablePtr taskManagerHashTable = NULL;
/* Mutext lock for task status send/recv sock */
static pthread_mutex_t taskStatusSendSockLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t taskStatusRecvSockLock = PTHREAD_MUTEX_INITIALIZER;

static taskItemPtr
newTaskItem (void) {
    taskItemPtr item;

    item = (taskItemPtr) malloc (sizeof (taskItem));
    if (item == NULL)
        return NULL;

    item->tid = 0;
    item->routine = NULL;
    item->args = NULL;

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
newTask (taskRoutine routine, void *args) {
    int ret;
    taskItemPtr tsk;
    pthread_t tid;
    char key [64];

    tsk = newTaskItem ();
    if (tsk == NULL)
        return -1;

    ret = pthread_create (&tid, NULL, routine, args);
    if (ret < 0) {
        freeTaskItem (tsk);
        return -1;
    }

    tsk->tid = tid;
    tsk->routine = routine;
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
    taskItemPtr task;
    pthread_t newTid;
    char oldKey [64], newKey [64];

    snprintf (oldKey, sizeof (oldKey), "%lu", oldTid);
    task = hashLookup (taskManagerHashTable, oldKey);
    if (task == NULL)
        return -1;

    ret = pthread_create (&newTid, NULL, task->routine, task->args);
    if (ret < 0)
        return -1;

    snprintf (newKey, sizeof (newKey), "%lu", newTid);
    task->tid = newTid;
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
    pthread_join (tsk->tid, NULL);

    return True;
}

void
stopAllTask (void) {
    hashLoopCheckToRemove (taskManagerHashTable, stopTaskForEachHashItem, NULL);
    usleep (500000);
}

void
sendTaskStatus (taskStatus status) {
    int ret;
    u_int retries = 3;
    char statusMsg [128];

    snprintf (statusMsg, sizeof (statusMsg),
              TASK_STATUS_MESSAGE_FORMAT_STRING, status, pthread_self ());

    do {
        pthread_mutex_lock (&taskStatusSendSockLock);
        ret = zstr_send (getTaskStatusSendSock (), statusMsg);
        pthread_mutex_unlock (&taskStatusSendSockLock);
        retries -= 1;
    } while (ret < 0 && retries);

    if (ret < 0)
        LOGE ("Send task status error.\n");
}

int
taskStatusHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    int ret;
    u_int retries;
    char *taskStatusMsg;
    u_int taskStatus;
    pthread_t tid;

    pthread_mutex_lock (&taskStatusRecvSockLock);
    taskStatusMsg = zstr_recv_nowait (getTaskStatusRecvSock ());
    pthread_mutex_unlock (&taskStatusRecvSockLock);
    if (taskStatusMsg == NULL)
        return 0;

    sscanf (taskStatusMsg, TASK_STATUS_MESSAGE_FORMAT_STRING, &taskStatus, &tid);
    switch (taskStatus) {
        case TASK_STATUS_EXIT_NORMALLY:
            LOGI ("Task %lu exit normally.\n", tid);
            pthread_kill (pthread_self (), SIGINT);
            break;

        case TASK_STATUS_EXIT_ABNORMALLY:
            LOGE ("Task %lu exit abnormally.\n",  tid);
            retries = 1;
            while (retries <= TASK_RESTART_MAX_RETRIES) {
                LOGI ("Try to restart task with retries: %u\n", retries);
                ret = restartTask (tid);
                if (!ret)
                    break;

                retries++;
            }

            if (ret < 0) {
                LOGE ("Restart task failed.\n");
                ret = -1;
            } else {
                LOGI ("Restart task successfully.\n");
                ret = 0;
            }
            break;

        default:
            LOGE ("Unknown task status.\n");
            ret = 0;
            break;
    }

    free (taskStatusMsg);
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
