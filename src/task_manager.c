#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include "util.h"
#include "hash.h"
#include "log.h"
#include "zmq_hub.h"
#include "task_manager.h"

#define TASK_RESTART_MAX_RETRIES 3

/* Task manager hash table */
static hashTablePtr taskManagerHashTable = NULL;
/* Thread local task interrupted flag */
static __thread boolean taskInterruptedFlag = false;
/* Mutext lock for task status push/pull sock */
static pthread_mutex_t taskStatusPushSockLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t taskStatusPullSockLock = PTHREAD_MUTEX_INITIALIZER;

static void
taskSigHandler (int signo) {
    if (signo == SIGUSR1)
        taskInterruptedFlag = true;
}

static void
setupTaskSignal (void) {
    struct sigaction action;

    /* Setup task SIGUSR1 handler */
    action.sa_handler = taskSigHandler;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction (SIGUSR1, &action, NULL);
}

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

boolean
taskIsInterrupted (void) {
    return taskInterruptedFlag;
}

void
resetTaskInterruptFlag (void) {
    taskInterruptedFlag = false;
}

taskId
newTask (taskFunc func, void *args) {
    int ret;
    taskItemPtr tsk;
    taskId tid;
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

    return tid;
}

taskId
restartTask (taskId tid) {
    int ret;
    taskId newTid;
    char key [32];
    taskItemPtr task;

    snprintf (key, sizeof (key), "%lu", tid);
    task = hashLookup (taskManagerHashTable, key);
    if (task == NULL) {
        LOGE ("Lookup task: %lu context error.\n", tid);
        return -1;
    }

    ret = pthread_create (&newTid, NULL, task->func, task->args);
    if (ret < 0) {
        LOGE ("Create new thread error.\n");
        return -1;
    }
    task->tid = newTid;

    return newTid;
}

static int
stopTaskForEachHashItem (void *data, void *args) {
    taskItemPtr tsk;

    tsk = (taskItemPtr) data;
    pthread_kill (tsk->tid, SIGUSR1);

    return 0;
}

void
stopAllTask (void) {
    hashForEachItemDo (taskManagerHashTable, stopTaskForEachHashItem, NULL);
    hashClean (taskManagerHashTable);
    /* Wait for all tasks exit completely */
    sleep (1);
}

void
sendTaskExit (void) {
    char exitMsg [128];

    snprintf (exitMsg, sizeof (exitMsg), "%u:%u", TASK_STATUS_EXIT, gettid ());

    pthread_mutex_lock (&taskStatusPushSockLock);
    zstr_send (getTaskStatusPushSock (), exitMsg);
    pthread_mutex_unlock (&taskStatusPushSockLock);
}

static char *
recvTaskStatusNonBlock (void) {
    pthread_mutex_lock (&taskStatusPullSockLock);
    return zstr_recv_nowait (getTaskStatusPullSock ());
    pthread_mutex_unlock (&taskStatusPullSockLock);
}

int
taskStatusHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg) {
    int retries, ret;
    char *statusMsg;
    u_int status;
    taskId tid;

    statusMsg = recvTaskStatusNonBlock ();
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
    setupTaskSignal ();
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
