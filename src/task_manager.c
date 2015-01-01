#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include "logger.h"
#include "hash.h"
#include "zmq_hub.h"
#include "task_manager.h"

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

    item->id = 0;
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
taskInterrupted (void) {
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

    tsk->id = tid;
    tsk->func = func;
    tsk->args = args;
    snprintf (key, sizeof (key) - 1, "%lu", tid);
    ret = hashInsert (taskManagerHashTable, key, tsk, freeTaskItemForHash);
    if (ret < 0) {
        pthread_kill (tid, SIGUSR1);
        return -1;
    }

    return tid;
}

static int
stopTaskForEachHashItem (void *data, void *args) {
    taskItemPtr tsk;

    tsk = (taskItemPtr) data;
    pthread_kill (tsk->id, SIGUSR1);

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
sendTaskStatus (const char *msg) {
    pthread_mutex_lock (&taskStatusPushSockLock);
    zstr_send (getTaskStatusPushSock (), msg);
    pthread_mutex_unlock (&taskStatusPushSockLock);
}

char *
recvTaskStatus (void) {
    pthread_mutex_lock (&taskStatusPullSockLock);
    return zstr_recv (getTaskStatusPullSock ());
    pthread_mutex_unlock (&taskStatusPullSockLock);
}

char *
recvTaskStatusNonBlock (void) {
    pthread_mutex_lock (&taskStatusPullSockLock);
    return zstr_recv_nowait (getTaskStatusPullSock ());
    pthread_mutex_unlock (&taskStatusPullSockLock);
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
