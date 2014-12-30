#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include "logger.h"
#include "hash.h"
#include "task_manager.h"

static hashTablePtr taskManagerHashTable = NULL;
static __thread boolean taskInterruptedFlag = false;

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
freeTaskItem (void *data) {
    free (data);
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
    ret = hashInsert (taskManagerHashTable, key, tsk, freeTaskItem);
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
