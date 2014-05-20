#include <sys/types.h>
#include <pthread.h>
#include "log.h"
#include "hash.h"
#include "task-manager.h"

static hashTablePtr taskManagerHashTable = NULL;

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

    snprintf (key, sizeof (key) - 1, "%d", tid);
    ret = hashInsert (taskManagerHashTable, key, tsk, freeTaskItem);
    if (ret < 0) {
        pthread_kill (tid, SIGINT);
        return -1;
    }

    return tid;
}

void
stopTask (taskId tid) {
    int ret;
    char key [32];

    pthread_kill (tid, SIGINT);
    snprintf (key, sizeof (key) - 1, "%d", tid);
    hashDel (taskManagerHashTable, key);
}

static int
stopTaskForEachHashItem (void *data, void *args) {
    taskItemPtr tsk;

    tsk = (taskItemPtr) data;
    pthread_kill (tsk->id, SIGINT);

    return 0;
}

void
stopAllTask (void) {
    hashForEachItemDo (taskManagerHashTable, stopTaskForEachHashItem, NULL);
    usleep (20000);
    hashClean (taskManagerHashTable);
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
