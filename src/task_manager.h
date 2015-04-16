#ifndef __TASK_MANAGER_H__
#define __TASK_MANAGER_H__

#include <pthread.h>
#include <czmq.h>
#include "util.h"

typedef void * (*taskRoutine) (void *args);

typedef enum {
    TASK_STATUS_READY,
    TASK_STATUS_EXIT_NORMALLY,
    TASK_STATUS_EXIT_ABNORMALLY
} taskStatus;

typedef struct _taskItem taskItem;
typedef taskItem *taskItemPtr;

struct _taskItem {
    pthread_t tid;                      /**< Task thread id */
    taskRoutine routine;                /**< Task routine */
    void *args;                         /**< Task routine arguments */
};

/*========================Interfaces definition============================*/
int
newTask (taskRoutine routine, void *args);
void
stopAllTask (void);
void
sendTaskStatus (taskStatus status);
int
taskStatusHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg);
int
initTaskManager (void);
void
destroyTaskManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __TASK_MANAGER_H__ */
