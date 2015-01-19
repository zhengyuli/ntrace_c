#ifndef __TASK_MANAGER_H__
#define __TASK_MANAGER_H__

#include <sys/types.h>
#include <pthread.h>
#include <czmq.h>
#include "util.h"

typedef void * (*taskFunc) (void *args);

typedef enum {
    TASK_STATUS_READY,
    TASK_STATUS_EXIT
} taskStatus;

typedef struct _taskItem taskItem;
typedef taskItem *taskItemPtr;

struct _taskItem {
    pthread_t tid;                      /**< Task thread id */
    taskFunc func;                      /**< Task function */
    void *args;                         /**< Task function arguments */
};

/*========================Interfaces definition============================*/
int
newTask (taskFunc func, void *args);
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
