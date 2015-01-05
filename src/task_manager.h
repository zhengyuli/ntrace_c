#ifndef __AGENT_TASK_MANAGER_H__
#define __AGENT_TASK_MANAGER_H__

#include <sys/types.h>
#include <pthread.h>

typedef pthread_t taskId;
typedef void * (*taskFunc) (void *args);

typedef enum {
    TASK_STATUS_READY,
    TASK_STATUS_EXIT
} taskStatus;

typedef struct _taskItem taskItem;
typedef taskItem *taskItemPtr;

struct _taskItem {
    taskId tid;
    taskFunc func;
    void *args;
};

/*========================Interfaces definition============================*/
boolean
taskInterrupted (void);
void
resetTaskInterruptFlag (void);
taskId
newTask (taskFunc func, void *args);
taskId
restartTask (taskId tid);
void
stopAllTask (void);
void
sendTaskExit (void);
int
taskStatusHandler (zloop_t *loop, zmq_pollitem_t *item, void *arg);
int
initTaskManager (void);
void
destroyTaskManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_TASK_MANAGER_H__ */
