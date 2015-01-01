#ifndef __AGENT_TASK_MANAGER_H__
#define __AGENT_TASK_MANAGER_H__

#include <sys/types.h>
#include <pthread.h>

#define TASK_STATUS_READY "Ready"
#define TASK_STATUS_EXIT "Exit"

typedef pthread_t taskId;
typedef void * (*taskFunc) (void *args);

typedef struct _taskItem taskItem;
typedef taskItem *taskItemPtr;

struct _taskItem {
    taskId id;
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
void
stopAllTask (void);
void
sendTaskStatus (const char *msg);
char *
recvTaskStatus (void);
char *
recvTaskStatusNonBlock (void);
int
initTaskManager (void);
void
destroyTaskManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_TASK_MANAGER_H__ */
