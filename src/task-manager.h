#ifndef __AGENT_TASK_MANAGER_H__
#define __AGENT_TASK_MANAGER_H__

#include <sys/types.h>
#include <pthread.h>

typedef pthread_t taskId;
typedef void * (*taskFunc) (void *args);

typedef struct _taskItem taskItem;
typedef taskItem *taskItemPtr;

struct _taskItem {
    taskId id;
};

/*========================Interfaces definition============================*/
taskId
newTask (taskFunc func, void *args);
void
stopTask (taskId tid);
void
stopAllTask (void);
int
initTaskManager (void);
void
destroyTaskManager (void);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_TASK_MANAGER_H__ */
