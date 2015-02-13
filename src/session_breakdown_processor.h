#ifndef __SESSION_BREAKDOWN_PROCESSOR_H__
#define __SESSION_BREAKDOWN_PROCESSOR_H__

/* Publish session breakdown callback definition */
typedef void (*publishSessionBreakdownCB) (char *sessionBreakdown, void *pubSock);

/*========================Interfaces definition============================*/
void
publishSessionBreakdown (char *sessionBreakdown, void *args);
/*=======================Interfaces definition end=========================*/

#endif /* __SESSION_BREAKDOWN_PROCESSOR_H__ */
