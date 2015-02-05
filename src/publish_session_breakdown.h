#ifndef __PUBLISH_SESSION_BREAKDOWN_H__
#define __PUBLISH_SESSION_BREAKDOWN_H__

/* Publish session breakdown callback definition */
typedef void (*publishSessionBreakdownCB) (char *sessionBreakdown, void *pubSock);

/*========================Interfaces definition============================*/
void
publishSessionBreakdown (char *sessionBreakdown, void *args);
/*=======================Interfaces definition end=========================*/

#endif /* __PUBLISH_SESSION_BREAKDOWN_H__ */
