#ifndef __OWNERSHIP_OBSERVE_SERVICE_H__
#define __OWNERSHIP_OBSERVE_SERVICE_H__

/* Slave handle success response */
#define SLAVE_HANDLE_SUCCESS_RESPONSE "{\"code\":0, \"body\":{}}"
/* Slave handle error response */
#define SLAVE_HANDLE_ERROR_RESPONSE "{\"code\":1, \"error_message\":\"error\"}"

/*========================Interfaces definition============================*/
void *
ownershipObserveService (void *args);
/*=======================Interfaces definition end=========================*/

#endif /* __OWNERSHIP_OBSERVE_SERVICE_H__ */
