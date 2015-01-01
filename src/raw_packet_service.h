#ifndef __AGENT_RAW_PACKET_SERVICE__
#define __AGENT_RAW_PACKET_SERVICE__

/*========================Interfaces definition============================*/
int
updateFilter (const char *filter);
void *
rawPktCaptureService (void *args);
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_RAW_PACKET_SERVICE__ */
