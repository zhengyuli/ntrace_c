#ifndef __SIGNALS_H__
#define __SIGNALS_H__

#include "util.h"

/*========================Interfaces definition============================*/
boolean
SIGUSR1IsInterrupted (void);
void
resetSignalsFlag (void);
void
setupSignals (void);
/*=======================Interfaces definition end=========================*/

#endif /* __SIGNALS_H__ */
