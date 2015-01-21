#include <signal.h>
#include "util.h"
#include "signals.h"

/* Thread local SIGUSR1 signal interrupted flag */
static __thread boolean SIGUSR1InterruptedFlag = false;

static void
SIGUSR1Handler (int signo) {
    SIGUSR1InterruptedFlag = true;
}

boolean
SIGUSR1IsInterrupted (void) {
    return SIGUSR1InterruptedFlag;
}

void
resetSignalsFlag (void) {
    SIGUSR1InterruptedFlag = false;
}

void
setupSignals (void) {
    struct sigaction action;

    /* Setup SIGUSR1 signal */
    action.sa_handler = SIGUSR1Handler;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction (SIGUSR1, &action, NULL);
}
