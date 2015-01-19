#include <signal.h>
#include "util.h"
#include "signals.h"

/* Thread local SIGUSR1 signal interrupted flag */
static __thread boolean sigusr1InterruptedFlag = false;

static void
sigusr1Handler (int signo) {
    sigusr1InterruptedFlag = true;
}

boolean
sigusr1IsInterrupted (void) {
    return sigusr1InterruptedFlag;
}

void
resetSignalsFlag (void) {
    sigusr1InterruptedFlag = false;
}

void
setupSignals (void) {
    struct sigaction action;

    /* Setup SIGUSR1 signal */
    action.sa_handler = sigusr1Handler;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction (SIGUSR1, &action, NULL);
}
