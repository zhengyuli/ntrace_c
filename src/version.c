#include <stdio.h>
#include "version.h"

int
getMajorVersion (void) {
    return AGENT_VERSION_MAJOR;
}

int
getMinorVersion (void) {
    return AGENT_VERSION_MINOR;
}

int
getRevisionVersion (void) {
    return AGENT_VERSION_REVISION;
}

char *
getVersionStr (void) {
    static char verStr [128] = {0};

    snprintf (verStr, sizeof (verStr) - 1, "%d.%d.%d",
              AGENT_VERSION_MAJOR,
              AGENT_VERSION_MINOR,
              AGENT_VERSION_REVISION);

    return verStr;
}
