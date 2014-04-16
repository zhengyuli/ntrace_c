#include <stdio.h>
#include <czmq.h>
#include "log.h"

int main(int argc, char *argv[]) {
    int ret;

    ret = initLog (NULL, LOG_INFO_LEVEL);
    if (ret < 0)
        return -1;

    while (!zctx_interrupted) {
        LOGE ("error\n");
        LOGW ("warning\n");
        LOGI ("info information\n");
        LOGD ("debug information\n");
        LOGD ("hello world\n");
        usleep (1000);
    }

    destroyLog ();
    return 0;
}
