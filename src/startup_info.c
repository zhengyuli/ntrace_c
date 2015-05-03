#include "log.h"
#include "startup_info.h"

#define NTRACE_STARTUP_LOGO                                              \
    "                                                                \n" \
    "==============================================================  \n" \
    "**                                                              \n" \
    "**                  _____                                       \n" \
    "**              _ _|_   _| __ __ _  ___ ___                     \n" \
    "**             | '_ \\| || '__/ _` |/ __/ _ \\                  \n" \
    "**             | | | | || | | (_| | (_|  __/                    \n" \
    "**             |_| |_|_||_|  \\__,_|\\___\\___|                 \n" \
    "**                                                              \n" \
    "**                                                              \n" \
    "**                                                              \n" \
    "**                             Copyright (C) zhengyu li, 2015   \n" \
    "**                                                              \n" \
    "**                             Author: zhengyu li               \n" \
    "**                             Email: lizhengyu419@gmail.com    \n" \
    "**                                                              \n" \
    "==============================================================  \n\n" \


void
displayNtraceStartupInfo (void) {
    LOGI ("%s", NTRACE_STARTUP_LOGO);
}
