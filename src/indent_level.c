#include "indent_level.h"

#define MAX_INDENT_LEVEL 5

static char *indentLevelArray [MAX_INDENT_LEVEL] = {
    "",
    "    ",
    "        ",
    "            ",
    "                "
};

char *
getIndentLevel (u_int level) {
    if (level > MAX_INDENT_LEVEL)
        level = MAX_INDENT_LEVEL;

    return indentLevelArray [level];
}
