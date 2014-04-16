#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main (int argc, char *argv[]) {
    char cmd[100];
    char buf[1024];
    FILE *fp;

    if (argc != 2)
        return -1;

    snprintf (cmd, sizeof (cmd), "ps -C %s|tr -s ' '|cut -d' ' -f2", argv [1]);
    if ((fp = popen (cmd, "r")) == NULL)
        return -1;
    while (fgets (buf, sizeof (buf), fp) != NULL)
        printf ("%s", buf);

    pclose (fp);
    return 0;
}
