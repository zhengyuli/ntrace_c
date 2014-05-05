#include <stdlib.h>
#include <string.h>
#include "data.h"

dataPtr
dataCreate (const u_char *d, int len) {
    dataPtr tmp;

    tmp = malloc (sizeof (data));
    if (tmp == NULL)
        return NULL;
    tmp->data = (u_char *) malloc (len);
    if (tmp->data == NULL) {
        free (tmp);
        return NULL;
    }
    memcpy (tmp->data, d, len);
    tmp->len = len;

    return tmp;
}

dataPtr
dataAlloc (int len) {
    dataPtr tmp;

    tmp = calloc (sizeof (data), len);
    if (tmp == NULL)
        return NULL;
    tmp->data = malloc (len);
    if (tmp->data == NULL) {
        free (tmp);
        return NULL;
    }

    return tmp;
}

int
dataMake (dataPtr dp, const u_char *d, int len) {
    dp->data = (u_char *) malloc (len);
    if (dp->data == NULL)
        return -1;
    memcpy (dp->data, d, len);
    dp->len = len;

    return 0;
}

void
dataDestroy (dataPtr *dpp) {
    if ((dpp == NULL) || (*dpp == NULL))
        return;

    if ((*dpp)->data)
        free ((*dpp)->data);
    free ((*dpp));
    *dpp = NULL;
}

int
dataCopy (dataPtr dst, dataPtr src) {
    dst->data = (u_char *) malloc (src->len);
    if (dst->data == NULL)
        return -1;
    memcpy (dst->data, src->data, src->len);
    dst->len = src->len;

    return 0;
}

void
dataZfree (dataPtr dp) {
    if (dp == NULL)
        return;
    if (d->data == NULL)
        return;
    memset (dp->data, 0, d->len);
    free (d->data);
    d->len = 0;
}

int
dataCompare (dataPtr d1p, dataPtr d2p) {
    if (d1p->len != d2p->len)
        return -1;
    return (memcmp (d1p->data, d2p->data, d1p->len));
}
