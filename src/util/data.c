#include <stdlib.h>
#include <string.h>
#include "data.h"

dataPtr
dataCreate (const u_char *d, u_int len) {
    dataPtr tmp;

    tmp = (dataPtr) malloc (sizeof (data));
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
dataAlloc (u_int len) {
    dataPtr tmp;

    tmp = (dataPtr) malloc (sizeof (data));
    if (tmp == NULL)
        return NULL;

    tmp->data = (u_char *) malloc (len);
    if (tmp->data == NULL) {
        free (tmp);
        return NULL;
    }

    return tmp;
}

int
dataMake (dataPtr dp, const u_char *d, u_int len) {
    dp->data = (u_char *) malloc (len);
    if (dp->data == NULL)
        return -1;

    memcpy (dp->data, d, len);
    dp->len = len;

    return 0;
}

void
dataDestroy (dataPtr *dpp) {
    dataPtr dp = *dpp;
    
    if ((dpp == NULL) || (dp == NULL))
        return;

    if (dp->data)
        free (dp->data);
    free (dp);
    dp = NULL;
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

    if (dp->data == NULL)
        return;
    memset (dp->data, 0, dp->len);
    free (dp->data);
    dp->data = NULL;
    dp->len = 0;
}

int
dataCompare (dataPtr d1p, dataPtr d2p) {
    if (d1p->len != d2p->len)
        return -1;
    return (memcmp (d1p->data, d2p->data, d1p->len));
}
