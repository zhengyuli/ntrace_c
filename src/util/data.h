#ifndef __WDM_AGENT_DATA_H__
#define __WDM_AGENT_DATA_H__

typedef struct _data data;
typedef data *dataPtr;

struct _data {
    u_char *data;
    int len;
};

dataPtr
dataCreate (u_char *d, int len);
dataPtr
dataAlloc (int len);
int
dataMake (dataPtr dp, u_char *d, int len);
void
dataDestroy (dataPtr *dpp);
int
dataCopy (dataPtr dst, dataPtr src);
void
dataZfree (dataPtr dp);
int
dataCompare (dataPtr d1p, dataPtr d2p);

#define INIT_DATA(a, b, c) ({(a).data = b; (a).len = c})
#define ATTACH_DATA(a, b) ({(a).data = b; (a).len = sizeof (b)})
#define ZERO_DATA(a) ({(a).data = 0; (a).len = 0})

#endif /* __WDM_AGENT_DATA_H__ */
