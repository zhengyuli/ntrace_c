#ifndef __AGENT_DATA_H__
#define __AGENT_DATA_H__

typedef struct _data data;
typedef data *dataPtr;

struct _data {
    u_char *data;
    u_int len;
};

dataPtr
dataCreate (const u_char *d, u_int len);
dataPtr
dataAlloc (u_int len);
int
dataMake (dataPtr dp, const u_char *d, u_int len);
void
dataDestroy (dataPtr *dpp);
int
dataCopy (dataPtr dst, dataPtr src);
void
dataZfree (dataPtr dp);
int
dataCompare (dataPtr d1p, dataPtr d2p);

#define INIT_DATA(a, b, c) ({(a).data = (b); (a).len = (c)})
#define ATTACH_DATA(a, b) ({(a).data = (b); (a).len = sizeof (b)})
#define ZERO_DATA(a) ({(a).data = NULL; (a).len = 0})

#endif /* __AGENT_DATA_H__ */
