#include <stdio.h>
#include <string.h>
#include <hiredis/hiredis.h>

int main (int argc, char *argv[]) {
    int i;
    redisContext *ctxt;
    redisReply *reply;

    ctxt = redisConnect ((const char *) "127.0.0.1", 6379);
    if (!ctxt || ctxt->err) {
        if (!ctxt)
            printf ("Alloc redis context failed.\n");
        else
            printf ("Connect redis server failed: %s.\n", ctxt->errstr);

        redisFree (ctxt);
        return -1;
    }

    reply = (redisReply *) redisCommand (ctxt, "HGETALL wdm:collector_map");
    if (reply == NULL) {
        printf ("reply is NULL.\n");
        redisFree (ctxt);
    }

    switch (reply->type) {
        case REDIS_REPLY_ARRAY:
            printf ("type: REDIS_REPLY_ARRAY\n");
            for (i = 0; i < reply->elements; i++) {
                switch (reply->element [i]->type) {
                    case REDIS_REPLY_ARRAY:
                        printf ("type: REDIS_REPLY_ARRAY\n");
                        break;
                    case REDIS_REPLY_STRING:
                        printf ("type: REDIS_REPLY_STRING\n");
                        break;
                    case REDIS_REPLY_ERROR:
                        printf ("type: REDIS_REPLY_ERROR: %s\n", reply->str);
                        break;
                    default:
                        printf ("type: other\n");
                }
            }
            break;
        case REDIS_REPLY_STRING:
            printf ("type: REDIS_REPLY_STRING\n");
            break;
        case REDIS_REPLY_ERROR:
            printf ("type: REDIS_REPLY_ERROR: %s\n", reply->str);
            break;
        default:
            printf ("type: other\n");
    }

    freeReplyObject (reply);
    redisFree (ctxt);
    return 0;
}
