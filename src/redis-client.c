#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <hiredis/hiredis.h>
#include <jansson.h>
#include "util.h"
#include "atomic.h"
#include "hash.h"
#include "log.h"
#include "service.h"
#include "redis-client.h"

/* Redis context for per-thread */
static __thread redisCtxtPtr rdsContext = NULL;

#ifndef NDEBUG
static u_int breakdownCount = 0;
#endif

static int
connectRedisServer (void);

/* Init registered services */
int
initServiceFromRedis (void) {
    int ret;
    u_int index;
    redisReply *reply;
    servicePtr svc;

    if ((rdsContext == NULL) || (rdsContext->ctxt == NULL))
        return -1;

    reply = (redisReply *) redisCommand (rdsContext->ctxt,
                                         "HGETALL wdm:service_map:agent_%d",
                                         rdsContext->agentId);
    if (reply == NULL) {
        LOGE ("%s\n", rdsContext->ctxt->errstr);
        return -1;
    }

    if (reply->type == REDIS_REPLY_ARRAY) {
        for (index = 0; (index + 1) < reply->elements; index += 2) {
            svc = json2Service (reply->element [index + 1]->str);
            if (svc == NULL) {
                freeReplyObject (reply);
                return -1;
            }

            ret = updateService (SVC_UPDATE_ADD, svc);
            if (ret < 0) {
                freeReplyObject (reply);
                return -1;
            }
        }
        freeReplyObject (reply);
        return 0;
    } else {
        freeReplyObject (reply);
        return -1;
    }
}

/*
 * @brief Service update callback registration function
 *
 * @param callbackFun callback function for service update
 */
void
serviceUpdateSub (svcUpdateCallback callbackFun) {
    redisReply *reply;
    char *key, *value;
    svcUpdateType updateType;
    servicePtr svc;

    reply = (redisReply *) redisCommand (rdsContext->ctxt,
                                         "PSUBSCRIBE wdm:pubsub_service_*:agent_%d",
                                         rdsContext->agentId);
    if (reply == NULL) {
        LOGE ("Redis error: %s\n", rdsContext->ctxt->errstr);
        return;
    }
    freeReplyObject (reply);

    while (redisGetReply (rdsContext->ctxt, (void **) &reply) == REDIS_OK) {
        key = reply->element [2]->str;
        value = reply->element [3]->str;

        if (STRPREFIX (key, "wdm:pubsub_service_add:agent_"))
            updateType = SVC_UPDATE_ADD;
        else if (STRPREFIX (key, "wdm:pubsub_service_update:agent_"))
            updateType = SVC_UPDATE_MOD;
        else if (STRPREFIX (key, "wdm:pubsub_service_delete:agent_"))
            updateType = SVC_UPDATE_DEL;
        else {
            LOGE ("Wrong service update.\n");
            continue;
        }

        svc = json2Service (value);
        if (svc)
            callbackFun (updateType, svc);
        else
            LOGE ("Service update error.\n");
        freeReplyObject (reply);
    }
}

/*
 * @brief Push session breakdown to redis server
 *
 * @param sessionBreakdownJson session breakdown to push
 */
void
pushSessionBreakdown (const char *sessionBreakdownJson) {
    BOOL retried = FALSE;
    redisReply *reply;

retry:
    reply = (redisReply *) redisCommand (rdsContext->ctxt, "RPUSH wdm:list_session_breakdown:agent_%d %s",
                                         rdsContext->agentId, sessionBreakdownJson);
    if (reply == NULL) {
        if ((rdsContext->ctxt->err == REDIS_ERR_EOF) && !retried) {
            LOGD ("Redis server closed the connection, reconnect again.\n");
            /* Free old redis context */
            redisFree (rdsContext->ctxt);
            rdsContext->ctxt = NULL;
            if (connectRedisServer () < 0)
                return;
            retried = TRUE;
            goto retry;
        } else
            LOGE ("Redis error: %s\n", rdsContext->ctxt->errstr);
    } else {
#ifndef NDEBUG
        LOGD ("Tcp session breakdown------------count: %u\n%s\n",
              ATOMIC_FETCH_AND_ADD (&breakdownCount, 1), sessionBreakdownJson);
#endif
        freeReplyObject (reply);
    }
}

/*
 * Publish pcap statistic json data to redis server
 *
 * @param json pcap statistic json data
 */
void
pubPcapStat (const char *pstatJson) {
    BOOL retried = FALSE;
    redisReply *reply;

retry:
    reply = (redisReply *) redisCommand (rdsContext->ctxt,
                                         "SET wdm:pcap_stat:agent_%d %s",
                                         rdsContext->agentId, pstatJson);
    if (reply == NULL) {
        if ((rdsContext->ctxt->err == REDIS_ERR_EOF) && !retried) {
            LOGD ("Redis server closed the connection, reconnect again.\n");
            /* Free old redis context */
            redisFree (rdsContext->ctxt);
            rdsContext->ctxt = NULL;
            if (connectRedisServer () < 0)
                return;
            retried = TRUE;
            goto retry;
        } else
            LOGE ("Redis error: %s\n", rdsContext->ctxt->errstr);
    } else
        freeReplyObject (reply);
}

static redisCtxtPtr
newRedisCtxt (void) {
    redisCtxtPtr context;

    context = (redisCtxtPtr) malloc (sizeof (redisCtxt));
    if (context) {
        context->agentId = 0;
        context->redisIp = NULL;
        context->redisPort = 0;
        context->ctxt = NULL;
        return context;
    } else
        return NULL;
}

static int
connectRedisServer (void) {
    /* Redis connect timeout */
    struct timeval timeout = {2, 0};

    rdsContext->ctxt = redisConnectWithTimeout (rdsContext->redisIp, rdsContext->redisPort, timeout);
    if ((rdsContext->ctxt == NULL) || (rdsContext->ctxt)->err) {
        if ((rdsContext->ctxt)->err)
            LOGE ("Connect redis server error: %s.\n", (rdsContext->ctxt)->errstr);
        return -1;
    }

    return 0;
}

/* Check agent id is valid or not */
static BOOL
agentIDIsValid (void) {
    u_int index;
    redisReply *reply;
    json_error_t error;
    json_t *root, *tmp;

    reply = (redisReply *) redisCommand (rdsContext->ctxt, "HGETALL wdm:agent_map");
    if (reply == NULL) {
        LOGE ("Redis error: %s\n", (rdsContext->ctxt)->errstr);
        return FALSE;
    }

    if (reply->type == REDIS_REPLY_ARRAY) {
        for (index = 0; (index + 1) < reply->elements; index += 2) {
            root = json_loads (reply->element [index + 1]->str, JSON_DISABLE_EOF_CHECK, &error);
            if (root == NULL) {
                LOGE ("Json parse error: %s.\n", error.text);
                continue;
            }
            tmp = json_object_get (root, "agent_id");
            if (tmp) {
                if (rdsContext->agentId == json_integer_value (tmp))
                    return TRUE;
            }
        }
        return FALSE;
    } else
        return FALSE;
}

/*
 * @brief Init redis context.
 *
 * @param agentId agent id
 * @param redisIp redis ip
 * @param redisPort redis port
 *
 * @return 0 if success else -1
 */
int
initRedisContext (u_int agentId, const char *redisIp, u_short redisPort) {
    int ret;

    rdsContext = newRedisCtxt ();
    if (rdsContext == NULL) {
        LOGE ("Alloc redisCtxt error.\n");
        return -1;
    }

    rdsContext->agentId = agentId;
    rdsContext->redisIp = strdup (redisIp);
    if (rdsContext->redisIp == NULL) {
        LOGE ("Strdup redisIp error: %s\n", strerror (errno));
        free (rdsContext);
        rdsContext = NULL;
        return -1;
    }
    rdsContext->redisPort = redisPort;

    ret = connectRedisServer ();
    if (ret < 0) {
        free (rdsContext->redisIp);
        rdsContext->redisIp = NULL;
        if (rdsContext->ctxt) {
            redisFree (rdsContext->ctxt);
            rdsContext->ctxt = NULL;
        }
        free (rdsContext);
        rdsContext = NULL;
        return -1;
    }

    if (!agentIDIsValid ()) {
        LOGE ("Agent %d has not been registered.\n", rdsContext->agentId);
        free (rdsContext->redisIp);
        rdsContext->redisIp = NULL;
        redisFree (rdsContext->ctxt);
        rdsContext->ctxt = NULL;
        free (rdsContext);
        rdsContext = NULL;
        return -1;
    }

    return 0;
}

/* Destroy redis context */
void
destroyRedisContext (void) {
    free (rdsContext->redisIp);
    rdsContext->redisIp = NULL;
    redisFree (rdsContext->ctxt);
    rdsContext->ctxt = NULL;
    free (rdsContext);
    rdsContext = NULL;
}
