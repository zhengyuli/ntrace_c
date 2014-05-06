#include <jansson.h>
#include "util.h"
#include "hash.h"
#include "log.h"
#include "protocol.h"

/* Protocol parser definitions */
extern protoParser defaultParser;
extern protoParser httpParser;
extern protoParser mysqlParser;

static protoInfo protoInfoTable [] = {
    {PROTO_DEFAULT, "DEFAULT", &defaultParser},
    {PROTO_HTTP, "HTTP", &httpParser},
    {PROTO_MYSQL, "MYSQL", &mysqlParser}
};

protoType
getProtoType (const char *protoName) {
    u_int i;
    protoInfoPtr tmp;

    for (i = 0; i < TABLE_SIZE (protoInfoTable); i++) {
        tmp = &protoInfoTable [i];
        if (strEqualIgnoreCase (tmp->name, protoName))
            return tmp->proto;
    }

    return PROTO_UNKNOWN;
}

const char *
getProtoName (protoType proto) {
    protoInfoPtr tmp;

    if (proto >= PROTO_UNKNOWN)
        return NULL;

    tmp = &protoInfoTable [proto];
    return (const char *) tmp->name;
}

protoParserPtr
getProtoParser (protoType proto) {
    protoInfoPtr tmp;

    if (proto >= PROTO_UNKNOWN)
        return NULL;

    tmp = &protoInfoTable [proto];
    return tmp->parser;
}

int
initProto (void) {
    int ret;
    u_int i;
    protoParserPtr parser;

    for (i = 0; i < TABLE_SIZE (protoInfoTable); i++) {
        parser = protoInfoTable [i].parser;
        ret = (*parser->initProto) ();
        if (ret < 0) {
            LOGE ("Init proto: %s error.\n", protoInfoTable [i].name);
            return -1;
        }
    }

    return 0;
}

void
destroyProto (void) {
    u_int i;
    protoParserPtr parser;

    for (i = 0; i < TABLE_SIZE (protoInfoTable); i++) {
        parser = protoInfoTable [i].parser;
        if (parser->destroyProto)
            (*parser->destroyProto) ();
    }
}
