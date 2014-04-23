#include <json/json.h>
#include "util.h"
#include "hash.h"
#include "log.h"
#include "default-analyzer.h"
#include "http-analyzer.h"
#include "mysql-analyzer.h"
#include "protocol.h"

static protoInfo protoInfoTable [] = {
    {PROTO_DEFAULT, "DEFAULT", &defaultParser},
    {PROTO_HTTP, "HTTP", &httpParser},
    {PROTO_MYSQL, "MYSQL", &mysqlParser}
};

int
initProto (void) {
    int ret;
    int i;
    protoInfoPtr tmp;
    protoParserPtr parser;

    for (i = 0; i < TABLE_SIZE (protoInfoTable); i++) {
        parser = protoInfoTable [i].parser;
        ret = (*parser->initProto) ();
        if (ret < 0)
            return -1;
    }

    return 0;
}

void
destroyProto (void) {
    int ret;
    int i;
    protoInfoPtr tmp;
    protoParserPtr parser;

    for (i = 0; i < TABLE_SIZE (protoInfoTable); i++) {
        parser = protoInfoTable [i].parser;
        if (parser->destroyProto)
            (*parser->destroyProto) ();
    }
}

protoType
getProtoType (const char *protoName) {
    int i;
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
