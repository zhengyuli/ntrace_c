#ifndef __AGENT_SSL_ANALYZER_H__
#define __AGENT_SSL_ANALYZER_H__

#include <openssl/evp.h>
#include "util.h"
#include "hash.h"
#include "data.h"
#incldue "ssl_ciphersuites.h"

typedef struct _sslRecDecoder sslRecDecoder;
typedef sslRecDecoder *sslRecDecoderPtr;

struct _sslRecDecoder {
    sslCipherSuitePtr cs;
    dataPtr macKey;
    EVP_CIPHER_CTX *evp;
    u_int seq;
};

typedef struct _sslDecodeCtx sslDecodeCtx;
typedef sslDecodeCtx *sslDecodeCtxPtr;

struct _sslDecodeCtx {
    SSL_CTX *sslCtx;
    SSL *ssl;
    hashTablePtr sessionCache;
};

typedef struct _sslDecoder sslDecoder;
typedef sslDecoder *sslDecoderPtr;

struct _sslDecoder {
    dataPtr sessionId;
    sslDecodeCtxPtr ctx;
    sslCipherSuitePtr cs;
    dataPtr clientRandom;
    dataPtr serverRandom;
    int ephemeralRsa;
    dataPtr PMS;
    dataPtr MS;
    sslRecDecoderPtr c2sDecoder;
    sslRecDecoderPtr c2sDecoderN;
    sslRecDecoderPtr s2cDecoder;
    sslRecDecoderPtr s2cDecoderN;
};

typedef struct _sslObject sslObject;
typedef sslObject *sslObjectPtr;

struct _sslObject {
    int version;
    int cipherSuite;
    sslCipherSuitePtr cs;

    int cliState;
    int srvState;

    struct in_addr cliIp;
    uint16_t cliPort;
    struct in_addr srvIp;
    uint16_t srvPort;

    sslDecodeCtxPtr sslDecCtx;
    sslDecoderPtr decoder;

    u_char *cliRcvBuf;
    int cliRcvBufSize;
    int cliRcvOffset;
    int cliRcvCount;

    u_char *srvRcvBuf;
    int srvRcvBufSize;
    int srvRcvOffset;
    int srvRcvCount;
};

#define SSL_HEADER_SIZE 5

/* SSL error code */
#define SSL_NO_DATA           1
#define SSL_BAD_RECORD_LEN    2
#define SSL_BAD_CONTENT_TYPE  3
#define SSL_BAD_PMS           4
#define SSL_CANT_DO_CIPHER    5
#define SSL_NO_DECRYPT        6
#define SSL_BAD_MAC           7
#define SSL_BAD_DATA          8

/* SSL state */
#define SSL_ST_SENT_NOTHING             0
#define SSL_ST_HANDSHAKE                1
#define SSL_ST_SENT_CHANGE_CIPHER_SPEC  2

/* SSL handshake type */
#define SSL_HANDSHAKE_HELLO_REQUEST        0x00
#define SSL_HANDSHAKE_CLIENT_HELLO         0x01
#define SSL_HANDSHAKE_SERVER_HELLO         0x02
#define SSL_HANDSHAKE_CERTIFICATE          0x0b
#define SSL_HANDSHAKE_SERVER_KEY_EXCHANGE  0x0c
#define SSL_HANDSHAKE_CERTIFICATE_REQUEST  0x0d
#define SSL_HANDSHAKE_SERVER_HELLO_DONE    0x0e
#define SSL_HANDSHAKE_CERTIFICATE_VERIFY   0x0f
#define SSL_HANDSHAKE_CLIENT_KEY_EXCHANGE  0x10
#define SSL_HANDSHAKE_FINISHED             0x14

/* SSL record type */
#define SSL_REC_CHANGE_CIPHER_SPEC  0x14
#define SSL_REC_ALERT               0x15
#define SSL_REC_HANDSHAKE           0x16
#define SSL_REC_APPLICATION_DATA    0x17

/* SSL version */
#define SSLV3_VERSION 0x300
#define TLSV1_VERSION 0x301

#endif /* __AGENT_SSL_ANALYZER_H__ */
