#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "ssl-packet.h"

static char *priKeyFile = NULL;
static char *priKeyPwd = NULL;
static sslDecodeCtxPtr sslDecCtx = NULL;

#define LSB(a) (a & 0xff)
#define MSB(a) ((a >> 8) & 0xff)
#define COMBINE(a, b) ((a << 8) | b)

#define SSL_DECODE_UINT8(a, b) sslDecodeUintX (1, a, b)
#define SSL_DECODE_UINT16(a, b) sslDecodeUintX (2, a, b)
#define SSL_DECODE_UINT24(a, b) sslDecodeUintX (3, a, b)
#define SSL_DECODE_UINT32(a, b) sslDecodeUintX (4, a, b)
#define SSL_DECODE_OPAQUE_ARRAY(a, b, c) sslDecodeOpaqueArray (a, b, c)

#define BYTES_NEEDED(x)  (x <= 255) ? 1 : ((x <= (1 << 16)) ? 2 : (x <= (1 << 24) ? 3 : 4))

#define PRF(ssl, secret, usage, rnd1, rnd2, out)
(ssl->version == SSLV3_VERSION) ?               \
ssl3Prf (ssl, secret, usage, rnd1, rnd2, out)   \
: tlsPrf (ssl, secret, usage, rnd1, rnd2, out)

int
sslDecodeUintX (int size, dataPtr dp, u_int *x) {
    u_int v = 0;

    if (size > dp->len) {
        LOGE ("sslDecodeUintX error.\n");
        return -1;
    }

    while (size--) {
        v <<= 8;
        v |= *(dp->data)++;
        dp->len--;
    }

    *x = v;
    return 0;
}

int
sslDecodeOpaqueArray (int size, dataPtr dp, dataPtr x) {
    int r;
    u_int len;

    if (size < 0) {
        size *= -1;
        r = sslDecodeUintX (BYTES_NEEDED (size), dp, &len);
        if (r < 0)
            return -1;
    } else
        len = size;

    if (len > data->len) {
        LOGE ("sslDecodeOpaqueArray error.\n");
        return -1;
    }

    x->data = data->data;
    x->len = len;
    data->data += len;
    data->len -= len;

    return 0;
}

void
sslDestroyRecDecoder (sslRecDecoderPtr *recDecoder) {
    if((recDecoder == NULL) || (*recDecoder == NULL))
        return;

    dataDestroy (&(*recDecoder)->macKey);
    if ((*recDecoder)->evp) {
        EVP_CIPHER_CTX_cleanup ((*recDecoder)->evp);
        free ((*recDecoder)->evp);
    }
    free (*recDecoder);
    *recDecoder = NULL;
}

sslRecDecoderPtr
sslCreateRecDecoder (sslCipherSuitePtr cs, u_char *mk, u_char *sk, u_char *iv) {
    sslRecDecoderPtr tmp;
    const EVP_CIPHER *ciph;

    /* Find the SSLeay cipher */
    if (cs->enc != ENC_NULL)
        ciph = (EVP_CIPHER *) EVP_get_cipherbyname (sslGetCipherName (cs->enc));

    tmp = (sslRecDecoderPtr) malloc (sizeof (sslRecDecoder));
    if (tmp == NULL)
        goto exit;

    dec->cs = cs;
    dec->macKey = dataCreate (mk, cs->digLen);
    if (dec->macKey == NULL)
        goto destroyRecDecoder;

    tmp->evp = (EVP_CIPHER_CTX *) malloc (sizeof (EVP_CIPHER_CTX));
    if(tmp->evp == NULL)
        goto destroyRecDecoder;

    EVP_CIPHER_CTX_init (dec->evp);
    EVP_CipherInit (dec->evp, ciph, sk, iv, 0);
    goto exit;

destroyRecDecoder:
    sslDestroyRecDecoder (&tmp);
exit:
    return tmp;
}

static int
fmtSeq (u_int num, u_char *buf) {
    u_int netNum;

    memset (buf, 0, 8);
    netNum = htonl (num);
    memcpy (buf + 4, &netNum, 4);

    return 0;
}

static int
tlsCheckMac (sslRecDecoderPtr recDecoder, int contentType, int version,
             u_char *data, u_int dataLen, u_char *mac) {
    HMAC_CTX hm;
    const EVP_MD *md;
    u_int len;
    u_char buf [20];

    md = EVP_get_digestbyname (sslGetDigestName (recDecoder->cs->dig));
    HMAC_Init (&hm, recDecoder->macKey->data, d->macKey->len, md);

    fmtSeq (recDecoder->seq, buf);
    recDecoder->seq++;
    HMAC_Update (&hm, buf, 8);
    buf [0] = contentType;
    HMAC_Update (&hm, buf, 1);

    buf [0] = MSB (version);
    buf [1] = LSB (version);
    HMAC_Update (&hm, buf, 2);

    buf [0] = MSB (dataLen);
    buf [1] = LSB (dataLen);
    HMAC_Update (&hm, buf, 2);

    HMAC_Update (&hm, data, dataLen);

    HMAC_Final (&hm, buf, &len);
    HMAC_cleanup (&hm);

    if (memcmp (mac, buf, len))
        return -1;
    else
        return 0;
}

int
ssl3CheckMac (sslRecDecoderPtr recDecoder, int contentType, int version,
              u_char *data, u_int dataLen, u_char *mac) {
    EVP_MD_CTX mc;
    const EVP_MD *md;
    u_int len;
    u_char buf [64], dgst [20];
    int padContent;

    padContent = (recDecoder->cs->dig == DIG_SHA) ? 40 : 48;

    md = EVP_get_digestbyname (sslGetDigestName (recDecoder->cs->dig));
    EVP_DigestInit (&mc, md);

    EVP_DigestUpdate (&mc, recDecoder->macKey->data, recDecoder->macKey->len);

    memset (buf, 0x36, padContent);
    EVP_DigestUpdate (&mc, buf, padContent);

    fmtSeq (recDecoder->seq, buf);
    recDecoder->seq++;
    EVP_DigestUpdate (&mc, buf, 8);

    buf [0] = contentType;
    EVP_DigestUpdate (&mc, buf, 1);

    buf [0] = MSB (dataLen);
    buf [1] = LSB (dataLen);
    EVP_DigestUpdate (&mc, buf, 2);
    EVP_DigestUpdate (&mc, data, dataLen);
    EVP_DigestFinal (&mc, dgst, &len);

    EVP_DigestInit (&mc, md);
    EVP_DigestUpdate (&mc, recDecoder->macKey->data, recDecoder->macKey->len);
    memset (buf, 0x5c, padContent);
    EVP_DigestUpdate (&mc, buf, padContent);
    EVP_DigestUpdate (&mc, dgst, len);
    EVP_DigestFinal (&mc, dgst, &len);

    if (memcmp (mac, dgst, len))
        return -1;

    return 0;
}

int
sslDecodeRecordData (sslObjectPtr ssl, sslRecDecoderPtr recDecoder, int contentType,
                     int version, u_char *in, int inLen, u_char *out, int *outLen) {
    int ret = 0;
    int pad;
    u_char *mac;

    EVP_Cipher (recDecoder->evp, out, in, inLen);
    *outLen = inLen;

    /* Now strip off the padding*/
    /* If block encryption strip off the padding */
    if (recDecoder->cs->block != 1) {
        pad = out [inLen - 1];
        *outLen -= (pad + 1);
    }

    /* After decryption then strip digest message */
    *outLen -= recDecoder->cs->digLen;
    mac = out + (*outLen);

    /* Now check the MAC */
    if (ssl->version == SSLV3_VERSION) {
        ret = ssl3CheckMac (recDecoder, contentType, version, out, *outLen, mac)
              if (ret < 0)
                  return -1;
    } else {
        ret = tlsCheckMac (recDecoder, contentType, version, out, *outLen, mac);
        if (ret < 0)
            return -1;
    }

    return 0;
}

static int
getPriKeyPwd (char *buf, int num, int rwflag, void *userdata) {
    if (num < strlen (priKeyPwd) + 1)
        return 0;

    strcpy (buf, priKeyPwd);
    return (strlen (priKeyPwd));
}

void
freeSSLDecodeCtx (sslDecodeCtxPtr ctx) {
    if (ctx->sslCtx)
        SSL_CTX_free (ctx->sslCtx);
    if (ctx->ssl)
        SSL_free (ctx->ssl);
    if (ctx->sessionCache)
        hashDestroy (&ctx->sessionCache);
}

sslDecodeCtxPtr
createSSLDecodeCtx (char *priKeyFile, char *priKeyPwd) {
    sslDecodeCtxPtr tmp;

    tmp = (sslDecodeCtxPtr) calloc (sizeof (sslDecodeCtx), 1);
    if (tmp == NULL)
        goto exit;

    tmp->sslCtx = SSL_CTX_new (SSLv23_server_method ());
    if (tmp->sslCtx == NULL)
        goto freeSSLDecodeCtx;

    sslPriKeyPwd = priKeyPwd;
    SSL_CTX_set_default_passwd_cb (tmp->sslCtx, getPriKeyPwd);
    if (SSL_CTX_use_PrivateKey_file (tmp->sslCtx, priKeyFile, SSL_FILETYPE_PEM) != 1) {
        LOGE ("Loading private key error.\n");
        goto freeSSLDecodeCtx;
    }

    tmp->ssl = SSL_new (tmp->sslCtx);
    if (tmp->ssl == NULL)
        goto freeSSLDecodeCtx;

    tmp->sessionCache = hashNew (0);
    if (tmp->sessionCache == NULL)
        goto freeSSLDecodeCtx;

    goto exit;

feeSSLDecodeCtx:
    freeSSLDecodeCtx (tmp);
    tmp = NULL;
exit:
    return tmp;
}

sslDecoderPtr
createSSLDecoder (sslDecodeCtxPtr ctx) {
    sslDecoderPtr tmp;

    tmp = (sslDecoderPtr) malloc (sizeof (sslDecoder));
    if (tmp == NULL)
        return NULL;
    tmp->sessionId = NULL;
    tmp->ctx = ctx;
    tmp->cs = NULL;
    tmp->clientRandom = NULL;
    tmp->serverRandom = NULL;
    tmp->ephemeralRsa = 0;
    tmp->PMS = NULL;
    tmp->MS = NULL;
    tmp->c2sDecoder = NULL;
    tmp->c2sDecoderN = NULL;
    tmp->s2cDecoder = NULL;
    tmp->s2cDecoderN = NULL;

    return tmp;
}

void
freeSSLDecoder (sslDecoderPtr decoder) {
    if (decoder == NULL)
        return;

    dataDestroy (&decoder->sessionId);
    dataDestroy (&decoder->clientRandom);
    dataDestroy (&decoder->serverRandom);
    dataDestroy (&decoder->PMS);
    dataDestroy (&decoder->MS);
    sslRecDecoderDestroy (&decoder->c2sDecoder);
    sslRecDecoderDestroy (&decoder->c2sDecoderN);
    sslRecDecoderDestroy (&decoder->s2cDecoder);
    sslRecDecoderDestroy (&decoder->s2cDecoderN);
    free (decoder);
}

static int tlsPrf (sslObjectPtr ssl, dataPtr secret, char *usage,
                   dataPtr rnd1, dataPtr rnd2, dataPtr out) {
    int ret = 0;
    dataPtr md5out;
    dataPtr SHAOut;
    dataPtr seed;
    u_char *ptr;
    dataPtr S1, S2;
    int i, S_l;

    md5out = dataAlloc (MAX (out->len, 16));
    if (md5out == NULL) {
        ret = -1;
        goto exit;
    }

    SHAOut = dataAlloc (MAX (out->len, 20));
    if (SHAOut == NULL) {
        ret = -1;
        goto freeMD5Out;
    }

    seed = dataAlloc (strlen (usage) + rnd1->len + rnd2->len);
    if (seed == NULL) {
        ret = -1;
        goto freeSHAOut;
    }

    ptr = seed->data;
    memcpy (ptr, usage, strlen (usage));
    ptr += strlen (usage);
    memcpy (ptr, rnd1->data, rnd1->len);
    ptr += rnd1->len;
    memcpy (ptr, rnd2->data, rnd2->len);
    ptr += rnd2->len;

    S_l = secret->len / 2 + secret->len % 2;
    S1 = dataAlloc (S_l);
    if (S1 == NULL) {
        ret = -1;
        goto freeSeed;
    }
    S2 = dataAlloc (S_l);
    if (S2 == NULL) {
        ret = -1;
        goto freeS1;
    }

    memcpy (S1->data, secret->data, S_l);
    memcpy (S2->data, secret->data + (secret->len - S_l), S_l);
    if (tlsPHash (ssl, S1, seed, EVP_get_digestbyname ("MD5"), md5Out) < 0) {
        ret = -1;
        goto freeS2;
    }
    if (tlsPHash (ssl, S2, seed, EVP_get_digestbyname ("SHA1"), SHAOut) < 0) {
        ret = -1;
        goto freeS2;
    }

    for (i = 0; i < out->len, i++)
        out->data [i] = md5Out->data [i] ^ SHAOut->data [i];

    goto exit;

freeS2:
    dataDestroy (&S2);
freeS1:
    dataDestroy (&S1);
freeSeed:
    dataDestroy (&seed);
freeSHAOut:
    dataDestroy (&SHAOut);
freeMD5Out:
    dataDestroy (&md5Out);
exit:
    return ret;
}

static int
ssl3Prf (sslObjectPtr ssl, dataPtr secret, dataPtr usage,
         dataPtr rnd1, dataPtr rnd2, dataPtr out) {
    int i = 0, j, off, toCopy;
    u_char buf [20];
    u_char outbuf [16];
    MD5_CTX md5;
    SHA_CTX sha;

    MD5_Init (&md5);
    memset (&sha, 0, sizeof (sha));
    SHA1_Init (&sha);

    for(off = 0; off < out->len; off += 16) {
        i++;
        /* A, BB, CCC,  ... */
        for(j = 0; j < i; j++) {
            buf [j] = 64 + i;
        }

        SHA1_Update (&sha, buf, i);
        if (secret)
            SHA1_Update (&sha, secret->data, secret->len);

        if (!strcmp (usage,"client write key") || !strcmp (usage,"server write key")) {
            SHA1_Update (&sha, rnd2->data, rnd2->len);
            SHA1_Update (&sha, rnd1->data, rnd1->len);
        } else {
            SHA1_Update (&sha, rnd1->data, rnd1->len);
            SHA1_Update (&sha, rnd2->data, rnd2->len);
        }
        SHA1_Final (buf, &sha);
        SHA1_Init (&sha);

        MD5_Update (&md5, secret->data, secret->len);
        MD5_Update (&md5, buf, 20);
        MD5_Final (outbuf, &md5);
        toCopy = MIN (out->len - off, 16);
        memcpy (out->data + off, outbuf, toCopy);
        MD5_Init (&md5);
    }

    return 0;
}

static int
ssl3GenerateExportIV (sslObjectPtr ssl, dataPtr rnd1, dataPtr rnd2, dataPtr out) {
    MD5_CTX md5;
    u_char tmp [16];

    MD5_Init (&md5);
    MD5_Update (&md5, rnd1->data, rnd1->len);
    MD5_Update(&md5, rnd2->data, rnd2->len);
    MD5_Final (tmp, &md5);

    memcpy (out->data, tmp, out->len);

    return(0);
}

static int
sslGenerateKeyingMaterial (sslObjectPtr ssl, sslDecoderPtr decoder) {
    int ret = 0;
    int needed;
    dataPtr keyBlock;
    u_char _cliIV [8], _srvIV [8];
    data cliIV, srvIV;
    u_char _cliKey [16], _srvKey [16];
    data cliKey, srvKey;
    data k;
    u_char *ptr, *cliWK, *srvWK, *cliMK, *srvMK, *cliIV, *srvIV;
    u_char _IVBlock [16];
    data IVBlock;
    u_char _keyNull;
    data keyNull;
    MD5_CTX md5;

    if(decoder->MS == NULL) {
        decoder->MS = dataAlloc (48);
        if(decoder->MS == NULL) {
            ret = -1;
            goto exit;
        }

        ret = PRF (ssl, decoder->PMS, "master secret", decoder->clientRandom,
                   decoder->serverRandom, decoder->MS);
        if(ret < 0) {
            ret = -1;
            goto exit;
        }
    }

    /* Compute the key block. First figure out how much data we need*/
    needed = ssl->cs->digLen * 2;
    needed += ssl->cs->bits / 4;
    if (ssl->cs->block > 1)
        needed += ssl->cs->block * 2;

    keyBlock = dataAlloc (needed);
    if(keyBlock == NULL) {
        ret = -1;
        goto exit;
    }
    ret = PRF (ssl, decoder->MS, "key expansion", decoder->serverRandom,
               decoder->>clientRandom, keyBlock);
    if(ret < 0) {
        ret = -1;
        goto freeKeyBlock;
    }

    ptr = keyBlock->data;
    cliMK = ptr;
    ptr += ssl->cs->digLen;
    srvMK = ptr;
    ptr += ssl->cs->digLen;

    cliWK=ptr;
    ptr += ssl->cs->effBits / 8;
    srvWK = ptr;
    ptr += ssl->cs->effBits / 8;

    if (ssl->cs->block > 1) {
        cliIV = ptr;
        ptr += ssl->cs->block;
        srvIV = ptr;
        ptr += ssl->cs->block;
    }

    if (ssl->cs->export) {
        if (ssl->cs->block > 1) {
            ATTACH_DATA (cliIV, _cliIV);
            ATTACH_DATA (srvIV, _srvIV);

            if (ssl->version == SSLV3_VERSION) {
                ret = ssl3GenerateExportIV (ssl, decoder->clientRandom, decoder->serverRandom, &cliIV);
                if(ret < 0) {
                    ret = -1;
                    goto freeKeyBlock;
                }

                ret = ssl3GenerateExportIV (ssl, decoder->serverRandom, decoder->clientRandom, &srvIV);
                if(ret < 0) {
                    ret = -1;
                    goto freeKeyBlock;
                }
            } else {
                INIT_DATA (keyNull, &_keyNull, 0);
                if (ssl->cs->block > 8) {
                    ret = -1;
                    goto freeKeyBlock;
                }

                ATTACH_DATA (IVBlock, _IVBlock);
                ret = PRF (ssl, &keyNull, "IV block", decoder->clientRandom,
                           decoder->serverRandom, &IVBlock);
                if (ret < 0) {
                    ret = -1;
                    goto freeKeyBlock;
                }

                memcpy (_cliIV, IVBlock.data, 8);
                memcpy (_srvIV, IVBlock.data + 8, 8);
            }

            cliIV = _cliIV;
            srvIV = _srvIV;
        }

        if(ssl->version == SSLV3_VERSION) {
            MD5_Init (&md5);
            MD5_Update (&md5, cliWK, ssl->cs->effBits / 8);
            MD5_Update (&md5, decoder->clientRandom->data, decoder->clientRandom->len);
            MD5_Update (&md5, decoder->serverRandom->data, decoder->serverRandom->len);
            MD5_Final (_cliKey, &md5);
            cliWK = _cliKey;

            MD5_Init (&md5);
            MD5_Update (&md5, srvWK, ssl->cs->effBits / 8);
            MD5_Update (&md5, decoder->serverRandom->data, decoder->serverRandom->len);
            MD5_Update (&md5, decoder->clientRandom->data, decoder->clientRandom->len);
            MD5_Final (_srvKey, &md5);
            srvWK = _srvKey;
        } else {
            ATTACH_DATA (cliKey, _cliKey);
            ATTACH_DATA (srvKey, _srvKey);

            INIT_DATA (k, cliWK, ssl->cs->effBits / 8);
            ret = PRF (ssl, &k, "client write key", decoder->clientRandom,
                       decoder->serverRandom, &cliKey);
            if(ret < 0) {
                ret = -1;
                goto freeKeyBlock;
            }
            cliWK = _cliKey;

            INIT_DATA (k, srvWK, ssl->cs->effBits / 8);
            ret = PRF (ssl, &k, "server write key", decoder->clientRandom,
                       decoder->serverRandom, &srvKey);
            if(ret < 0) {
                ret = -1;
                goto freeKeyBlock;
            }
            srvWK = _srvKey;
        }
    }

    decoder->c2sDecoderN = sslCreateRecDecoder (ssl->cs, cliMK, cliWK, cliIV);
    if (decoder->c2sDecoderN == NULL) {
        ret = -1;
        goto freeKeyBlock;
    }
    decoder->s2cDecoderN = sslCreateRecDecoder (ssl->cs, srvMK, srvWK, srvIV);
    if (decoder->s2cDecoderN == NULL) {
        ret = -1;
        goto freeKeyBlock;
    }

freeKeyBlock:
    dataZfree (keyBlock);
    dataDestroy (&keyBlock);
exit:
    return ret;
}

static void
sslCreateSessionLookupKey (sslObjectPtr ssl, u_char *sid, int sidLen, char *key) {
    u_char *key, *tmp;
    int tmpLen;

    tmpLen = sidLen + 32;        /* SessionId + ip + port */
    tmp = key;
    memcpy (tmp, sid, sidLen);
    tmp += sidLen;
    sprintf (tmp, "%s:%d", inet_ntoa (ssl->srvIp), ntohs (ssl->srvPort));
}

int
sslRestoreSession (sslObjectPtr ssl, sslDecoderPtr decoder) {
    dataPtr msd;
    u_char lookupKey [128];

    sslCreateSessionLookupKey (ssl, decoder->SessionId->data, decoder->SessionId->len, lookupKey);
    msd = (dataPtr) hashLookup (decoder->ctx->sessionCache, lookupKey);
    if (msd == NULL)
        ret = -1;

    decoder->MS = dataCreate (msd->data, msd->len);
    if (decoder->MS)
        ret = -1;

    switch (ssl->version) {
        case SSLV3_VERSION:
            if (sslGenerateKeyingMaterial (ssl, decoder) < 0)
                return -1;
            break;

        case TLSV1_VERSION:
            if (sslGenerateKeyingMaterial (ssl, decoder) < 0)
                return -1;
            break;

        default:
            return -1;
    }

    return 0;
}

static void
freeSessionCache (void *data) {
    dataPtr msd = (dataPtr) data;

    dataZfree (msd);
    dataDestroy (&msd);
}

int
sslSaveSession (sslObjectPtr sdd, sslDecoderPtr decoder) {
    dataPtr msd;
    u_char lookupKey [128];

    sslCreateSessionLookupKey (ssl, decoder->sessionId->data, decoder->sessionId->len, lookupKey);
    msd = dataCreate (decoder->MS->data, decoder->MS->len);
    if (msd == NULL)
        return -1;

    if (hashInsert (decoder->ctx->sessionCache, lookupKey, (void *) msd, freeSessionCache) < 0)
        return -1;

    return 0;
}

int
sslSetClientRandom (sslObjectPtr ssl, u_char *random, int len) {
    sslDecoderPtr decoder = ssl->decoder;

    decoder->clientRandom = dataCreate (random, len);
    if (decoder->clientRandom == NULL)
        return -1;

    return 0;
}

int
sslSetClientSessionId (sslObjectPtr ssl, u_char *sessionId, int len) {
    sslDecoderPtr decoder = ssl->decoder;

    decoder->sessionId = dataCreate (sessionId, len);
    if (decoder->sessionId == NULL)
        return -1;

    return 0;
}

int
sslSetServerRandom (sslObjectPtr ssl, u_char *random, int len) {
    sslDecoderPtr decoder = ssl->decoder;

    decoder->serverRandom = dataCreate (random, len);
    if (decoder->serverRandom == NULL)
        return -1;

    return 0;
}

int
sslProcessServerSessionId (sslObjectPtr ssl, u_char *sessionId, int len) {
    int ret = 0;
    int restored = 0;
    data tmp;
    sslDecoderPtr decoder = ssl->decoder;

    INIT_DATA (tmp, sessionId, len);
    /* First check to see if the client tried to restore */
    if (decoder->sessionId) {
        if (dataCompare (&tmp, decoder->sessionId))
            goto exit;
        ret = sslRestoreSession (ssl, decoder);
        if (ret < 0) {
            ret = -1;
            goto exit;
        }

        restored = 1;
    }

exit:
    if (!restored) {
        dataZfree (decoder->sessionId);
        ret = dataMake (decoder->SessionId, sessionId, len);
    }

    return ret;
}

int
sslProcessChangeCipherSpec (sslObjectPtr ssl, int fromClient) {
    sslDecoderPtr decoder = ssl->decoder;

    if(fromClient) {
        decoder->c2sDecoder = decoder->c2sDecoderN;
        decoder->c2sDecoderN = NULL;
    } else {
        decoder->s2cDecoder = decoder->s2cDecoderN;
        decoder->s2cDecoderN = NULL;
    }

    return 0;
}

int
sslDecodeRecord (sslObjectPtr ssl, int fromClient, int contentType,
                 int version, dataPtr d) {
    int state;
    u_char *out;
    int outLen;
    sslRecDecoderPtr rd;
    sslDecoderPtr decoder = ssl->decoder;

    if (fromClient) {
        rd = decoder->c2sDecoder;
        state = ssl->cliState;
    } else {
        rd = decoder->s2cDecoder;
        state = ssl->srvState;
    }

    /* If SSL_REC_CHANGE_CIPHER_SPEC has not been sent */
    if (rd == NULL)
        return 0;

    out = (u_char *) malloc (d->len);
    if (out == NULL)
        return -1;

    if (sslDecodeRecordData (ssl, rd, contentType, version, d->data, d->len, out, &outLen)) {
        free (out);
        return -1;
    }
    memcpy (d->data, out, outLen);
    d->len = outLen;

    return 0;
}

int
sslProcessClientKeyExchange (sslObjectPtr ssl, u_char *pms, int len) {
    int i;
    EVP_PKEY *pk;
    sslRecDecoderPtr decoder = ssl->decoder;

    if (ssl->cs->kex != KEX_RSA)
        return -1;

    if (decoder->ephemeralRsa)
        return -1;

    pk = SSL_get_privatekey (decoder->ctx->ssl);
    if (pk == NULL)
        return -1;

    if (pk->type != EVP_PKEY_RSA)
        return -1;

    decoder->PMS = dataAlloc (BN_num_bytes (pk->pkey.rsa->n));
    if (decoder->PMS == NULL)
        return -1;

    i = RSA_private_decrypt (len, pms, decoder->PMS->data, pk->pkey.rsa, RSA_PKCS1_PADDING);
    if (i != 48)
        return -1;
    decoder->PMS->len = 48;
    /* Destroy master secret to enforce keying material regeneration */
    dataDestroy (&decoder->MS);

    switch (ssl->version) {
        case SSLV3_VERSION:
        case TLSV1_VERSION:
            if (sslGenerateKeyingMaterial (ssl, decoder) < 0)
                return -1;
            break;

        default:
            return -1;
    }

    if (sslSaveSession (ssl, decoder) < 0)
        return -1;

    return 0;
}

static int
tlsPHash (sslObjectPtr ssl, dataPtr secret, dataPtr seed, EVP_MD *md, dataPtr out) {
    u_char *ptr = out->data;
    int left = out->len;
    int toCopy;
    u_char *A;
    u_char _A [20], tmp [20];
    u_int A_l, tmp_l;
    HMAC_CTX hm;

    A = seed->data;
    A_l = seed->len;

    while (left) {
        HMAC_Init (&hm, secret->data, secret->len, md);
        HMAC_Update (&hm, A, A_l);
        HMAC_Final (&hm, _A, &A_l);
        A = _A;

        HMAC_Init (&hm, secret->data, secret->len, md);
        HMAC_Update (&hm, A, A_l);
        HMAC_Update (&hm, seed->data, seed->len);
        HMAC_Final (&hm, tmp, &tmp_l);

        toCopy = MIN (left, tmp_l);
        memcpy (ptr, tmp, toCopy);
        ptr += toCopy;
        left -= toCopy;
    }

    HMAC_cleanup (&hm);

    return 0;
}

static int
decodeContentTypeChangeCipherSpec (sslObjectPtr ssl, int fromClient, dataPtr record) {
    sslProcessChangeCipherSpec (ssl, fromClient);

    if (fromClient)
        ssl->cliState = SSL_ST_SENT_CHANGE_CIPHER_SPEC;
    else
        ssl->srvState = SSL_ST_SENT_CHANGE_CIPHER_SPEC;

    return 0;
}

static int
decodeContentTypeAlert (sslObjectPtr ssl, int fromClient, dataPtr record) {
    /* TODO: */
    return 0;
}

static int
decodeHandshakeTypeHelloRequest (sslObjectPtr ssl, int fromClient, dataPtr data) {
    return 0;
}

static int
decodeHandshakeTypeClientHello (sslObjectPtr ssl, int fromClient, dataPtr data) {
    int ret;
    u_int majVer, minVer;
    u_int csLen, cs;
    u_int compLen, comp;
    data sessionId, random;

    SSL_DECODE_UINT8 (data, &majVer);
    SSL_DECODE_UINT8 (data, &minVer);

    SSL_DECODE_OPAQUE_ARRAY (32, data, &random);
    ret = sslSetClientRandom (ssl, random.data, random.len);
    if (ret < 0)
        return -1;

    SSL_DECODE_OPAQUE_ARRAY (-32, data, &sessionId);
    if (sessionId.len) {
        ret = sslSetClientSessionId (ssl, sessionId.data, sessionId.len);
        if (ret < 0)
            return -1;
    }

    return 0;
}

static int
decodeHandshakeTypeServerHello (sslObjectPtr ssl, int fromClient, dataPtr data) {
    int ret;
    data random, sessionId;
    uint majVer, minVer;

    SSL_DECODE_UINT8 (data, &majVer);
    SSL_DECODE_UINT8 (data, &minVer);
    ssl->version = majVer * 256 + minVer;

    SSL_DECODE_OPAQUE_ARRAY (32, data, &random);
    ret = sslSetServerRandom (ssl, random.data, random.len);
    if (ret < 0)
        return -1;

    SSL_DECODE_OPAQUE_ARRAY (-32, data, &sessionId);
    SSL_DECODE_UINT16 (data, &ssl->cipherSuite);
    ssl->cs = sslGetCipherSuite (ssl->cipherSuite);
    if (ssl->cs == NULL)
        return -1;

    sslProcessServerSessionId (ssl, sessionId.data, sessionId.len);
}

static int
decodeHandshakeTypeCertificate (sslObjectPtr ssl, int fromClient, dataPtr data) {
    /* TODO: print certificate */
    return 0;
}

static int
decodeHandshakeTypeServerKeyExchange (sslObjectPtr ssl, int fromClient, dataPtr data) {
    return 0;
}

static int
decodeHandshakeTypeCertificateRequest (sslObjectPtr ssl, int fromClient, dataPtr data) {
    return 0;
}

static int
decodeHandshakeTypeServerHelloDone (sslObjectPtr ssl, int fromClient, dataPtr data) {
    return 0;
}

static int
decodeHandshakeTypeCertificateVerify (sslObjectPtr ssl, int fromClient, dataPtr data) {
    return 0;
}

static int
decodeHandshakeTypeClientKeyExchange (sslObjectPtr ssl, int fromClient, dataPtr data) {
    data pms;

    if(ssl->cs) {
        switch(ssl->cs->kex) {
            case KEX_RSA:
                if (ssl->version > SSLV3_VERSION)
                    SSL_DECODE_OPAQUE_ARRAY (-((1 << 15) - 1), data, &pms);
                else
                    SSL_DECODE_OPAQUE_ARRAY (data->len, data, &pms);
                sslProcessClientKeyExchange (ssl, pms.data, pms.len);
                break;

            default:
                break;
        }
    }

    return 0;
}

static int
decodeHandshakeTypeFinished (sslObjectPtr ssl, int fromClient, dataPtr data) {
    return 0;
}

static int
decodeContentTypeHandshake (sslObjectPtr ssl, int fromClient, dataPtr record) {
    data handShakeMsg;
    u_int handShakeType;
    u_int handShakeMsgLen;

    SSL_DECODE_UINT8 (record, &handShakeType);
    SSL_DECODE_UINT24 (record, &handShakeMsgLen);

    if (record->len < handShakeMsgLen)
        return -1;
    handShakeMsg.data = record->data;
    handShakeMsg.len = handShakeMsgLen;

    switch (handShakeType) {
        case SSL_HANDSHAKE_HELLO_REQUEST:
            decodeHandshakeTypeHelloRequest (ssl, fromClient, &handShakeMsg);

        case SSL_HANDSHAKE_CLIENT_HELLO:
            decodeHandshakeTypeClientHello (ssl, fromClient, &handShakeMsg);

        case SSL_HANDSHAKE_SERVER_HELLO:
            decodeHandshakeTypeServerHello (ssl, fromClient, &handShakeMsg);

        case SSL_HANDSHAKE_CERTIFICATE:
            decodeHandshakeTypeCertificate (ssl, fromClient, &handShakeMsg);

        case SSL_HANDSHAKE_SERVER_KEY_EXCHANGE:
            decodeHandshakeTypeServerKeyExchange (ssl, fromClient, &handShakeMsg);

        case SSL_HANDSHAKE_CERTIFICATE_REQUEST:
            decodeHandshakeTypeCertificateRequest (ssl, fromClient, &handShakeMsg);

        case SSL_HANDSHAKE_SERVER_HELLO_DONE:
            decodeHandshakeTypeServerHelloDone (ssl, fromClient, &handShakeMsg);

        case SSL_HANDSHAKE_CERTIFICATE_VERIFY:
            decodeHandshakeTypeCertificateVerify (ssl, fromClient, &handShakeMsg);

        case SSL_HANDSHAKE_CLIENT_KEY_EXCHANGE:
            decodeHandshakeTypeClientKeyExchange (ssl, fromClient, &handShakeMsg);

        case SSL_HANDSHAKE_FINISHED:
            decodeHandshakeTypeFinished (ssl, fromClient, &handShakeMsg);

            break;
    }
}

static int
decodeContentTypeApplicationData (sslObjectPtr ssl, int fromClient, dataPtr record) {
    /* TODO: update decrypted data */
    return 0;
}

int
initSSL (void) {
    return SSL_library_init ();
}

static sslDecodeCtxPtr
getSSLDecodeCtx (struct in_addr *ip, uint16_t port) {
    if (sslDecCtx == NULL)
        sslDecCtx = sslDecodeCtxCreate (priKeyFile, priKeyPwd);

    return sslDecCtx;
}

static void
freeSSLObject (sslObjectPtr object) {
    if (object->decoder)
        freeSSLDecoder (object->decoder);
    if (object->cliRcvBuf)
        free (object->cliRcvBuf);
    if (object->srvRcvBuf)
        free (object->srvRcvBuf);

    free (object);
}

static sslObjectPtr
newSSLObject (struct in_addr *cliIp, uint16_t cliPort,
              struct in_addr *srvIp, uint16_t srvPort) {
    sslObjectPtr object;

    object = (sslObjectPtr) calloc (sizeof (sslObject), 1);
    if (object == NULL)
        goto exit;

    object->cliState = SSL_ST_SENT_NOTHING;
    object->srvState = SSL_ST_HANDSHAKE;

    object->cliIp.s_addr = cliIp.s_addr;
    object->cliPort = cliPort;
    object->srvIp.s_addr = srvIp.s_addr;
    object->srvPort = srvPort;

    object->sslDecCtx = getSSLDecodeCtx (srvIp, srvPort);
    if (object->sslDecCtx == NULL)
        goto freeSSLObject;
    object->decoder = createSSLDecoder (object->sslDecCtx);
    if (object->decoder == NULL)
        goto freeSSLObject;

    object->cliRcvBuf = NULL;
    object->cliRcvBufSize = 0;
    object->cliRcvOffset = 0;
    object->cliRcvCount = 0;

    object->srvRcvBuf = NULL;
    object->srvRcvBufSize = 0;
    object->srvRcvOffset = 0;
    object->srvRcvCount = 0;

    goto exit;

freeSSLObject:
    freeSSLObject (object);
    object = NULL;
exit:
    return object;
}

static int
processV2Hello (sslObjectPtr ssl, u_char *data, int dataLen, int *parseLen) {
    int ver;
    int recLen;
    int csLen;
    int sidLen;
    int challLen;
    data d;
    data chall;
    char random [32];

    *parseLen = dataLen;

    if (dataLen == 0)
        return SSL_NO_DATA;

    d.data = data;
    d.len = dataLen;
    /* First check the message length. */
    if (d.len < 4)
        return SSL_BAD_CONTENT_TYPE;

    recLen = ((d.data [0] & 0x7f) << 8) | (d.data [1]);
    d.data += 2;
    d.len -= 2;

    /* We assume SSLv2 client request in one tcp packet,
     * if dataLen doesn't equal to record len, whatever
     * this is it isn't valid SSLv2.
     */
    if (d.len != recLen)
        return SSL_BAD_CONTENT_TYPE;

    /* If msg_type == 1 then we've got a v2 message (or trash)*/
    if (*d.data != 1)
        return SSL_BAD_CONTENT_TYPE;
    d.data++;
    d.len--;

    /* Get ssl version */
    SSL_DECODE_UINT16 (&d,&ver);
    if( ver <= 2)
        return SSL_BAD_DATA;
    /* Get ssl cipher spec length */
    SSL_DECODE_UINT16 (&d, &csLen);
    /* Get ssl session id length */
    SSL_DECODE_UINT16 (&d, &sidLen);
    /* Get ssl challenge length */
    SSL_DECODE_UINT16 (&d, &challLen);

    if (csLen % 3)
        return SSL_BAD_DATA;

    if (sidLen != 0)
        return SSL_BAD_DATA;

    if(challLen < 16 || challLen > 32)
        return SSL_BAD_DATA;

    SSL_DECODE_OPAQUE_ARRAY (challLen, &d, &chall);

    memset (random, 0, 32);
    memcpy (random + (32 - challLen), chall.data, challLen);

    sslSetClientRandom (ssl->decoder, random, 32);
    ssl->cliState = SSL_ST_HANDSHAKE;

    return 0;
}

static int
processBeginningPlaintext (sslObjectPtr ssl, u_char *data, int dataLen, int *parseLen) {
    *parseLen = dataLen;

    if (data [0] == 0x16)
        return SSL_BAD_CONTENT_TYPE;

    return 0;
}

static int
readSSLRecord (sslObjectPtr ssl, u_char *data, int dataLen, dataPtr record) {
    int recLen;

    record.data = NULL;
    record.len = 0;

    if (dataLen < SSL_HEADER_SIZE)
        return -1;
    /* Check record contentType */
    switch (data [0]) {
        case SSL_REC_CHANGE_CIPHER_SPEC:
        case SSL_REC_ALERT:
        case SSL_REC_HANDSHAKE:
        case SSL_REC_APPLICATION_DATA:
            break;

        default:
            LOGE ("Wrong SSL conetent type: %d.\n", data [0]);
            record.len = dataLen;
            return -1;
    }

    /* Get record length */
    recLen = COMBINE (data [3], data [4]);
    /* If current record has been fragmented, delay processing
     * until get the complete ssl record.
     */
    if (dataLen < (SSL_HEADER_SIZE + recLen))
        return -1;
    record->data = data;
    record->len = SSL_HEADER_SIZE + recLen;

    return 0;
}

int
sslProcess (int fromClient, u_char *data, int dataLen, sslObjectPtr ssl) {
    int ret;
    int parseLen;
    data record;
    int recordLen;
    u_int contentType;
    u_int contentLen;
    u_int majVer, minVer, version;

    /* Handle SSLv2 backwards compat client hello */
    if (fromClient && ssl->cliState == SSL_ST_SENT_NOTHING) {
        ret = processV2Hello (ssl, data, dataLen, &parseLen);
        if ((ret == 0) || (ret == SSL_NO_DATA) || (ret == SSL_BAD_DATA))
            return parseLen;
    }

    if (ssl->cliState == SSL_ST_SENT_NOTHING) {
        ret = processBeginningPlaintext (ssl, data, dataLen, &parseLen);
        if (ret == 0)
            return parseLen;
    }

    ret = readSSLRecord (ssl, data, dataLen, &record);
    if (ret < 0)
        return record.len;

    recordLen = record.len;
    if (recordLen) {
        if (ssl->cliState == SSL_ST_SENT_NOTHING)
            ssl->cliState = SSL_ST_HANDSHAKE;

        SSL_DECODE_UINT8 (&record, &contentType);
        SSL_DECODE_UINT8 (&record, &majVer);
        SSL_DECODE_UINT8 (&record, &minVer);
        SSL_DECODE_UINT8 (&record, &contentLen);

        if (record.len != contentLen)
            return recordLen;

        version = majVer * 256 + minVer;
        ret = sslDecodeRecord (ssl, fromClient, contentType, version, &record);
        if (ret < 0)
            return recordLen;

        switch (contentType) {
            case SSL_REC_CHANGE_CIPHER_SPEC:
                decodeContentTypeChangeCipherSpec (ssl, fromClient, &record);
                break;

            case SSL_REC_ALERT:
                decodeContentTypeAlert (ssl, fromClient, &record);
                break;

            case SSL_REC_HANDSHAKE:
                decodeContentTypeHandshake (ssl, fromClient, &record);
                break;

            case SSL_REC_APPLICATION_DATA:
                decodeContentTypeHandshake (ssl, fromClient, &record);
                break;

            default:
                LOGE ("Unknown contentType: %d\n", contentType);
                break;
        }
    }

    return recordLen;
}
