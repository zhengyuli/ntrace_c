#include "util.h"
#include "cipherSuites.h"

static char *cipherNames [] = {
    "DES",
    "DES3",
    "RC4",
    "RC2",
    "IDEA"
};

static char *digestNames [] = {
    "MD5",
    "SHA1"
};

static sslCipherSuite cipherSuites [] = {
    {1,   KEX_RSA, SIG_RSA,  ENC_NULL, 0, 0,   0,   DIG_MD5, 16, 0},
    {2,   KEX_RSA, SIG_RSA,  ENC_NULL, 0, 0,   0,   DIG_SHA, 20, 0},
    {3,   KEX_RSA, SIG_RSA,  ENC_RC4,  1, 128, 40,  DIG_MD5, 16, 1},
    {4,   KEX_RSA, SIG_RSA,  ENC_RC4,  1, 128, 128, DIG_MD5, 16, 0},
    {5,   KEX_RSA, SIG_RSA,  ENC_RC4,  1, 128, 128, DIG_SHA, 20, 0},
    {6,   KEX_RSA, SIG_RSA,  ENC_RC2,  8, 128, 40,  DIG_SHA, 20, 1},
    {7,   KEX_RSA, SIG_RSA,  ENC_IDEA, 8, 128, 128, DIG_SHA, 20, 0},
    {8,   KEX_RSA, SIG_RSA,  ENC_DES,  8, 64,  40,  DIG_SHA, 20, 1},
    {9,   KEX_RSA, SIG_RSA,  ENC_DES,  8, 64,  64,  DIG_SHA, 20, 0},
    {10,  KEX_RSA, SIG_RSA,  ENC_3DES, 8, 192, 192, DIG_SHA, 20, 0},
    {11,  KEX_DH,  SIG_DSS,  ENC_DES,  8, 64,  40,  DIG_SHA, 20, 1},
    {12,  KEX_DH,  SIG_DSS,  ENC_DES,  8, 64,  64,  DIG_SHA, 20, 0},
    {13,  KEX_DH,  SIG_DSS,  ENC_3DES, 8, 192, 192, DIG_SHA, 20, 0},
    {14,  KEX_DH,  SIG_RSA,  ENC_DES,  8, 64,  40,  DIG_SHA, 20, 1},
    {15,  KEX_DH,  SIG_RSA,  ENC_DES,  8, 64,  64,  DIG_SHA, 20, 0},
    {16,  KEX_DH,  SIG_RSA,  ENC_3DES, 8, 192, 192, DIG_SHA, 20, 0},
    {17,  KEX_DH,  SIG_DSS,  ENC_DES,  8, 64,  40,  DIG_SHA, 20, 1},
    {18,  KEX_DH,  SIG_DSS,  ENC_DES,  8, 64,  64,  DIG_SHA, 20, 0},
    {19,  KEX_DH,  SIG_DSS,  ENC_3DES, 8, 192, 192, DIG_SHA, 20, 0},
    {20,  KEX_DH,  SIG_RSA,  ENC_DES,  8, 64,  40,  DIG_SHA, 20, 1},
    {21,  KEX_DH,  SIG_RSA,  ENC_DES,  8, 64,  64,  DIG_SHA, 20, 0},
    {22,  KEX_DH,  SIG_RSA,  ENC_3DES, 8, 192, 192, DIG_SHA, 20, 0},
    {23,  KEX_DH,  SIG_NONE, ENC_RC4,  1, 128, 40,  DIG_MD5, 16, 1},
    {24,  KEX_DH,  SIG_NONE, ENC_RC4,  1, 128, 128, DIG_MD5, 16, 0},
    {25,  KEX_DH,  SIG_NONE, ENC_DES,  8, 64,  40,  DIG_MD5, 16, 1},
    {26,  KEX_DH,  SIG_NONE, ENC_DES,  8, 64,  64,  DIG_MD5, 16, 0},
    {27,  KEX_DH,  SIG_NONE, ENC_3DES, 8, 192, 192, DIG_MD5, 16, 0},
    {96,  KEX_RSA, SIG_RSA,  ENC_RC4,  1, 128, 56,  DIG_MD5, 16, 1},
    {97,  KEX_RSA, SIG_RSA,  ENC_RC2,  1, 128, 56,  DIG_MD5, 16, 1},
    {98,  KEX_RSA, SIG_RSA,  ENC_DES,  8, 64,  64,  DIG_SHA, 20, 1},
    {99,  KEX_DH,  SIG_DSS,  ENC_DES,  8, 64,  64,  DIG_SHA, 16, 1},
    {100, KEX_RSA, SIG_RSA,  ENC_RC4,  1, 128, 56,  DIG_SHA, 20, 1},
    {101, KEX_DH,  SIG_DSS,  ENC_RC4,  1, 128, 56,  DIG_SHA, 20, 1},
    {102, KEX_DH,  SIG_DSS,  ENC_RC4,  1, 128, 128, DIG_SHA, 20, 0},
};

char *
sslGetDigestName (int dig) {
    int index = dig - 0x40;

    if (index < 0 || index >= TABLE_SIZE (digestNames))
        return NULL;

    return digestNames [index];
}

char *
sslGetCipherName (int ciph) {
    int index = dig - 0x30;

    if (index < 0 || index >= TABLE_SIZE (cipherNames))
        return NULL;

    return cipherNames [index];
}

sslCipherSuitePtr
sslGetCipherSuite (int index) {
    int i;

    for (i = 0; i < TABLE_SIZE (cipherSuites) ; i++) {
        if (cipherSuites [i].index == index)
            return &cipherSuites [i];
    }

    return NULL;
}
