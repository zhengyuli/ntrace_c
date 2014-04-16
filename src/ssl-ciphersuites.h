#ifndef __WDM_AGENT_SS_CIPHERSUITES_H__
#define __WDM_AGENT_SS_CIPHERSUITES_H__

#define KEX_RSA     0x10
#define KEX_DH      0x11

#define SIG_RSA     0x20
#define SIG_DSS     0x21
#define SIG_NONE    0x22

#define ENC_DES     0x30
#define ENC_DES3    0x31
#define ENC_RC4     0x32
#define ENC_RC2     0x33
#define ENC_IDEA    0x34
#define ENC_NULL    0x35

#define DIG_MD5     0x40
#define DIG_SHA     0x41

typedef struct _sslCipherSuite sslCipherSuite;
typedef sslCipherSuite *sslCipherSuitePtr;

struct _sslCipherSuite {
    int index;
    int kex;
    int sig;
    int enc;
    int block;
    int bits;
    int effBits;
    int dig;
    int digLen;
    int export;
};

char *
sslGetDigestName (int dig);
char *
sslGetCipherName (int ciph);
sslCipherSuitePtr
sslGetCipherSuite (int index);

#endif /* __WDM_AGENT_SS_CIPHERSUITES_H__ */
