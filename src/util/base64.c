#include <string.h>

static char base64String [] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define BAD_CHAR(c, p) (!(p = memchr (base64String, c, 64)))

/*
 * @brief Encode binary data to base64
 *
 * @param to dest addr to store encoded data
 * @param from binary data to encode
 * @param len length of binary data to encode
 *
 * @return length of encoded data
 */
u_int
base64Encode (u_char *to, const u_char *from, u_int len) {
    const u_char *fromp = from;
    u_char *top = to;
    u_char cbyte;
    u_char obyte;
    u_char end [3];

    for (; len >= 3; len -= 3) {
        cbyte = *fromp++;
        *top++ = base64String [(int)(cbyte >> 2)];
        obyte = (cbyte << 4) & 0x30;        /* 0011 0000 */

        cbyte = *fromp++;
        obyte |= (cbyte >> 4);          /* 0000 1111 */
        *top++ = base64String [(int) obyte];
        obyte = (cbyte << 2) & 0x3C;        /* 0011 1100 */

        cbyte = *fromp++;
        obyte |= (cbyte >> 6);          /* 0000 0011 */
        *top++ = base64String [(int) obyte];
        *top++ = base64String [(int) (cbyte & 0x3F)];/* 0011 1111 */
    }

    if (len) {
        end [0] = *fromp++;
        if (--len)
            end [1] = *fromp++;
        else
            end [1] = 0;
        end [2] = 0;

        cbyte = end [0];
        *top++ = base64String [(int) (cbyte >> 2)];
        obyte = (cbyte << 4) & 0x30;        /* 0011 0000 */

        cbyte = end [1];
        obyte |= (cbyte >> 4);
        *top++ = base64String [(int) obyte];
        obyte = (cbyte << 2) & 0x3C;        /* 0011 1100 */

        if (len)
            *top++ = base64String [(int) obyte];
        else
            *top++ = '=';
        *top++ = '=';
    }
    
    *top = 0;
    
    return top - to;
}

/*
 * @brief Decode base64 data
 *
 * @param to addr to store decode data
 * @param from data to decode
 * @param len length of base64 encoded data
 *
 * @return length of decoded data if success else return 0
 */
u_int
base64Decode (u_char *to, const u_char *from, u_int len) {
    u_char *fromp = from;
    u_char *top = to;
    u_char *p;
    u_char cbyte;
    u_char obyte;
    int padding = 0;

    for (; len >= 4; len -= 4) {
        if ((cbyte = *fromp++) == '=')
            cbyte = 0;
        else {
            if (BAD_CHAR (cbyte, p))
                return 0;
            cbyte = (p - base64String);
        }
        obyte = cbyte << 2;     /* 1111 1100 */

        if ((cbyte = *fromp++) == '=')
            cbyte = 0;
        else {
            if (BAD_CHAR (cbyte, p))
                return 0;
            cbyte = p - base64String;
        }
        obyte |= cbyte >> 4;        /* 0000 0011 */
        *top++ = obyte;

        obyte = cbyte << 4;     /* 1111 0000 */
        if ((cbyte = *fromp++) == '=') {
            cbyte = 0;
            padding++;
        } else {
            padding = 0;
            if (BAD_CHAR (cbyte, p))
                return 0;
            cbyte = p - base64String;
        }
        obyte |= cbyte >> 2;        /* 0000 1111 */
        *top++ = obyte;

        obyte = cbyte << 6;     /* 1100 0000 */
        if ((cbyte = *fromp++) == '=') {
            cbyte = 0;
            padding++;
        } else {
            padding = 0;
            if (BAD_CHAR (cbyte, p))
                return 0;
            cbyte = p - base64String;
        }
        obyte |= cbyte;         /* 0011 1111 */
        *top++ = obyte;
    }

    *top = 0;
    if (len)
        return 0;
    else
        return (top - to - padding);
}
