#ifndef __BASE64_H__
#define __BASE64_H__

#include <stdlib.h>

/*========================Interfaces definition============================*/
u_int
base64Encode (u_char *to, u_char *from, u_int len);
u_int
base64Decode (u_char *to, u_char *from, u_int len);
/*=======================Interfaces definition end=========================*/

#endif /* __BASE64_H__ */
