#ifndef __AGENT_BASE64_H__
#define __AGENT_BASE64_H__

u_int
base64Encode (u_char *to, const u_char *from, u_int len);
u_int
base64Decode (u_char *to, const u_char *from, u_int len);

#endif /* __AGENT_BASE64_H__ */
