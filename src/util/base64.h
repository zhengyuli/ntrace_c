#ifndef __WDM_AGENT_BASE64_H__
#define __WDM_AGENT_BASE64_H__

int
base64Encode (char *to, char *from, unsigned int len);
int
base64Decode (char *to, char *from, unsigned int len);

#endif /* __WDM_AGENT_BASE64_H__ */
