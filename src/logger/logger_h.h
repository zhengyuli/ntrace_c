/** 
 * @file logger.h -*- c -*-
 * 
 * @brief agent logger interface
 * 
 * Time-stamp: <2015-01-07 13:35:51 Wednesday by lzy>
 * 
 * Copyright (c) 2011-2012, zhengyu li <lizhengyu419@gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without" 
 * modification, are permitted provided that the following conditions are met:
 * 
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __AGENT_LOGGER_H__
#define __AGENT_LOGGER_H__

#include <stdlib.h>

/* Log level tag */
#define LOG_ERR_TAG "<0>"       /* Error message */
#define LOG_WARNING_TAG "<1>"   /* Warning message */
#define LOG_INFO_TAG "<2>"      /* Normal information */
#define LOG_DEBUG_TAG "<3>"     /* Debug information */

/*========================Interfaces definition============================*/
void
logToConsole (const char *msg, ...);
void
doLog (char *filePath, u_int line, const char *func, const char *msg, ...);

#define LOGE(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_ERR_TAG __VA_ARGS__)
#define LOGW(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_WARNING_TAG __VA_ARGS__)
#define LOGI(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_INFO_TAG __VA_ARGS__)
#ifdef NDEBUG
#define LOGD(...)
#else
#define LOGD(...) doLog (__FILE__, __LINE__, __FUNCTION__, LOG_DEBUG_TAG __VA_ARGS__)
#endif
/*=======================Interfaces definition end=========================*/

#endif /* __AGENT_LOGGER_H__ */
