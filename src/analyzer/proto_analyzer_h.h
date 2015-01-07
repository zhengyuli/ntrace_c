/** 
 * @file proto_analyzer.h -*- c -*-
 * 
 * @brief agent proto analyzer interface
 * 
 * Time-stamp: <2015-01-07 13:34:57 Wednesday by lzy>
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

#ifndef __AGENT_PROTOCOL_H__
#define __AGENT_PROTOCOL_H__

#include <jansson.h>
#include "util.h"

typedef enum {
    STREAM_FROM_CLIENT = 0,
    STREAM_FROM_SERVER = 1
} streamDirection;

typedef enum {
    SESSION_ACTIVE = 0,
    SESSION_DONE = 1
} sessionState;

/* Protocol analyzer callback definition */
typedef int (*initProtoAnalyzerCB) (void);
typedef void (*destroyProtoAnalyzerCB) (void);
typedef void * (*newSessionDetailCB) (void);
typedef void (*freeSessionDetailCB) (void *sd);
typedef void * (*newSessionBreakdownCB) (void);
typedef void (*freeSessionBreakdownCB) (void *sbd);
typedef int (*generateSessionBreakdownCB) (void *sd, void *sbd);
typedef void (*sessionBreakdown2JsonCB) (json_t *root, void *sd, void *sbd);
typedef void (*sessionProcessEstbCB) (void *sd, timeValPtr tm);
typedef void (*sessionProcessUrgeDataCB) (streamDirection direction, char urgData, void *sd, timeValPtr tm);
typedef u_int (*sessionProcessDataCB) (streamDirection direction, u_char *data, u_int dataLen, void *sd,
                                       timeValPtr tm, sessionState *state);
typedef void (*sessionProcessResetCB) (streamDirection direction, void *sd, timeValPtr tm);
typedef void (*sessionProcessFinCB) (streamDirection direction, void *sd, timeValPtr tm, sessionState *state);

typedef struct _protoAnalyzer protoAnalyzer;
typedef protoAnalyzer *protoAnalyzerPtr;

/* Proto analyzer callback */
struct _protoAnalyzer {
    char proto [32];                                     /**< Protocol type */
    initProtoAnalyzerCB initProtoAnalyzer;               /**< Protocol init callback */
    destroyProtoAnalyzerCB destroyProtoAnalyzer;         /**< Protocol destroy callback */
    newSessionDetailCB newSessionDetail;                 /**< Create new session detail callback */
    freeSessionDetailCB freeSessionDetail;               /**< Free session detail callback */
    newSessionBreakdownCB newSessionBreakdown;           /**< Create new session breakdown callback */
    freeSessionBreakdownCB freeSessionBreakdown;         /**< Free session breakdown callback */
    generateSessionBreakdownCB generateSessionBreakdown; /**< Generate session breakdown callback */
    sessionBreakdown2JsonCB sessionBreakdown2Json;       /**< Translate session breakdown to json callback */
    sessionProcessEstbCB sessionProcessEstb;             /**< Tcp establishment callback */
    sessionProcessUrgeDataCB sessionProcessUrgData;      /**< Urgency data processing callback */
    sessionProcessDataCB sessionProcessData;             /**< Data processing callback */
    sessionProcessResetCB sessionProcessReset;           /**< Tcp reset processing callback */
    sessionProcessFinCB sessionProcessFin;               /**< Tcp fin processing callback */
};

#endif /* __AGENT_PROTOCOL_H__ */
