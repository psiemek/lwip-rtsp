/*
 * Copyright (c) 2017 Murat Seker.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of the contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef _RTSP_H_
#define _RTSP_H_

#include "lwip/tcp.h"

enum RTSPStatusCode {
	RTSP_STATUS_OK             = 200,
	RTSP_STATUS_METHOD         = 405,
	RTSP_STATUS_BANDWIDTH      = 453,
	RTSP_STATUS_SESSION        = 454,
	RTSP_STATUS_STATE          = 455,
	RTSP_STATUS_AGGREGATE      = 459,
	RTSP_STATUS_ONLY_AGGREGATE = 460,
	RTSP_STATUS_TRANSPORT      = 461,
	RTSP_STATUS_INTERNAL       = 500,
	RTSP_STATUS_SERVICE        = 503,
	RTSP_STATUS_VERSION        = 505
};

enum State {
	INIT      = 0,
	OPTIONS,
	DESCRIBE,
	SETUP,
	PLAY,
	PAUSE
};

typedef struct RTSPHeader {
	int content_length;
	enum RTSPStatusCode status_code;
	int c_seq;
	long session_id;
} RTSPHeader;

typedef struct RTSPSession {
	int c_seq;
	char uri[256];
	enum State state;
	enum State requested_state;
	long session_id;
	ip4_addr_t ip;
	int port;
	struct tcp_pcb *pcb;
} RTSPSession;

err_t rtsp_setup(RTSPSession *session, const char *uri);
err_t rtsp_play(RTSPSession *session);
err_t rtsp_pause(RTSPSession *session);
err_t rtsp_teardown(RTSPSession *session);

}


#endif // _RTSP_H_
