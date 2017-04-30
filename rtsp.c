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

#include "rtsp.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#if LWIP_TCP

#ifndef RTSP_DEBUG
#define RTSP_DEBUG     LWIP_DBG_ON
#endif

#define CRLF           "\r\n"

#define RTSP_STATUS_OK 200

static err_t tcp_send_packet(RTSPSession *session, const char *packet);
static u8_t starts_with(const char *str, const char *pfx, const char **ptr);
static const char *find_line_break(const char *buffer);
static void rtsp_parse_line(RTSPHeader *reply, const char *buf);
static const char *rtsp_parse_response(RTSPHeader *reply, const char *response);
static err_t send_packet(RTSPSession *session, const char *command);
static err_t send_next_packet(RTSPSession *session);
static err_t receive_response(RTSPSession *session, char *server_reply);
static err_t parse_url(RTSPSession *session, const char *uri);
static err_t rtsp_connected_clbk(void *arg, struct tcp_pcb *tpcb, err_t err);
static err_t rtsp_recvd_clbk(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void rtsp_error_clbk(void *arg, err_t err);
static err_t disconnect_server(RTSPSession *session);
static err_t connect_server(RTSPSession *session);

static err_t tcp_send_packet(RTSPSession *session, const char *packet) {
    err_t result;

    LWIP_ASSERT("session != NULL", session != NULL);

    if ((result = tcp_write(session->pcb, packet, strlen(packet), TCP_WRITE_FLAG_COPY)) != ERR_OK) {
        LWIP_DEBUGF(RTSP_DEBUG, ("tcp_send_packet: Write error %d\n", result));
        return result;
    }

    if ((result = tcp_output(session->pcb)) != ERR_OK) {
        LWIP_DEBUGF(RTSP_DEBUG, ("tcp_send_packet: Output error %d\n", result));
        return result;
    }

    return ERR_OK;
}

static u8_t starts_with(const char *str, const char *pfx, const char **ptr) {
    while (*pfx && toupper(*pfx) == toupper(*str)) {
        pfx++;
        str++;
    }

    if (!*pfx && ptr)
        *ptr = str;

    return !*pfx;
}

static const char *find_line_break(const char *buffer) {
    const char *pt = buffer;

    LWIP_ASSERT("buffer != NULL", buffer != NULL);

    while(*pt != '\0' && strncmp(pt, CRLF, 2) != 0) {
        ++pt;
    }

    if(*pt == '\0')
        return NULL;

    return pt + 2;
}

static void rtsp_parse_line(RTSPHeader *reply, const char *buf) {
    const char *p;

    LWIP_ASSERT("reply != NULL", reply != NULL);

    if (starts_with(buf, "Session:", &p)) {
        reply->session_id = strtol(p, NULL, 10);
    } else if (starts_with(buf, "Content-Length:", &p)) {
        reply->content_length = strtol(p, NULL, 10);
    } else if (starts_with(buf, "CSeq:", &p)) {
        reply->c_seq = strtol(p, NULL, 10);
    } else if (starts_with(buf, "RTSP/1.0", &p)) {
        reply->status_code = strtol(p, NULL, 10);
    }
}

static const char *rtsp_parse_response(RTSPHeader *reply, const char *response) {
    const char *line_break;
    const char *pt = response;

    LWIP_ASSERT("reply != NULL", reply != NULL);
    LWIP_ASSERT("response != NULL", response != NULL);

    while(pt) {
        rtsp_parse_line(reply, pt);
        line_break = find_line_break(pt);

        if(line_break == pt + 2) // Empty line
            return line_break;

        pt = line_break;
    }

    return NULL;
}

struct tcp_pcb *testpcb;

static err_t send_packet(RTSPSession *session, const char *command) {
    char packet[256];

    LWIP_ASSERT("session != NULL", session != NULL);
    LWIP_ASSERT("command != NULL", command != NULL);

    sprintf(packet, "%s %s RTSP/1.0" CRLF "CSeq: %d" CRLF,
            command,
            session->uri,
            ++session->c_seq);

    // Include session id if the session is set up
    if(session->state > DESCRIBE) {
        LWIP_ASSERT("session->session_id != 0", session->session_id != 0);

        sprintf(packet + strlen(packet), "Session: %ld" CRLF, session->session_id);
    }

    sprintf(packet + strlen(packet), CRLF);

    return tcp_send_packet(session, packet);
}

static err_t send_next_packet(RTSPSession *session) {
    err_t res;

    LWIP_ASSERT("session != NULL", session != NULL);

    switch(session->state) {
    case INIT:
        res = send_packet(session, "OPTIONS");
        session->requested_state = OPTIONS;
        break;
    case OPTIONS:
        res = send_packet(session, "DESCRIBE");
        session->requested_state = DESCRIBE;
        break;
    case DESCRIBE:
        res = send_packet(session, "SETUP");
        session->requested_state = SETUP;
        break;
    default:
        res = ERR_VAL;
    }

    return res;
}

static err_t receive_response(RTSPSession *session, char *server_reply) {
    RTSPHeader reply;
    const char *header_end;

    LWIP_ASSERT("session != NULL", session != NULL);
    LWIP_ASSERT("server_reply != NULL", server_reply != NULL);

    memset(&reply, 0, sizeof(RTSPHeader));

    header_end = rtsp_parse_response(&reply, server_reply);

    if(reply.c_seq != session->c_seq) {
        /* Maybe server sent something without our request ? */
        LWIP_DEBUGF(RTSP_DEBUG, ("start_rtsp: Sequence numbers do not match\n"));
        return -1;
    }

    if(reply.status_code != RTSP_STATUS_OK) {
        LWIP_DEBUGF(RTSP_DEBUG, ("start_rtsp: Server denied %d\n", reply.status_code));
        return -1;
    }

    session->state = session->requested_state;

    if(session->state == DESCRIBE) {
        if(header_end != NULL) {
            //LWIP_DEBUGF(RTSP_DEBUG, ("SDP :\n"));
            //LWIP_DEBUGF(RTSP_DEBUG, ("%s\n", header_end));

            // TODO : Do something with the payload
        }
    }

    if(session->state == SETUP) {
        session->session_id = reply.session_id;
    } else if(session->state > SETUP) {
        if(session->session_id != reply.session_id) {
            LWIP_DEBUGF(RTSP_DEBUG, ("receive_response: Wrong session ID\n"));
            return -1;
        }
    }

    return ERR_OK;
}

err_t rtsp_play(RTSPSession *session) {
    LWIP_ASSERT("session != NULL", session != NULL);

    if(session->state != SETUP && session->state != PAUSE) {
        LWIP_DEBUGF(RTSP_DEBUG, ("rtsp_play: Session is not ready\n"));
        return -1;
    }

    if(send_packet(session, "PLAY") < 0) {
        LWIP_DEBUGF(RTSP_DEBUG, ("rtsp_play: Send error\n"));
        return -1;
    }

    session->requested_state = PLAY;

    return ERR_OK;
}

err_t rtsp_pause(RTSPSession *session) {
    LWIP_ASSERT("session != NULL", session != NULL);

    if(session->state != PLAY) {
        LWIP_DEBUGF(RTSP_DEBUG, ("rtsp_pause: Session is not playing\n"));
        return -1;
    }

    if(send_packet(session, "PAUSE") < 0) {
        LWIP_DEBUGF(RTSP_DEBUG, ("rtsp_pause: Send error\n"));
        return -1;
    }

    session->requested_state = PAUSE;

    return ERR_OK;
}

err_t rtsp_teardown(RTSPSession *session) {
    LWIP_ASSERT("session != NULL", session != NULL);

    if(session->state < PLAY || session->state > PAUSE) {
        LWIP_DEBUGF(RTSP_DEBUG, ("rtsp_teardown: Session is not ready\n"));
        return -1;
    }

    if(send_packet(session, "TEARDOWN") < 0) {
        LWIP_DEBUGF(RTSP_DEBUG, ("rtsp_teardown: Send error\n"));
        return -1;
    }

    return disconnect_server(session);
}

static err_t parse_url(RTSPSession *session, const char *uri) {
    /* Need a real parser ! */
    err_t res;
    u16_t scanned;

    LWIP_ASSERT("session != NULL", session != NULL);

    char ip_address[16];

    scanned = sscanf(uri, "rtsp://%99[^:]:%99hu/%99[^\n]",
            ip_address,
            &session->port,
            session->uri);

    if(scanned != 3) {
        LWIP_DEBUGF(RTSP_DEBUG, ("parse_url: Malformed URL\n"));

        return ERR_ARG;
    }

    res = ipaddr_aton(ip_address, &session->ip);
    if(res != 1) {
        LWIP_DEBUGF(RTSP_DEBUG, ("parse_url: Malformed URL\n"));

        return ERR_ARG;
    }

    return ERR_OK;
}

static err_t rtsp_connected_clbk(void *arg, struct tcp_pcb *tpcb, err_t err) {
    RTSPSession *session = (RTSPSession *)arg;

    LWIP_ASSERT("session != NULL", session != NULL);
    LWIP_DEBUGF(RTSP_DEBUG, ("Connection Established.\n"));

    send_next_packet(session);

    return ERR_OK;
}

static err_t rtsp_recvd_clbk(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    RTSPSession *session = (RTSPSession *)arg;

    LWIP_ASSERT("session != NULL", session != NULL);

    if (p) {
        LWIP_DEBUGF(RTSP_DEBUG, ("Contents of pbuf %s\n", (char *)p->payload));

        struct pbuf *q;
        char *text = malloc(p->tot_len + 1);
        char *pt = text;

        for (q = p; q != NULL; q = q->next) {
            memcpy(pt, q->payload, q->len);
            pt += q->len;
        }
        *pt = '\0';

        /* Inform TCP that we have taken the data */
        tcp_recved(session->pcb, p->tot_len);

        receive_response(session, text);

        free(text);

        if(session->state == SETUP)
            return ERR_OK;

        send_next_packet(session);
    } else {
        LWIP_DEBUGF(RTSP_DEBUG, ("rtsp_recvd_clbk: Host closed the connection\n"));

        disconnect_server(session);

        return ERR_ABRT;
    }

    return ERR_OK;
}

static void rtsp_error_clbk(void *arg, err_t err) {
    RTSPSession *session = (RTSPSession *)arg;

    LWIP_ASSERT("session != NULL", session != NULL);

    disconnect_server(session);
}

static err_t disconnect_server(RTSPSession *session) {
    tcp_arg(session->pcb, NULL);
    tcp_sent(session->pcb, NULL);
    tcp_recv(session->pcb, NULL);
    tcp_close(session->pcb);

    memset(session, 0, sizeof(RTSPSession));

    return ERR_OK;
}

static err_t connect_server(RTSPSession *session) {
    LWIP_ASSERT("session != NULL", session != NULL);

    tcp_err(session->pcb, rtsp_error_clbk);
    tcp_recv(session->pcb, rtsp_recvd_clbk);
    tcp_connect(session->pcb, &session->ip, session->port, rtsp_connected_clbk);

    return ERR_OK;
}

err_t rtsp_setup(RTSPSession *session, const char *uri) {
    err_t res;

    LWIP_ASSERT("session != NULL", session != NULL);

    if(session->state > INIT) {
        LWIP_DEBUGF(RTSP_DEBUG, ("rtsp_setup: Already connected\n"));
        return ERR_ISCONN;
    }

    memset(session, 0, sizeof(RTSPSession));

    session->pcb = tcp_new();
    tcp_arg(session->pcb, session);

    if((res = parse_url(session, uri)) != ERR_OK) {
        LWIP_DEBUGF(RTSP_DEBUG, ("start_rtsp: Invalid address : %d\n", res));
        return res;
    }

    if((res = connect_server(session)) != ERR_OK) {
        LWIP_DEBUGF(RTSP_DEBUG, ("start_rtsp: Connect error : %d\n", res));
        return res;
    }

    return ERR_OK;
}

#endif /* LWIP_TCP */
