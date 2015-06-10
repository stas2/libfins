/*
    libfins
    
    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
    MA  02110-1301  USA
*/

#include "fins.h"
#include <malloc.h>
#include <string.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>

#if defined(_WIN32)
# define OS_WIN32
/* ws2_32.dll has getaddrinfo and freeaddrinfo on Windows XP and later.
 * minwg32 headers check WINVER before allowing the use of these */
# ifndef WINVER
# define WINVER 0x0501
# endif
# include <ws2tcpip.h>
# define SHUT_RDWR 2
# define close closesocket
#else
# include <sys/socket.h>
# include <sys/ioctl.h>

#if defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD__ < 5)
# define OS_BSD
# include <netinet/in_systm.h>
#endif

# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
//# include <poll.h>
//# include <netdb.h>
#include <net/if.h>
#include <errno.h>
#endif


#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#define MAX_MSG 2010
#define MAX_HEADER 32


struct fins_t
{
	int sockfd;

	unsigned char srv_node_no, cli_node_no;
	char sid;
	char ip[16];
	int port;

	struct timeval response_timeout;

	int debug;

	unsigned char fins_cmnd[MAX_MSG + MAX_HEADER], fins_resp[MAX_MSG + MAX_HEADER]; //, fins_tcp_header[MAX_HEADER];
};

struct fins_t *fins_new_tcp(const char* ip, const int port)
{
	struct fins_t *c = (struct fins_t*)malloc(sizeof(struct fins_t));
	if (!c)
		return 0;

	memset(c, 0, sizeof(*c));
	c->sockfd = -1;
	c->sid = 0;
	strncpy(c->ip, ip, sizeof(c->ip) - 1);
	c->port = port;

	c->response_timeout.tv_sec = 0;
	c->response_timeout.tv_usec = 500000;

	return c;
}

/*
* TCP RECEIVE PROCESSING (RECEIVE REPEATED UP TO THE SPECIFIED NUMBER OF BYTES)
*/
static int tcp_recv(int sockfd, unsigned char *buf, int len)
{
	int total_len = 0;
	int recv_len;

	for (;;)
	{
		recv_len = recv(sockfd, (char *)buf, len, 0);

		if (recv_len > 0)
		{
			if (recv_len < (int)len)
			{
				len -= recv_len;
				buf += recv_len;
				total_len += recv_len;
			}
			else
			{
				total_len += recv_len;
				break;
			}
		}
		else
		{
			total_len = 0;
			break;
		}
	}

	return total_len;

}

#ifdef OS_WIN32
static int _fins_tcp_init_win32(void)
{
	/* Initialise Windows Socket API */
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup() returned error code %d\n", (unsigned int)GetLastError());
		return -1;
	}
	return 0;
}
#endif

static int tcp_set_ipv4_options(struct fins_t *c)
{
	int rc;
	int option;
	int sockfd = c->sockfd;

	/* Set the TCP no delay flag */
	/* SOL_TCP = IPPROTO_TCP */
	option = 1;
	rc = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const void *)&option, sizeof(int));
	if (rc == -1) {
		return -1;
	}

#if _WIN32
	int ms = c->response_timeout.tv_sec * 1000 + c->response_timeout.tv_usec / 1000;
	rc = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof(ms));
#else
	rc = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &c->response_timeout, sizeof(struct timeval));
#endif
	if (rc == -1) {
		return -1;
	}

#ifndef OS_WIN32
	/**
     * Cygwin defines IPTOS_LOWDELAY but can't handle that flag so it's
     * necessary to workaround that problem.
     **/
	/* Set the IP low delay option */
	option = IPTOS_LOWDELAY;
	rc = setsockopt(sockfd, IPPROTO_IP, IP_TOS,
			(const void *)&option, sizeof(int));
	if (rc == -1) {
		return -1;
	}
#endif

	return 0;
}

static void printarray(uint8_t *data, ssize_t len)
{
	uint8_t *p = data;
	for (ssize_t i = len; i; --i, ++p) {
		fprintf(stderr, " %02x", *p);
	}
	fprintf(stderr, "\n");
}

int fins_connect(struct fins_t *c)
{ 
	struct sockaddr_in cs_addr;
	unsigned char *fins_tcp_header = c->fins_cmnd;

#ifdef OS_WIN32
	if (_fins_tcp_init_win32() == -1) {
		return -1;
	}
#endif

	/*GENERATE TCP SOCKET*/
	if ((c->sockfd = socket(AF_INET,SOCK_STREAM,0)) < 0) {
		if (c->debug)
			fprintf(stderr, "can't open stream socket\n");
		return -1;
	}

	if (tcp_set_ipv4_options(c) == -1) {
		return -1;
	}

//	/*ALLOCATE IP ADDRESS AND PORT # TO SOCKET*/
//	memset(&ws_addr, 0, sizeof(ws_addr));
//	ws_addr.sin_family = AF_INET;
//	ws_addr.sin_addr.s_addr = htonl(INADDR_ANY);
//	ws_addr.sin_port = htons(0); /*ASSIGN LOCAL TCP PORT NUMBER*/

//	if (bind(c->sockfd,(struct sockaddr *)&ws_addr,sizeof(ws_addr)) < 0) {
//		fprintf(stderr, "can't bind local address\n");
//		close(c->sockfd);
//		c->sockfd = -1;
//		return 0;
//	}

	/* ESTABLISH CONNECTION WITH FINS/TCP SERVER*/
	memset(&cs_addr, 0, sizeof(cs_addr));
	cs_addr.sin_family = AF_INET;
	cs_addr.sin_addr.s_addr = inet_addr(c->ip);
	cs_addr.sin_port = htons(c->port);

	if (connect(c->sockfd,(struct sockaddr *)&cs_addr,sizeof(cs_addr)) < 0) {
		if (c->debug)
			fprintf(stderr, "can't connect to FINS/TCP server\n");
		return -1;
	}

	/* SEND FINS/TCP COMMAND*/
	/*
	* GENERATE FINS NODE NUMBER DATA SEND COMMAND (CLIENT TO SERVER)
	*/
	fins_tcp_header[0] = 'F'; /* Header */
	fins_tcp_header[1] = 'I';
	fins_tcp_header[2] = 'N';
	fins_tcp_header[3] = 'S';
	fins_tcp_header[4] = 0x00; /* Length */
	fins_tcp_header[5] = 0x00;
	fins_tcp_header[6] = 0x00;
	fins_tcp_header[7] = 0x0C;
	fins_tcp_header[8] = 0x00; /* Command */
	fins_tcp_header[9] = 0x00;
	fins_tcp_header[10] = 0x00;
	fins_tcp_header[11] = 0x00;
	fins_tcp_header[12] = 0x00; /* Error Code */
	fins_tcp_header[13] = 0x00;
	fins_tcp_header[14] = 0x00;
	fins_tcp_header[15] = 0x00;
	fins_tcp_header[17] = 0x00; /* Client Node Add */
	fins_tcp_header[18] = 0x00;
	fins_tcp_header[19] = 0x00;
	fins_tcp_header[20] = 0x00; /*AUTOMATICALLY GET FINS CLIENT FINS NODE NUMBER*/

	/*SEND FINS/TCP COMMAND*/
	ssize_t sendlen = 20;

	if (send(c->sockfd, (char *)fins_tcp_header,sendlen, MSG_NOSIGNAL) != sendlen) {
		if (c->debug)
			fprintf(stderr, "FINS/TCP header send error\n");
		return -1;
	}

	if (c->debug)
		fprintf(stderr, "FINS/TCP header send length %ld\n", (long)sendlen);

	/*RECEIVE FINS/TCP COMMAND (READ RECEIVE FUNCTIONS)*/
	ssize_t recvlen = 24;
	if (tcp_recv(c->sockfd, fins_tcp_header, recvlen) != recvlen) {
		if (c->debug)
			fprintf(stderr, "TCP receive error\n");
		return -1;
	}

	if (c->debug) {
		fprintf(stderr, "Received header:");
		printarray(fins_tcp_header, recvlen);
	}

	/* CONFIRM WHETHER FINS NODE NUMBER SEND COMMAND (CLIENT TO SERVER) WAS RECEIVED*/
	if ((fins_tcp_header[8] != 0x00) || (fins_tcp_header[9] != 0x00) ||
			(fins_tcp_header[10] != 0x00) || (fins_tcp_header[11] != 0x01))
	{
#ifdef _WIN32
		SetLastError(ERROR_INVALID_DATA);
#else
		errno = EINVAL;
#endif
		if (c->debug)
			fprintf(stderr, "FINS/TCP illegal commmand error\n");
		return -1;
	}

	c->cli_node_no = fins_tcp_header[19];
	c->srv_node_no = fins_tcp_header[23];

	if (c->debug) {
		fprintf(stderr, "FINS/TCP header receive length %ld\n", (long)recvlen);
		fprintf(stderr, "FINS/TCP client Node No. = %d\n", c->cli_node_no);
		fprintf(stderr, "FINS/TCP server Node No. = %d\n", c->srv_node_no);
	}

	return 0;
}

static int fins_command(struct fins_t *c, uint8_t mrc, uint8_t src, const int type, const int address, const int nb, const int isize, const uint16_t *idata, const int osize, uint16_t *odata)
{
	unsigned char *fins_tcp_req_header = c->fins_cmnd;
	unsigned char *fins_cmnd = c->fins_cmnd + 16;
	unsigned char *fins_tcp_resp_header = c->fins_resp;
	unsigned char *fins_resp = c->fins_resp + 16;

	/* SEND FINS/TCP COMMAND*/
	/*
	* GENERATE FINS COMM AND FRAME
	*/
	fins_tcp_req_header[0] = 'F'; /* Header */
	fins_tcp_req_header[1] = 'I';
	fins_tcp_req_header[2] = 'N';
	fins_tcp_req_header[3] = 'S';

	fins_tcp_req_header[4] = 0x00; /* Length */
	fins_tcp_req_header[5] = 0x00;
//	fins_tcp_header[6] = 0x00;
//	fins_tcp_header[7] = 8+18; /*Length of data from Command up to end of FINS frame */

	fins_tcp_req_header[8] = 0x00; /* Command (4 bytes) - FINS FRAME SEND (2) */
	fins_tcp_req_header[9] = 0x00;
	fins_tcp_req_header[10] = 0x00;
	fins_tcp_req_header[11] = 0x02;

	fins_tcp_req_header[12] = 0x00; /* Error Code */
	fins_tcp_req_header[13] = 0x00;
	fins_tcp_req_header[14] = 0x00;
	fins_tcp_req_header[15] = 0x00;

//	/* SEND FINS/TCP COMMAND*/
//	ssize_t sendlen = 16;
//	if (send(c->sockfd, (char *)fins_tcp_header,sendlen, MSG_NOSIGNAL) != sendlen) {
//		fprintf(stderr, "FINS/TCP header send error\n");
//		return -1;
//	}

//	fprintf(stderr, "FINS/TCP header send length %ld\n", (long)sendlen);


	/* SEND FINS COMMAND FRAME*/
	/*
	* GENERATE MEMORY AREA COMMAND
	*/
	fins_cmnd[0] = 0x80; /* ICF */
	fins_cmnd[1] = 0x00; /* RSV */
	fins_cmnd[2] = 0x02; /* GCT */

	fins_cmnd[3] = 0x00; /* DNA */
	fins_cmnd[4] = c->srv_node_no; /* DA1 */ /*Ethernet Unit FINS NODE NUMBER*/
	fins_cmnd[5] = 0x00; /* DA2 */

	fins_cmnd[6] = 0x00; /* SNA */
	fins_cmnd[7] = c->cli_node_no; /* SA1 */ /*WS FINS NODE NUMBER OBTAINED AUTOMATICALLY*/
	fins_cmnd[8] = 0x00; /* SA2 */

	fins_cmnd[9] = ++c->sid; /* SID */

	fins_cmnd[10] = mrc; /* MRC */
	fins_cmnd[11] = src; /* SRC */
	fins_cmnd[12] = type; /* VARIABLE TYPE: DM*/
	fins_cmnd[13] = (uint8_t)((address & 0xFF00) >> 8); /* READ START ADDRESS */
	fins_cmnd[14] = (uint8_t)(address & 0x00FF);
	fins_cmnd[15] = 0x00;
	fins_cmnd[16] = (uint8_t)((nb & 0xFF00) >> 8); /* WORDS READ */
	fins_cmnd[17] = (uint8_t)(nb & 0x00FF);

	uint8_t *p_cmnd = fins_cmnd + 18;
	const uint16_t *p_idata = idata;
	for (int i = isize; i; --i) {
		uint16_t value = *p_idata++;
		*p_cmnd++ = (uint8_t)((value & 0xFF00) >> 8);
		*p_cmnd++ = (uint8_t)(value & 0x00FF);
	}

	/* SEND FINS COMMAND FRAME*/
//	signal(SIGALRM,recv_fail);

	ssize_t sendlen = 8 + 18 + isize * 2;

	fins_tcp_req_header[6] = (uint8_t)(sendlen >> 8);
	fins_tcp_req_header[7] = (uint8_t)(sendlen); /*Length of data from Command up to end of FINS frame */

	sendlen += 8;

	if (c->debug) {
		fprintf(stderr, "Sending:");
		printarray(c->fins_cmnd, sendlen);
	}

	if (send(c->sockfd, (char *)c->fins_cmnd, sendlen, MSG_NOSIGNAL) != sendlen) {
		if (c->debug)
			fprintf(stderr, "send error\n");
		return -1;
	}

	if (c->debug)
		fprintf(stderr, "send length %ld\n", (long)sendlen);

	/* RECEIVE FINS/TCP COMMAND (READ RECEIVE FUNCTIONS)*/
	ssize_t recvlen = 16;
	if (tcp_recv(c->sockfd, fins_tcp_resp_header, recvlen) != recvlen) {
		if (c->debug)
			fprintf(stderr, "TCP receive error\n");
		return -1;
	}

	if (c->debug) {
		fprintf(stderr, "Received:");
		printarray(fins_tcp_resp_header, recvlen);
	}

	/* CONFIRM WHETHER FINS FRAME SEND COMMAND WAS RECEIVED*/
	if ((fins_tcp_resp_header[8] != 0x00) || (fins_tcp_resp_header[9] != 0x00) ||
	   (fins_tcp_resp_header[10] != 0x00) || (fins_tcp_resp_header[11] != 0x02  && fins_tcp_resp_header[11] != 0x1))
	{
#ifdef _WIN32
		SetLastError(ERROR_INVALID_DATA);
#else
		errno = EINVAL;
#endif
		if (c->debug)
			fprintf(stderr, "FINS/TCP illegal commmand error");
		return -1;
	}

	if (c->debug)
		fprintf(stderr, "FINS/TCP header receive length %ld\n", (long)recvlen);

	recvlen = fins_tcp_resp_header[6];
	recvlen <<=8;
	recvlen |= fins_tcp_resp_header[7];
	recvlen -= 8; /* SUBTRACT LENGTH OF COMMAND & ERROR CODE OF FINS/TCP HEADER*/

	if (c->debug)
		fprintf(stderr, "FINS/TCP frame receive length %ld\n", (long)recvlen);

	/* RECEIVE FINS RESPONSE FRAME*/
	if (tcp_recv(c->sockfd, fins_resp, recvlen) != recvlen) {
		fprintf(stderr, "receive error\n");
		return -1;
	}

	if (c->debug)
		fprintf(stderr, "recv length %ld\n", (long)recvlen);

	if (recvlen < 14) {
#ifdef _WIN32
		SetLastError(ERROR_INVALID_DATA);
#else
		errno = EINVAL;
#endif
		/*ILLEGAL RESPONSE LENGTH CHECK*/
		if (c->debug)
			fprintf(stderr, "FINS length error\n");
		return -1;
	}

	if ((fins_cmnd[3] != fins_resp[6])
	 || (fins_cmnd[4] != fins_resp[7])
	 || (fins_cmnd[5] != fins_resp[8]) )
	{
#ifdef _WIN32
		SetLastError(ERROR_INVALID_DATA);
#else
		errno = EINVAL;
#endif
		/*DESTINATION ADDRESS CHECK*/
		if (c->debug)
			fprintf(stderr, "illegal source address error\n");
		return -1;
	}

	if(fins_cmnd[9] != fins_resp[9]) {
#ifdef _WIN32
		SetLastError(ERROR_INVALID_DATA);
#else
		errno = EINVAL;
#endif
		/* SID CHECK */
		if (c->debug)
			fprintf(stderr, "illegal SID error\n");
		return -1;
	}

	ssize_t n = (recvlen - 14) / 2;
	if (osize < n) {
		n = osize;
	}

	uint16_t *p_odata = odata;
	uint8_t *p_resp = fins_resp + 14;
	for(int i = n; i; --i) {
		uint16_t value = *p_resp++ << 8;
		value |= *p_resp++;
		*p_odata++ = value;
	}

	return n;
}

int fins_read(struct fins_t *c, const int type, const int from,
		const int nb, short unsigned int* oData)
{
	return fins_command(c, 1, 1, type, from, nb, 0, NULL, nb, oData);
}

int fins_write(struct fins_t *c, const int type, const int from,
	       const int nb, const short unsigned int* iData)
{
	fins_command(c, 1, 2, type, from, nb, nb, iData, 0, NULL);
	return nb;
}

void fins_free(struct fins_t *c)
{
	free(c);
}

int fins_close(struct fins_t *c)
{
	shutdown(c->sockfd, SHUT_RDWR);
	close(c->sockfd);
	c->sockfd = -1;
	return 0;
}

int fins_flush(struct fins_t *c)
{
    int rc;
    int rc_sum = 0;

    do {
	/* Extract the garbage from the socket */
	char devnull[MAX_MSG];
#ifndef OS_WIN32
	rc = recv(c->sockfd, devnull, MAX_MSG, MSG_DONTWAIT);
#else
	/* On Win32, it's a bit more complicated to not wait */
	fd_set rfds;
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(c->sockfd, &rfds);
	rc = select(c->sockfd+1, &rfds, NULL, NULL, &tv);
	if (rc == -1) {
	    return -1;
	}

	if (rc == 1) {
	    /* There is data to flush */
	    rc = recv(c->sockfd, devnull, MAX_MSG, 0);
	}
#endif
	if (rc > 0) {
	    rc_sum += rc;
	}
    } while (rc == MAX_MSG);

    return rc_sum;
}


void fins_set_debug(struct fins_t *ctx, int debug)
{
	ctx->debug = debug;
}

void fins_set_response_timeout(struct fins_t *ctx, const struct timeval *timeout)
{
	ctx->response_timeout = *timeout;
}
