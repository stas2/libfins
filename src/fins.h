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

#ifndef __FINS_H_
#define __FINS_H_

#ifdef __cplusplus
extern "C" {
#endif 

struct fins_t;
struct timeval;

struct fins_t *fins_new_tcp(const char* ip, const int port);

void fins_set_response_timeout(struct fins_t *ctx, const struct timeval *timeout);

int fins_connect(struct fins_t *c);
int fins_close(struct fins_t *c);
int fins_read(struct fins_t *c, const int type, const int from, const int nb, unsigned short *oData);
int fins_write(struct fins_t *c, const int type, const int from, const int nb, const unsigned short *iData);

void fins_free(struct fins_t *c);
int fins_flush(struct fins_t *c);

void fins_set_debug(struct fins_t *ctx, int debug);

#ifdef __cplusplus
};
#endif

#endif // __FINS_H_
