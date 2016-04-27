/**
 * Copyright 2014 Context Information Security
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>


#include <freerdp/utils/stream.h>
#include <freerdp/utils/memory.h>


typedef struct rdp_tcp rdpTcp;
struct rdp_tcp
{
        int sockfd;
        char ip_address[32];
        uint8 mac_address[6];
        struct rdp_settings* settings;
};


void tcp_get_ip_address(rdpTcp * tcp)
{
}

void tcp_get_mac_address(rdpTcp * tcp)
{
}

boolean tcp_connect(rdpTcp* tcp, const char* hostname, uint16 port)
{
    tcp->sockfd = -1;
    return true;
}

int tcp_read(rdpTcp* tcp, uint8* data, int length)
{
    int status;

    status = read(tcp->sockfd, data, length);

    if (status == 0)
    {
        /* Peer disconnected. */
        return -1;
    }
    else if (status < 0)
    {
        /* No data available */
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        perror("recv");
        return -1;
    }

    return status;
}

int tcp_write(rdpTcp* tcp, uint8* data, int length)
{
    return length;
}

boolean tcp_disconnect(rdpTcp * tcp)
{
    return true;
}

boolean tcp_set_blocking_mode(rdpTcp* tcp, boolean blocking)
{
    int flags;
    flags = fcntl(tcp->sockfd, F_GETFL);

    if (flags == -1)
    {
        printf("tcp_set_blocking_mode: fcntl failed.\n");
        return false;
    }

    if (blocking == true)
        fcntl(tcp->sockfd, F_SETFL, flags & ~(O_NONBLOCK));
    else
        fcntl(tcp->sockfd, F_SETFL, flags | O_NONBLOCK);

    return true;
}

boolean tcp_set_keep_alive_mode(rdpTcp* tcp)
{
    return true;
}

rdpTcp* tcp_new(rdpSettings* settings)
{
    rdpTcp* tcp;

    tcp = (rdpTcp*) xzalloc(sizeof(rdpTcp));

    if (tcp != NULL)
    {
        tcp->sockfd = -1;
        tcp->settings = settings;
    }

    return tcp;
}

void tcp_free(rdpTcp* tcp)
{
    if (tcp != NULL) xfree(tcp);
}
