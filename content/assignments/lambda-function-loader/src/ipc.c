// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"
#include "../utils/utils.h"

int create_socket(void)
{
	/* TODO: Implement create_socket(). */
	int sock_fd, rc;
	struct sockaddr_un addr;

	sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	DIE(sock_fd < 0, "socket");

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SOCKET_NAME);
	rc = bind(sock_fd, (struct sockaddr *) &addr, sizeof(addr));
	DIE(rc < 0, "bind");

	return sock_fd;
}

int connect_socket(int fd)
{
	/* TODO: Implement connect_socket(). */
	int connect_fd;
	struct sockaddr_un addr;
	socklen_t addr_len = sizeof(addr);

	connect_fd = accept(fd, (struct sockaddr *) &addr, &addr_len);
	DIE(connect_fd < 0, "accept");

	return connect_fd;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	/* TODO: Implement send_socket(). */
	ssize_t bytes_sent;

	bytes_sent = send(fd, buf, len, 0);
	DIE(bytes_sent < 0, "send");

	return bytes_sent;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* TODO: Implement recv_socket(). */
	ssize_t bytes_received;

	bytes_received = recv(fd, buf, len, 0);
	DIE(bytes_received < 0, "recv");

	return bytes_received;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */
	close(fd);
}
