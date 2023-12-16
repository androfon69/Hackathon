// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"

int create_socket(void)
{
	/* TODO: Implement create_socket(). */
	int sock_fd;

	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ERR(sock_fd < 0, "Coudln't connect to socket.\n");

	return sock_fd;
}

int connect_socket(int fd)
{
	/* TODO: Implement connect_socket(). */
	int rc;
	struct sockaddr_un addr;

	rc = access(SOCKET_NAME, R_OK | W_OK);
	if (rc < 0) {
		perror("Couldn't access socket\n");
		return rc;
	}

	/* populate socket */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(SOCKET_NAME), "%s", SOCKET_NAME);
	rc = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	ERR(rc < 0, "Couldn't connect to socket.\n");

	return rc;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	/* TODO: Implement send_socket(). */
	ssize_t bytes_sent;

	bytes_sent = send(fd, buf, len, 0);

	return bytes_sent;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* TODO: Implement recv_socket(). */
	ssize_t bytes_received;

	bytes_received = recv(fd, buf, len, 0);

	return bytes_received;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */
	int rc;
	rc = close(fd);
	ERR(rc < 0, "Couldn't close socket.\n");
}
