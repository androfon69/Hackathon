// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"
#include "server.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */
	return 0;
}

static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */
	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	/* TODO: Implement lib_posthooks(). */
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	/* TODO: Implement server connection. */
	int ret, listen_fd, accept_fd;
	struct sockaddr_un addr, recv_addr;
	socklen_t recv_addr_len;
	struct lib lib;
	char buff[BUFSIZ];

	remove(SOCKET_NAME);

	listen_fd = create_socket();
	memset(&addr, 0, sizeof(addr));
	//snprintf(addr.sun_path, sizeof(SOCKET_NAME), "%s", SOCKET_NAME);
	strcpy(addr.sun_path, SOCKET_NAME);
	addr.sun_family = AF_UNIX;
	ret = bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr));
	DIE(ret < 0, "bind");

	ret = listen(listen_fd, MAX_CLIENTS);
	DIE(ret < 0, "listen");

	while (1) {
		/* TODO - get message from client */
		accept_fd = accept(listen_fd, (struct sockaddr *) &recv_addr, &recv_addr_len);
		DIE(accept_fd < 0, "accept");

		memset(buff, 0, BUFSIZ);
		ssize_t bytes_received = recv_socket(accept_fd, buff, BUFSIZ);
		
		send_socket(accept_fd, buff, bytes_received);

		printf("%s\n", buff);

		/* TODO - parse message with parse_command and populate lib */
		/* TODO - handle request from client */
		//ret = lib_run(&lib);
	}

	return 0;
}
