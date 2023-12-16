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
	lib->handle = dlopen(lib->libname, RTLD_LAZY);
	if (lib->handle == NULL) {
		return -1;
	}

	if (!strlen(lib->funcname)) {
		strcpy(lib->funcname, "run");
	}

	void *addr_func = dlsym(lib->handle, lib->funcname);
	if (addr_func == NULL) {
		return -1;
	}

	if (strlen(lib->filename)) {
		lib->p_run = addr_func;
		lib->run = NULL;
	} else {
		lib->p_run = NULL;
		lib->run = addr_func;
	}

	return 0;
	/* TODO: Implement lib_load(). */
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	if (!strcmp("run", lib->funcname)) {
		lib->run();
	}

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

static void handle(int connectfd)
{
	char buffer[BUFSIZ];
	struct lib *library = malloc(sizeof(struct lib));
	ssize_t bytes;

	bytes = recv_socket(connectfd, buffer, BUFSIZ);
	if (bytes < 0) {
		close(connectfd);
		free(library);
		return;
	}

	library->funcname = calloc(BUFSIZE, 1);
	library->libname = calloc(BUFSIZE, 1);
	library->filename = calloc(BUFSIZE, 1);
	parse_command(buffer, &library->libname, &library->funcname, &library->filename);

	lib_run(library);

	send_data(connectfd, buffer, strlen(buffer));
}

static void handle_in_new_process(int connectfd)
{
	pid_t pid;

	pid = fork();
	switch (pid) {
	case -1:
		DIE(1 == 1, "pid == -1");
		break;
	case 0:		/* child process */
		daemon(1, 1);
		handle(connectfd);
		exit(EXIT_SUCCESS);
		break;
	default:
		break;
	}

	close(connectfd);
}


int main(void)
{
	/* TODO: Implement server connection. */
	int ret, listen_fd, accept_fd;
	struct sockaddr_un addr, recv_addr;
	socklen_t recv_addr_len;
	struct lib lib;

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

		handle_in_new_process(accept_fd);

		/* TODO - parse message with parse_command and populate lib */
		/* TODO - handle request from client */
		//ret = lib_run(&lib);
	}

	return 0;
}
