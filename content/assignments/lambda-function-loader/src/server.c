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

void free_lib(struct lib *lib) {
	if (lib->outputfile)
		free(lib->outputfile);

	if (lib->filename)
		free(lib->filename);

	if (lib->funcname)
		free(lib->funcname);

	if (lib->libname)
		free(lib->libname);

	free(lib);
}

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */

	return 0;
}

static int lib_load(struct lib *lib)
{
	int rc;

	strcpy(lib->outputfile, OUTPUT_TEMPLATE);
	lib->output_fd = mkstemp(lib->outputfile);

	rc = dup2(lib->output_fd, STDOUT_FILENO);
	DIE(rc < 0, "dup2");

	lib->handle = dlopen(lib->libname, RTLD_LAZY);
	if (lib->handle == NULL) {
		if (strlen(lib->filename))
			printf("Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		else 
			printf("Error: %s %s could not be executed.\n", lib->libname, lib->funcname);
		return -1;
	}

	if (!strlen(lib->funcname)) {
		strcpy(lib->funcname, "run");
	}

	void *addr_func = dlsym(lib->handle, lib->funcname);
	if (addr_func == NULL) {
		if (strlen(lib->filename))
			printf("Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		else 
			printf("Error: %s %s could not be executed.\n", lib->libname, lib->funcname);
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
	int rc;

	/* No args/function specified */
	if (!strlen(lib->filename)) {
		lib->run();

		rc = close(lib->output_fd);
		DIE(rc < 0, "close");

		return 0;
	} else {
		lib->p_run(lib->filename);

		rc = close(lib->output_fd);
		DIE(rc < 0, "close");

		return 0;
	}

	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	int rc;

	rc = dlclose(lib->handle);
	DIE(rc, "dlclose");

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

static void handle(int acceptfd)
{
	char buffer[BUFSIZ];
	struct lib *lib = malloc(sizeof(struct lib));
	ssize_t bytes;

	bytes = recv_socket(acceptfd, buffer, BUFSIZ);
	if (bytes < 0) {
		close(acceptfd);
		free(lib);
		return;
	}

	lib->funcname = calloc(BUFSIZE, 1);
	lib->libname = calloc(BUFSIZE, 1);
	lib->filename = calloc(BUFSIZE, 1);
	lib->outputfile = calloc(BUFSIZ, 1);
	parse_command(buffer, lib->libname, lib->funcname, lib->filename);

	lib_run(lib);

	send_socket(acceptfd, lib->outputfile, strlen(lib->outputfile));

	free_lib(lib);

	close(acceptfd);
}

static void handle_in_new_process(int acceptfd)
{
	pid_t pid;

	pid = fork();
	switch (pid) {
	case -1:
		close_socket(acceptfd);
		DIE(1, "pid == -1");
		break;
	case 0:		/* child process */
		daemon(1, 1);
		handle(acceptfd);
		exit(EXIT_SUCCESS);
		break;
	default:
		break;
	}
}


int main(void)
{
	/* TODO: Implement server connection. */
	int ret, listen_fd, accept_fd;
	struct sockaddr_un addr, recv_addr;
	socklen_t recv_addr_len;

	remove(SOCKET_NAME);

	listen_fd = create_socket();
	memset(&addr, 0, sizeof(addr));
	//snprintf(addr.sun_path, sizeof(SOCKET_NAME), "%s", SOCKET_NAME);
	strcpy(addr.sun_path, SOCKET_NAME);
	addr.sun_family = AF_UNIX;
	ret = bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr));
	DIE(ret < 0, "bind");

	ret = listen(listen_fd, 5000);
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

	close_socket(listen_fd);

	return 0;
}
