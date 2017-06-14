/* Copyright (C) 2016 Alexander Lamaison
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include "openssh_fixture.h"
#include "libssh2_config.h"

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int run_command(const char *command, char **output)
{
    FILE *pipe;
    char command_buf[BUFSIZ];
    int ret;
    if (output) {
        *output = NULL;
    }

    /* Rewrite the command to redirect stderr to stdout to we can output it */
    ret = snprintf(command_buf, sizeof(command_buf), "%s 2>&1", command);
    if (ret < 0 || ret >= BUFSIZ) {
        fprintf(stderr, "Unable to format command (%s)\n", command);
        return -1;
    }

    fprintf(stdout, "Command: %s\n", command);
#ifdef WIN32
    pipe = _popen(command_buf, "r");
#else
    pipe = popen(command_buf, "r");
#endif
    if (pipe) {
        char buf[BUFSIZ];
        char *p = buf;
        while (fgets(p, sizeof(buf) - (p - buf), pipe) != NULL)
            ;

#ifdef WIN32
        ret = _pclose(pipe);
#else
        ret = pclose(pipe);
#endif
        if (ret == 0) {
            if (output) {
                /* command output may contain a trailing newline, so we trim
                 * whitespace here */
                size_t end = strlen(buf) - 1;
                while (end > 0 && isspace(buf[end])) {
                    buf[end] = '\0';
                }

                *output = strdup(buf);
            }
        }
        else {
            fprintf(stderr, "Error running command '%s' (exit %d): %s\n",
                    command, ret, buf);
        }
        return ret;
    }
    else {
        fprintf(stderr, "Unable to execute command '%s'\n", command);
        return -1;
    }
}

static int build_openssh_server_docker_image()
{
    return run_command("docker build -t libssh2/openssh_server openssh_server",
                       NULL);
}

static int start_openssh_server(char **container_id_out)
{
    return run_command("docker run --detach -P libssh2/openssh_server",
                       container_id_out);
}

static int stop_openssh_server(char *container_id)
{
    char command_buf[BUFSIZ];
    int rc = snprintf(command_buf, sizeof(command_buf), "docker stop %s",
                      container_id);
    if (rc > -1 && rc < BUFSIZ) {
        return run_command(command_buf, NULL);
    }
    else {
        return rc;
    }
}

static const char *docker_machine_name()
{
    return getenv("DOCKER_MACHINE_NAME");
}

static int ip_address_from_container(char *container_id, char **ip_address_out)
{
    const char *active_docker_machine = docker_machine_name();
    if (active_docker_machine != NULL) {

        // This can be flaky when tests run in parallel (see
        // https://github.com/docker/machine/issues/2612), so we retry a few
        // times with exponential backoff if it fails
        int attempt_no = 0;
        int wait_time = 500;
        for (;;) {
            char command_buf[BUFSIZ];
            int rc = snprintf(command_buf, sizeof(command_buf),
                              "docker-machine ip %s", active_docker_machine);
            if (rc > -1 && rc < BUFSIZ) {
                return run_command(command_buf, ip_address_out);
            }

            if (attempt_no > 5) {
                fprintf(
                    stderr,
                    "Unable to get IP from docker-machine after %d attempts\n",
                    attempt_no);
                return -1;
            }
            else {
#ifdef WIN32
#pragma warning(push)
#pragma warning(disable : 4996)
                _sleep(wait_time);
#pragma warning(pop)
#else
                sleep(wait_time);
#endif
                ++attempt_no;
                wait_time *= 2;
            }
        }
    }
    else {
        char command_buf[BUFSIZ];
        int rc = snprintf(
            command_buf, sizeof(command_buf),
            "docker inspect --format \"{{ index (index (index "
            ".NetworkSettings.Ports \\\"22/tcp\\\") 0) \\\"HostIp\\\" }}\" %s",
            container_id);
        if (rc > -1 && rc < BUFSIZ) {
            return run_command(command_buf, ip_address_out);
        }
        else {
            return rc;
        }
    }
}

static int port_from_container(char *container_id, char **port_out)
{
    char command_buf[BUFSIZ];
    int rc = snprintf(
        command_buf, sizeof(command_buf),
        "docker inspect --format \"{{ index (index (index "
        ".NetworkSettings.Ports \\\"22/tcp\\\") 0) \\\"HostPort\\\" }}\" %s",
        container_id);
    if (rc > -1 && rc < BUFSIZ) {
        return run_command(command_buf, port_out);
    }
    else {
        return rc;
    }
}

static int open_socket_to_container(char *container_id)
{
    char *ip_address = NULL;

    int ret = ip_address_from_container(container_id, &ip_address);
    if (ret == 0) {
        char *port_string = NULL;
        ret = port_from_container(container_id, &port_string);
        if (ret == 0) {
            unsigned long hostaddr = inet_addr(ip_address);
            if (hostaddr != (unsigned long)(-1)) {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock > -1) {
                    struct sockaddr_in sin;

                    sin.sin_family = AF_INET;
                    sin.sin_port = htons((short)strtol(port_string, NULL, 0));
                    sin.sin_addr.s_addr = hostaddr;

                    if (connect(sock, (struct sockaddr *)(&sin),
                                sizeof(struct sockaddr_in)) == 0) {
                        ret = sock;
                    }
                    else {
                        fprintf(stderr, "Failed to connect to %s:%s\n",
                                ip_address, port_string);
                        ret = -1;
                    }
                }
                else {
                    fprintf(stderr, "Failed to open socket (%d)\n", sock);
                    ret = -1;
                }
            }
            else {
                fprintf(stderr, "Failed to convert %s host address\n",
                        ip_address);
                ret = -1;
            }

            free(port_string);
        }
        else {
            fprintf(stderr, "Failed to get port for container %s\n",
                    container_id);
            ret = -1;
        }

        free(ip_address);
    }
    else {
        fprintf(stderr, "Failed to get IP address for container %s\n",
                container_id);
        ret = -1;
    }

    return ret;
}

static char *running_container_id = NULL;

int start_openssh_fixture()
{
    int ret;
#ifdef HAVE_WINSOCK2_H
    WSADATA wsadata;

    ret = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if (ret != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", ret);
        return 1;
    }
#endif

    ret = build_openssh_server_docker_image();
    if (ret == 0) {
        return start_openssh_server(&running_container_id);
    }
    else {
        fprintf(stderr, "Failed to build docker image\n");
        return ret;
    }
}

void stop_openssh_fixture()
{
    if (running_container_id) {
        stop_openssh_server(running_container_id);
        free(running_container_id);
        running_container_id = NULL;
    }
    else {
        fprintf(stderr, "Cannot stop container - none started");
    }
}

int open_socket_to_openssh_server()
{
    return open_socket_to_container(running_container_id);
}
