/*
	This program attempts to run the program EXECUTABLE_NAME in the same
	directory as itself using AuthorizationExecuteWithPrivileges. If the
	authorization fails or is canceled, EXECUTABLE_NAME is run without
	privileges using a plain exec.

	This program is the first link in the chain
		zenmap_auth -> zenmap_wrapper.py -> zenmap.bin
*/

#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>

#define EXECUTABLE_NAME "zenmap_wrapper.py"

int main(int argc, char *argv[]) {
	AuthorizationItem items[] = {
		{ kAuthorizationRightExecute, 0, NULL, 0 }
	};
	AuthorizationRights rights = { 1, items };
	AuthorizationRef ref;
	AuthorizationFlags flags;
	OSStatus status;
	char executable_path[1024];
	const char *cwd;
	size_t len_cwd;
	int return_code;

	cwd = dirname(argv[0]);
	len_cwd = strlen(cwd);
	if (sizeof(executable_path) < len_cwd + strlen("/") + strlen(EXECUTABLE_NAME) + 1) {
		fprintf(stderr, "Not enough room to store executable path: %s\n", strerror(errno));
		exit(1);
	}
	strcpy(executable_path, cwd);
	executable_path[len_cwd] = '/';
	strcpy(executable_path + len_cwd + 1, EXECUTABLE_NAME);

	flags = kAuthorizationFlagDefaults
		| kAuthorizationFlagInteractionAllowed
		| kAuthorizationFlagPreAuthorize
		| kAuthorizationFlagExtendRights;
	status = AuthorizationCreate(&rights, kAuthorizationEmptyEnvironment, flags, &ref);
	if (status != errAuthorizationSuccess) {
		if (status != errAuthorizationCanceled)
			fprintf(stderr, "Couldn't create authorization reference (status code %ld).\n", status);
		errno = 0;
		execv(executable_path, argv);
		fprintf(stderr, "Couldn't exec '%s': %s.\n", executable_path, strerror(errno));
		exit(1);
	}

	status = AuthorizationExecuteWithPrivileges(ref, executable_path,
		kAuthorizationFlagDefaults, argv + 1, NULL);
	AuthorizationFree(ref, kAuthorizationFlagDefaults);
	if (status != errAuthorizationSuccess) {
		fprintf(stderr, "Couldn't execute '%s' with privileges (status code %ld).\n", executable_path, status);
		errno = 0;
		execv(executable_path, argv);
		fprintf(stderr, "Couldn't exec '%s': %s.\n", executable_path, strerror(errno));
		exit(1);
	}

	wait(&return_code);
	exit(return_code);
}
