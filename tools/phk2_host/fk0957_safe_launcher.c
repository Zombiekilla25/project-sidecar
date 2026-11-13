/* Minimal static launcher: sanitize loader/Python environment before Python starts. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef FK0957_BOOTSTRAP_PATH
#define FK0957_BOOTSTRAP_PATH "/usr/local/lib/sidecar/fk0957/fk0957_safe_bootstrap.py"
#endif

int main(int argc, char **argv) {
    char **child_argv = calloc((size_t)argc + 4, sizeof(char *));
    if (child_argv == NULL) return 126;
    child_argv[0] = "/usr/bin/python3";
    child_argv[1] = "-I";
    child_argv[2] = "-S";
    child_argv[3] = FK0957_BOOTSTRAP_PATH;
    for (int i = 1; i < argc; ++i) child_argv[i + 3] = argv[i];
    child_argv[argc + 3] = NULL;

    char *const clean_env[] = {
        "PATH=/usr/bin:/bin",
        "LANG=C.UTF-8",
        "FK0957_TRUSTED_LAUNCHER=1",
        NULL
    };
    execve("/usr/bin/python3", child_argv, clean_env);
    (void)errno;
    return 126;
}
