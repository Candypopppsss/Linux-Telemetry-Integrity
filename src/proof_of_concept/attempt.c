#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

/* One single-threaded execve attempt; no shell fallback or persistence. */
int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--target") == 0) {
        puts("LTI_RESULT success");
        return 0;
    }
    if (argc != 3) {
        fprintf(stderr, "usage: %s PATH EXPECTED_ERRNO (0 for success)\n", argv[0]);
        return 2;
    }
    char *end;
    long expected = strtol(argv[2], &end, 10);
    if (*end || expected < 0 || expected > 4095) return 2;
    if (prctl(PR_SET_NAME, "lti-attempt", 0, 0, 0) != 0) return 2;
    char *target_argv[] = {argv[1], "--target", NULL};
    char *target_env[] = {NULL};
    execve(argv[1], target_argv, target_env);
    int error = errno;
    printf("LTI_RESULT errno=%d\n", error);
    return error == expected && expected != 0 ? 0 : 1;
}
