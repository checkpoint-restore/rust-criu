/*
 * Simple loop process for notify callback testing.
 * Based on CRIU's test/others/libcriu/test_notify.c
 *
 * Usage: ./loop
 *   Forks, creates new session, closes stdio, then loops until killed.
 *   Writes "ready" to stdout before closing it (for synchronization).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#define SUCC_ECODE 42

int main(void) {
    /* Create new session */
    if (setsid() < 0) {
        perror("setsid");
        return 1;
    }

    /* Print PID for parent to read */
    printf("%d\n", getpid());
    fflush(stdout);

    /* Close stdio */
    close(0);
    close(1);
    close(2);

    /* Ignore SIGHUP */
    signal(SIGHUP, SIG_IGN);

    /* Loop until killed */
    while (1) {
        sleep(1);
    }

    return SUCC_ECODE;
}
