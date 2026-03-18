/*
 * PTY slave loop process for orphan-pts-master testing.
 *
 * Usage: ./loop_pts <slave_fd>
 *   Receives an inherited slave PTY fd number, creates a new session,
 *   sets slave as controlling terminal, redirects stdio, then loops until killed.
 */
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>

int main(int argc, char *argv[]) {
    if (argc != 2)
        return 1;

    int slave_fd = atoi(argv[1]);

    if (setsid() < 0)
        return 1;

    if (ioctl(slave_fd, TIOCSCTTY, 0) != 0)
        return 1;

    dup2(slave_fd, 0);
    dup2(slave_fd, 1);
    dup2(slave_fd, 2);
    if (slave_fd > 2)
        close(slave_fd);

    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd <= 0) max_fd = 1024;
    for (int fd = 3; fd < (int)max_fd; fd++)
        close(fd);

    signal(SIGHUP, SIG_IGN);

    while (1)
        pause();

    return 0;
}
