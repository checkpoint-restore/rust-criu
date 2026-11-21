/*
 * Loop process for the inherit stdin test.
 *
 * Usage: ./loop_stdin <output file>
 *   Creates a new session, prints its PID to stdout, closes stdout and
 *   stderr, then appends everything read from stdin to <output file>.
 *   On EOF it keeps running without reading, so a stdin replaced by
 *   /dev/null never produces any output.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	char buf[256];
	ssize_t n;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <output file>\n", argv[0]);
		return 1;
	}

	if (setsid() < 0) {
		perror("setsid");
		return 1;
	}

	printf("%d\n", getpid());
	fflush(stdout);
	close(1);
	close(2);

	signal(SIGHUP, SIG_IGN);

	while (1) {
		n = read(0, buf, sizeof(buf));
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			pause();
			continue;
		}
		fd = open(argv[1], O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (fd < 0)
			return 1;
		if (write(fd, buf, n) != n)
			return 1;
		close(fd);
	}

	return 0;
}
