/*
 * Used by tests/track_mem.rs, which checks that track_mem skips unchanged pages
 * by comparing the dumped pages with the size of this region. The region is
 * filled with a non-zero byte because CRIU does not dump anonymous pages that
 * were never written, and it is never touched again so that a dump which does
 * not skip unchanged pages always writes at least the region size.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>

#define REGION_SIZE (16 * 1024 * 1024)
#define FILL_BYTE 0xa5

int main(void) {
    void *region;

    region = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(region, FILL_BYTE, REGION_SIZE);

    if (setsid() < 0) {
        perror("setsid");
        return 1;
    }

    printf("%d\n", REGION_SIZE);
    fflush(stdout);

    close(0);
    close(1);
    close(2);

    signal(SIGHUP, SIG_IGN);

    while (1) {
        sleep(1);
    }

    return 0;
}
