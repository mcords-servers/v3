#include "kit.h"

char exitbool;
unsigned long lps;

// char timer;

int main(int argc, char **argv) {
    unsigned long loops = 0;
    clock_t last_time = clock();
    double elapsed = 0;
    {
        double ms = -1.0;
        FILE *f = fopen("/proc/self/stat", "r");
        if (f) {
            char buf[4096];
            if (fgets(buf, sizeof(buf), f)) {
                char *rp = strrchr(buf, ')');
                if (rp && rp[1] == ' ') {
                    unsigned long long start_ticks = 0;
                    int field = 0;
                    char *save = NULL;
                    for (char *tok = strtok_r(rp + 2, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
                        if (++field == 20) { start_ticks = strtoull(tok, NULL, 10); break; }
                    }
                    if (start_ticks) {
                        FILE *u = fopen("/proc/uptime", "r");
                        double up = 0.0;
                        if (u && fscanf(u, "%lf", &up) == 1) {
                            long hz = sysconf(_SC_CLK_TCK);
                            if (hz > 0) ms = (up - (double)start_ticks / (double)hz) * 1000.0;
                        }
                        if (u) fclose(u);
                    }
                }
            }
            fclose(f);
        }
        if (ms >= 0.0) printf("Server startup time: %d ms\n", (int)ms);
    }

    while (!exitbool) {
        call_event(EVENT_LPS, NULL);

        // This part calculates lps (loops per second)
        loops++;
        clock_t now = clock();
        elapsed = (double)(now - last_time) / CLOCKS_PER_SEC;
        if (elapsed >= 1.0) {
            lps = loops;
            loops = 0;
            last_time = now;
        }
    }
    return 0;
}
