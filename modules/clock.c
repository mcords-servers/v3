#include "kit.h"

int delay(double seconds_interval, int *last_tick) {
    clock_t now = clock();
    int now_ms = (int)((double)now * 1000 / CLOCKS_PER_SEC);

    if (now_ms - *last_tick >= (int)(seconds_interval * 1000)) {
        *last_tick = now_ms;
        return 1;
    }
    return 0;
}

static void calls(ptr ptr) {
    // static int sec; if (delay(1.0, &(sec))) DEBUG(lps);
}

__attribute__((constructor))
static void test() {
    LOG("Module %s loaded",FILENAME);
    on_event(EVENT_LPS, calls);
}