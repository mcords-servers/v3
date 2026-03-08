#include "kit.h"

#include "kit.h"

static void on_packet(PlayerInfo *p) {
    //TODO: Send empty required registries
}

__attribute__((constructor))
static void start(void) {
    on_event(EVENT_REG, on_packet);
}