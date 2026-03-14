#include "world.h"

#define Count 256
static PlayerInfo* players[Count];
static char playersc;

static void manage(PlayerInfo* p) {
    if (strncmp(p->world, WORLD,16)) {
        for (unsigned char i = 0; i < Count; i++) if (players[i]==p) {
            players[i] = NULL;
            playersc--;
            LOG("%s left the %s", p->username, WORLD);
            return;
        }
        return;
    };
    for (unsigned char i = 0; i < Count; i++) if (!players[i]) {
        players[i] = p;
        playersc++;
        LOG("%s connected to %s", p->username, WORLD);
        return;
    }
    //All places are taken
    LOG("Can't transfer %s to %s", p->username, WORLD);
}

__attribute__((constructor))
static void start() {
    LOG("World loaded");
    on_event(EVENT_WRLD, manage);
}