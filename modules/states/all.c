#include "kit.h"

static void on_packet(PacketField* pkt) {
    if (!pkt) return;
    PlayerInfo *p = fds_get(packet_fd, "player");
    if (!p || packet_count != 2 || pkt[0].type != PACKET_TYPE_VARINT || pkt[1].type != PACKET_TYPE_RAW) return;

    int packet_id = pkt[0].content.varint;
    size_t payload_len = pkt[1].content.bytes.len;

    switch (p->state) {
    case LOGIN:
        if (packet_id == 0x03 && payload_len == 0) {
            p->state=CONFIG;
            LOG("Entering config state");
        }
        break;

    case CONFIG:
        if (packet_id == 0x03 && payload_len == 0) {
            p->state=CONFIG;
            LOG("Entering config state");
        }

        break;

    case PLAY:
        break;
    }
}

__attribute__((constructor))
static void start(void) {
    on_event(EVENT_PKT, on_packet);
}
