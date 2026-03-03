#include "kit.h"

static void on_packet(ptr p) {
    PacketField *pkt = (PacketField *)p;

    // you can also use global packet_count / packet_fd
    for (size_t i = 0; i < packet_count; i++) {
        if (pkt[i].type == 1) { // varint
            // LOG("field[%zu] varint=%d", i, pkt[i].content.varint);
        } else if (pkt[i].type == 2) { // string
            // LOG("field[%zu] string_len=%zu", i, pkt[i].content.string.len);
        } else if (pkt[i].type == 3) { // unsigned short
            // LOG("field[%zu] us=%hu", i, pkt[i].content.us);
        } else if (pkt[i].type == 4) { // long long
            // LOG("field[%zu] ll=%lld", i, pkt[i].content.ll);
        }
    }

    // LOG("from fd=%d", packet_fd);
}

__attribute__((constructor))
static void start(void) {
    on_event(EVENT_PKT, on_packet);
}
