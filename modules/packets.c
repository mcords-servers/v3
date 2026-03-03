#include "kit.h"

static void on_packet(ptr p) {
    PacketField *pkt = (PacketField *)p;

    // you can also use global packet_count / packet_fd
    for (size_t i = 0; i < packet_count; i++) {
        if (pkt[i].type == PACKET_TYPE_VARINT) {
            // LOG("field[%zu] varint=%d", i, pkt[i].content.varint);
        } else if (pkt[i].type == PACKET_TYPE_STRING) {
            // LOG("field[%zu] string_len=%zu", i, pkt[i].content.string.len);
        } else if (pkt[i].type == PACKET_TYPE_US) {
            // LOG("field[%zu] us=%hu", i, pkt[i].content.us);
        } else if (pkt[i].type == PACKET_TYPE_LONG_LONG) {
            // LOG("field[%zu] ll=%lld", i, pkt[i].content.ll);
        }
    }

    // LOG("from fd=%d", packet_fd);
}

__attribute__((constructor))
static void start(void) {
    on_event(EVENT_PKT, on_packet);
}
