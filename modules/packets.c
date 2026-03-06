#include "kit.h"

static void on_packet(PacketField* pkt) {
    if (!pkt) return;
    if (packet_count != 2) return;
    if (pkt[0].type != PACKET_TYPE_VARINT) return;
    if (pkt[1].type != PACKET_TYPE_RAW) return;
    int packet_id = pkt[0].content.varint;
    const unsigned char *payload = pkt[1].content.bytes.data;
    size_t payload_len = pkt[1].content.bytes.len;

    // LOG("fd=%d packet_id=%d payload_len=%zu", packet_fd, packet_id, payload_len);

    if (((long)fds_get(packet_fd, "status"))!=2 || fds_get(packet_fd, "state")) return;

    if (packet_id == 0) {
        PacketField username[2];
        size_t ping_n = 0;
        int rc = packet_parse_template_fields(payload, payload_len, "s16 uuid", username, 2, &ping_n);
        if (rc == 0 && ping_n == 2) {
            LOG("username=%s", username[1].content.string);
        }
    }
}

__attribute__((constructor))
static void start(void) {
    on_event(EVENT, on_packet);
}
