#include "kit.h"

static void on_packet(PacketField* pkt) {
    if (!pkt) return;
    PlayerInfo *p = fds_get(packet_fd, "player");
    if (packet_count != 2 || pkt[0].type != PACKET_TYPE_VARINT || pkt[1].type != PACKET_TYPE_RAW) return;
    if (!p && pkt[0].content.varint && fds_get(packet_fd, "status")!=(ptr)1) disconnect(packet_fd);
    if (!p) return;

    int packet_id = pkt[0].content.varint;
    const unsigned char* payload = pkt[1].content.bytes.data;
    size_t payload_len = pkt[1].content.bytes.len;

    switch (p->state) {
    case LOGIN:
        if (packet_id == 0x03 && payload_len == 0) {
            p->state=CONFIG;
            // LOG("Entering config state");
        }
        break;

    case CONFIG:
        if (packet_id == 0x00 && payload_len) {
            PacketField parsed[9];
            size_t n = 0;
            char r = packet_parse_template_fields(payload, payload_len, "s16 b v bool ub v bool bool v", parsed, 9, &n);
            if (r||n!=9) disconnect(p->fd);
            int i = 0;
            strncpy(p->info.locale, parsed[i].content.string.data, parsed[i].content.string.len);
            p->info.view_distance = parsed[++i].content.b;
            p->info.chat_colors = parsed[++i].content.boolean;
            p->info.skin_parts_mask = parsed[++i].content.ub;
            p->info.main_hand =  parsed[++i].content.varint;
            p->info.text_filtering = parsed[++i].content.boolean;
            p->info.allow_server_listings = parsed[++i].content.boolean;
            p->info.particle_status = parsed[++i].content.varint;

            PacketField f[5];

            f[0].content.varint = 0x0E;          // Clientbound Known Packs (Configuration)
            f[1].content.varint = 1;             // known_packs count = 1

            f[2].content.string.data = "minecraft";
            f[2].content.string.len  = 9;

            f[3].content.string.data = "core";
            f[3].content.string.len  = 4;

            f[4].content.string.data = "1.21.10";
            f[4].content.string.len  = 7;

            packet_send_template_fd(packet_fd, "v v s32767 s32767 s32767", f, 5);

            // DEBUG((char*)p->info.locale);

        } else if (packet_id == 0x02 && payload_len) {
            PacketField parsed[2];
            size_t n = 0;
            char r = packet_parse_template_fields(payload, payload_len, "s32767 s32767", parsed, 2, &n);
            if (r||n!=2) disconnect(p->fd);
            if (strncmp("minecraft:brand", parsed[0].content.string.data, parsed[0].content.string.len)) return;
            p->brand = strndup(parsed[1].content.string.data, parsed[1].content.string.len);
            mem_add(p->fd, p->brand);

            PacketField send[3];
            send[0].content.varint = 0x01;
            send[1].content.string.data = "minecraft:brand";
            send[1].content.string.len = 15;
            send[2].content.string.data = "vanilla";
            send[2].content.string.len = 7;
            packet_send_template_fd(packet_fd, "v s32767 s32767", send, 3);
        } else if (packet_id == 0x03 && payload_len == 0) {
            p->state=PLAY;
            // LOG("Entering play state");
        } else if (packet_id==0x07 && payload_len) {
            call_event(EVENT_REG, p);
            PacketField fields[1];
            fields[0].content.varint = 0x03;
            packet_send_template_fd(p->fd, "v", fields, 1);
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
