#include "kit.h"

static void on_packet(PacketView *pkt) {
    if (!pkt) return;

    PlayerInfo *p = fds_get(pkt->fd, "player");
    if (!p && pkt->id && fds_get(pkt->fd, "status") != (ptr)1) disconnect(pkt->fd);
    if (!p) return;

    switch (p->state) {
    case LOGIN:
        if (pkt->id == 0x03 && pkt->payload_len == 0) {
            p->state = CONFIG;
            LOG("Entering config state");
        }
        break;

    case CONFIG:
        if (pkt->id == 0x00 && pkt->payload_len) {
            int protocol = (int)(long)fds_get(pkt->fd, "protocol");
            PacketParsed parsed;
            if (!packet_parse(PKT_CONFIG_CLIENT_INFORMATION, protocol, pkt->payload, pkt->payload_len, &parsed)) {
                disconnect(pkt->fd);
            }

            memset(p->info.locale, 0, sizeof(p->info.locale));
            if (parsed.data.client_info.locale_len) {
                size_t copy = parsed.data.client_info.locale_len;
                if (copy >= sizeof(p->info.locale)) copy = sizeof(p->info.locale) - 1;
                memcpy(p->info.locale, parsed.data.client_info.locale, copy);
            }
            p->info.view_distance = parsed.data.client_info.view_distance;
            p->info.chat_colors = (unsigned)parsed.data.client_info.chat_colors;
            p->info.skin_parts_mask = parsed.data.client_info.skin_parts;
            p->info.main_hand = (unsigned)parsed.data.client_info.main_hand;
            p->info.text_filtering = (unsigned)parsed.data.client_info.text_filtering;
            p->info.allow_server_listings = (unsigned)parsed.data.client_info.allow_server_listings;
            p->info.particle_status = (unsigned)parsed.data.client_info.particle_status;
            p->info.chat_mode = (unsigned)parsed.data.client_info.chat_mode;

            PacketOut out;
            out.kind = PKT_OUT_CONFIG_KNOWN_PACKS;
            out.data.known_packs.count = 1;
            out.data.known_packs.ns = "minecraft";
            out.data.known_packs.ns_len = 9;
            out.data.known_packs.id = "core";
            out.data.known_packs.id_len = 4;
            out.data.known_packs.version = "1.21.10";
            out.data.known_packs.version_len = 7;
            packet_send_kind(pkt->fd, PKT_OUT_CONFIG_KNOWN_PACKS, protocol, &out);
        } else if (pkt->id == 0x02 && pkt->payload_len) {
            int protocol = (int)(long)fds_get(pkt->fd, "protocol");
            PacketParsed parsed;
            if (!packet_parse(PKT_CONFIG_PLUGIN_MESSAGE, protocol, pkt->payload, pkt->payload_len, &parsed)) return;
            if (parsed.data.plugin_message.channel_len != 15 ||
                strncmp("minecraft:brand", parsed.data.plugin_message.channel, 15)) {
                return;
            }

            PacketReader r;
            packet_reader_init(&r, parsed.data.plugin_message.data, parsed.data.plugin_message.data_len);
            const char *brand = NULL;
            size_t brand_len = 0;
            if (!packet_read_string(&r, 32767, &brand, &brand_len)) return;

            p->brand = strndup(brand, brand_len);
            mem_add(p->fd, p->brand);

            PacketOut out;
            out.kind = PKT_OUT_CONFIG_PLUGIN_MESSAGE;
            out.data.plugin_message.channel = "minecraft:brand";
            out.data.plugin_message.channel_len = 15;
            out.data.plugin_message.value = "vanilla";
            out.data.plugin_message.value_len = 7;
            packet_send_kind(pkt->fd, PKT_OUT_CONFIG_PLUGIN_MESSAGE, protocol, &out);
        } else if (pkt->id == 0x03 && pkt->payload_len == 0) {
            p->state = PLAY;
            LOG("Entering play state");
        } else if (pkt->id == 0x07 && pkt->payload_len) {
            call_event(EVENT_REG, p);
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
