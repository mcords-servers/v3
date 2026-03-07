#include "kit.h"

static void on_packet(PacketField* pkt) {
    if (!pkt) return;
    if (packet_count != 2) return;
    if (pkt[0].type != PACKET_TYPE_VARINT) return;
    if (pkt[1].type != PACKET_TYPE_RAW) return;
    int packet_id = pkt[0].content.varint;
    const unsigned char *payload = pkt[1].content.bytes.data;
    size_t payload_len = pkt[1].content.bytes.len;

    if (fds_get(packet_fd, "player") || ((long)fds_get(packet_fd, "status")) != 2) return;

    if (packet_id == 0) {
        PacketField login_with_uuid[2];
        size_t n = 0;
        int rc = packet_parse_template_fields(payload, payload_len, "s16 uuid", login_with_uuid, 2, &n);
        if (rc == 0 && n == 2 && login_with_uuid[0].type == PACKET_TYPE_STRING) {
            PlayerInfo* p = malloc(sizeof(PlayerInfo));
            if (!p) {
                shutdown(packet_fd, SHUT_RDWR);
                return;
            }
            mem_add(packet_fd, p);
            char *username = strndup(login_with_uuid[0].content.string.data, login_with_uuid[0].content.string.len);
            if (!username) {
                shutdown(packet_fd, SHUT_RDWR);
                return;
            }
            mem_add(packet_fd, username); // so it gets freed on disconnect
            fds_set(packet_fd, "player", p);
            p->fd = packet_fd;
            p->state = LOGIN;
            p->username = username;

            LOG("%s is connecting", username);

            PacketField f[4];
            memset(f, 0, sizeof(f));

            f[0].content.varint = 0x02;                      // packet id
            memcpy(f[1].content.uuid, login_with_uuid[1].content.uuid, 16);   // UUID bytes
            f[2].content.string.data = username;             // char*
            f[2].content.string.len = strlen(username);      // <= 16

            f[3].content.array.count = 0;                    // properties count
            f[3].content.array.data = NULL;
            f[3].content.array.len = 0;

            packet_send_template_fd(packet_fd, "v uuid s16 parr:prop", f, 4);

            return;
        }
    }
}

__attribute__((constructor))
static void start(void) {
    on_event(EVENT_PKT, on_packet);
}
