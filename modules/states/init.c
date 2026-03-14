#include "kit.h"

static void on_packet(PacketView *pkt) {
    if (!pkt) return;
    if (pkt->id != 0) return;
    if (fds_get(pkt->fd, "player") || ((long)fds_get(pkt->fd, "status")) != 2) return;

    PacketParsed parsed;
    int protocol = (int)(long)fds_get(pkt->fd, "protocol");
    if (!packet_parse(PKT_LOGIN_START, protocol, pkt->payload, pkt->payload_len, &parsed)) {
        shutdown(pkt->fd, SHUT_RDWR);
        return;
    }

    PlayerInfo *p = calloc(1, sizeof(PlayerInfo));
    if (!p) {
        shutdown(pkt->fd, SHUT_RDWR);
        return;
    }
    mem_add(pkt->fd, p);

    char *username = strndup(parsed.data.login_start.username, parsed.data.login_start.username_len);
    if (!username) {
        shutdown(pkt->fd, SHUT_RDWR);
        return;
    }
    mem_add(pkt->fd, username);

    fds_set(pkt->fd, "player", p);
    p->fd = pkt->fd;
    p->state = LOGIN;
    p->username = username;

    // LOG("%s is connecting", username);

    PacketOut out;
    out.kind = PKT_OUT_LOGIN_SUCCESS;
    memcpy(out.data.login_success.uuid, parsed.data.login_start.uuid, 16);
    out.data.login_success.username = username;
    out.data.login_success.username_len = strlen(username);
    out.data.login_success.properties_count = 0;
    packet_send_kind(pkt->fd, PKT_OUT_LOGIN_SUCCESS, protocol, &out);
}

__attribute__((constructor))
static void start(void) {
    on_event(EVENT_PKT, on_packet);
}
