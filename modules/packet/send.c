#include "kit.h"

static size_t encode_varint(unsigned char *dst, int value) {
    size_t out = 0;
    unsigned int v = (unsigned int)value;

    do {
        unsigned char byte = (unsigned char)(v & 0x7F);
        v >>= 7;
        if (v) byte |= 0x80;
        dst[out++] = byte;
    } while (v);

    return out;
}

void packet_writer_init(PacketWriter *w, unsigned char *buf, size_t cap) {
    if (!w) return;
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
}

int packet_write_bytes(PacketWriter *w, const unsigned char *data, size_t len) {
    if (!w || !data) return 0;
    if (w->len + len > w->cap) return 0;
    memcpy(w->buf + w->len, data, len);
    w->len += len;
    return 1;
}

int packet_write_u8(PacketWriter *w, unsigned char value) {
    return packet_write_bytes(w, &value, 1);
}

int packet_write_u16(PacketWriter *w, unsigned short value) {
    unsigned char b[2];
    b[0] = (unsigned char)((value >> 8) & 0xFFu);
    b[1] = (unsigned char)(value & 0xFFu);
    return packet_write_bytes(w, b, sizeof(b));
}

int packet_write_i64(PacketWriter *w, long long value) {
    unsigned char b[8];
    b[0] = (unsigned char)((value >> 56) & 0xFFu);
    b[1] = (unsigned char)((value >> 48) & 0xFFu);
    b[2] = (unsigned char)((value >> 40) & 0xFFu);
    b[3] = (unsigned char)((value >> 32) & 0xFFu);
    b[4] = (unsigned char)((value >> 24) & 0xFFu);
    b[5] = (unsigned char)((value >> 16) & 0xFFu);
    b[6] = (unsigned char)((value >> 8) & 0xFFu);
    b[7] = (unsigned char)(value & 0xFFu);
    return packet_write_bytes(w, b, sizeof(b));
}

int packet_write_varint(PacketWriter *w, int value) {
    unsigned char tmp[5];
    size_t n = encode_varint(tmp, value);
    return packet_write_bytes(w, tmp, n);
}

int packet_write_string(PacketWriter *w, const char *data, size_t len) {
    if (!w || !data) return 0;
    if (len > (size_t)INT32_MAX) return 0;
    if (!packet_write_varint(w, (int)len)) return 0;
    return packet_write_bytes(w, (const unsigned char *)data, len);
}

int packet_write_uuid(PacketWriter *w, const unsigned char uuid[16]) {
    if (!w || !uuid) return 0;
    return packet_write_bytes(w, uuid, 16);
}

int packet_send(int fd, int packet_id, const unsigned char *payload, size_t payload_len) {
    if (fd < 0) return 0;
    if (payload_len > (size_t)INT32_MAX) return 0;

    unsigned char id_buf[5];
    size_t id_len = encode_varint(id_buf, packet_id);
    size_t body_len = id_len + payload_len;

    unsigned char len_buf[5];
    size_t len_len = encode_varint(len_buf, (int)body_len);

    unsigned char framed[8192];
    if (len_len + body_len > sizeof(framed)) return 0;

    size_t off = 0;
    memcpy(framed + off, len_buf, len_len);
    off += len_len;
    memcpy(framed + off, id_buf, id_len);
    off += id_len;
    if (payload_len) {
        memcpy(framed + off, payload, payload_len);
        off += payload_len;
    }

    return packet_send_fd(fd, framed, off) >= 0;
}

int packet_send_writer(int fd, int packet_id, PacketWriter *w) {
    if (!w) return 0;
    return packet_send(fd, packet_id, w->buf, w->len);
}

int packet_send_kind(int fd, PacketOutKind kind, int protocol, const PacketOut *out) {
    if (fd < 0 || !out) return 0;
    if (protocol < 0) return 0;
    if (protocol != 0 && protocol < 765) {
        if (kind == PKT_OUT_CONFIG_KNOWN_PACKS ||
            kind == PKT_OUT_CONFIG_PLUGIN_MESSAGE ||
            kind == PKT_OUT_REGISTRY_DATA) {
            return 0;
        }
    }

    unsigned char buf[8192];
    PacketWriter w;
    packet_writer_init(&w, buf, sizeof(buf));

    switch (kind) {
    case PKT_OUT_LOGIN_DISCONNECT:
        if (!packet_write_string(&w, out->data.login_disconnect.json, out->data.login_disconnect.json_len)) return 0;
        return packet_send_writer(fd, 0, &w);
    case PKT_OUT_STATUS_RESPONSE:
        if (!packet_write_string(&w, out->data.status_response.json, out->data.status_response.json_len)) return 0;
        return packet_send_writer(fd, 0, &w);
    case PKT_OUT_PONG:
        if (!packet_write_i64(&w, out->data.pong.value)) return 0;
        return packet_send_writer(fd, 1, &w);
    case PKT_OUT_LOGIN_SUCCESS:
        if (!packet_write_uuid(&w, out->data.login_success.uuid)) return 0;
        if (!packet_write_string(&w, out->data.login_success.username, out->data.login_success.username_len)) return 0;
        if (!packet_write_varint(&w, out->data.login_success.properties_count)) return 0;
        return packet_send_writer(fd, 0x02, &w);
    case PKT_OUT_CONFIG_KNOWN_PACKS:
        if (!packet_write_varint(&w, out->data.known_packs.count)) return 0;
        if (!packet_write_string(&w, out->data.known_packs.ns, out->data.known_packs.ns_len)) return 0;
        if (!packet_write_string(&w, out->data.known_packs.id, out->data.known_packs.id_len)) return 0;
        if (!packet_write_string(&w, out->data.known_packs.version, out->data.known_packs.version_len)) return 0;
        return packet_send_writer(fd, 0x0E, &w);
    case PKT_OUT_CONFIG_PLUGIN_MESSAGE:
        if (!packet_write_string(&w, out->data.plugin_message.channel, out->data.plugin_message.channel_len)) return 0;
        if (!packet_write_string(&w, out->data.plugin_message.value, out->data.plugin_message.value_len)) return 0;
        return packet_send_writer(fd, 0x01, &w);
    case PKT_OUT_REGISTRY_DATA:
        if (!packet_write_string(&w, out->data.registry_data.registry_id, out->data.registry_data.registry_id_len)) return 0;
        if (!packet_write_varint(&w, (int)out->data.registry_data.entry_count)) return 0;
        for (size_t i = 0; i < out->data.registry_data.entry_count; i++) {
            const char *entry = out->data.registry_data.entries[i];
            if (!packet_write_string(&w, entry, strlen(entry))) return 0;
            if (!packet_write_u8(&w, 0)) return 0;
        }
        return packet_send_writer(fd, 0x07, &w);
    }

    return 0;
}
