#include "kit.h"

static int decode_varint(const unsigned char *src, size_t src_len, int *value, size_t *used) {
    int result = 0;
    int shift = 0;
    size_t i = 0;

    while (i < src_len && i < 5) {
        unsigned char byte = src[i];
        result |= (int)(byte & 0x7F) << shift;
        i += 1;

        if ((byte & 0x80) == 0) {
            if (value) *value = result;
            if (used) *used = i;
            return 1;
        }

        shift += 7;
    }

    if (i >= 5) return -1;
    return 0;
}

void packet_reader_init(PacketReader *r, const unsigned char *buf, size_t len) {
    if (!r) return;
    r->buf = buf;
    r->len = len;
    r->off = 0;
}

int packet_read_varint(PacketReader *r, int *out) {
    if (!r) return 0;
    size_t used = 0;
    int value = 0;
    int rc = decode_varint(r->buf + r->off, r->len - r->off, &value, &used);
    if (rc != 1) return 0;
    r->off += used;
    if (out) *out = value;
    return 1;
}

int packet_read_u8(PacketReader *r, unsigned char *out) {
    if (!r) return 0;
    if (r->off + 1 > r->len) return 0;
    if (out) *out = r->buf[r->off];
    r->off += 1;
    return 1;
}

int packet_read_u16(PacketReader *r, unsigned short *out) {
    if (!r) return 0;
    if (r->off + 2 > r->len) return 0;
    unsigned short v = (unsigned short)((r->buf[r->off] << 8) | r->buf[r->off + 1]);
    r->off += 2;
    if (out) *out = v;
    return 1;
}

int packet_read_i64(PacketReader *r, long long *out) {
    if (!r) return 0;
    if (r->off + 8 > r->len) return 0;
    const unsigned char *b = r->buf + r->off;
    long long v =
        ((long long)b[0] << 56) |
        ((long long)b[1] << 48) |
        ((long long)b[2] << 40) |
        ((long long)b[3] << 32) |
        ((long long)b[4] << 24) |
        ((long long)b[5] << 16) |
        ((long long)b[6] << 8) |
        (long long)b[7];
    r->off += 8;
    if (out) *out = v;
    return 1;
}

int packet_read_string(PacketReader *r, size_t max_len, const char **data, size_t *len) {
    if (!r) return 0;
    int str_len = 0;
    if (!packet_read_varint(r, &str_len)) return 0;
    if (str_len < 0 || (size_t)str_len > max_len) return 0;
    if (r->off + (size_t)str_len > r->len) return 0;
    if (data) *data = (const char *)(r->buf + r->off);
    if (len) *len = (size_t)str_len;
    r->off += (size_t)str_len;
    return 1;
}

int packet_read_uuid(PacketReader *r, unsigned char out[16]) {
    if (!r) return 0;
    if (r->off + 16 > r->len) return 0;
    if (out) memcpy(out, r->buf + r->off, 16);
    r->off += 16;
    return 1;
}

int packet_read_remaining(PacketReader *r, const unsigned char **data, size_t *len) {
    if (!r) return 0;
    if (data) *data = r->buf + r->off;
    if (len) *len = r->len - r->off;
    r->off = r->len;
    return 1;
}

static int ensure_consumed(PacketReader *r) {
    return r && r->off == r->len;
}

int packet_parse(PacketKind kind, int protocol, const unsigned char *payload, size_t payload_len, PacketParsed *out) {
    if (!out) return 0;
    PacketReader r;
    packet_reader_init(&r, payload, payload_len);

    out->kind = kind;
    if (protocol < 0) return 0;

    switch (kind) {
    case PKT_HANDSHAKE: {
        int next_state = 0;
        int proto = 0;
        const char *addr = NULL;
        size_t addr_len = 0;
        unsigned short port = 0;

        if (!packet_read_varint(&r, &proto)) return 0;
        if (!packet_read_string(&r, 255, &addr, &addr_len)) return 0;
        if (!packet_read_u16(&r, &port)) return 0;
        if (!packet_read_varint(&r, &next_state)) return 0;
        if (!ensure_consumed(&r)) return 0;

        out->data.handshake.protocol = proto;
        out->data.handshake.address = addr;
        out->data.handshake.address_len = addr_len;
        out->data.handshake.port = port;
        out->data.handshake.next_state = next_state;
        return 1;
    }
    case PKT_STATUS_PING: {
        long long value = 0;
        if (!packet_read_i64(&r, &value)) return 0;
        if (!ensure_consumed(&r)) return 0;
        out->data.ping.value = value;
        return 1;
    }
    case PKT_LOGIN_START: {
        const char *username = NULL;
        size_t username_len = 0;
        unsigned char uuid[16];
        if (!packet_read_string(&r, 16, &username, &username_len)) return 0;
        if (!packet_read_uuid(&r, uuid)) return 0;
        if (!ensure_consumed(&r)) return 0;
        out->data.login_start.username = username;
        out->data.login_start.username_len = username_len;
        memcpy(out->data.login_start.uuid, uuid, 16);
        (void)protocol;
        return 1;
    }
    case PKT_CONFIG_CLIENT_INFORMATION: {
        if (protocol != 0 && protocol < 765) return 0;
        const char *locale = NULL;
        size_t locale_len = 0;
        unsigned char view_distance = 0;
        int chat_mode = 0;
        unsigned char chat_colors = 0;
        unsigned char skin_parts = 0;
        int main_hand = 0;
        unsigned char text_filtering = 0;
        unsigned char allow_server_listings = 0;
        int particle_status = 0;

        if (!packet_read_string(&r, 16, &locale, &locale_len)) return 0;
        if (!packet_read_u8(&r, &view_distance)) return 0;
        if (!packet_read_varint(&r, &chat_mode)) return 0;
        if (!packet_read_u8(&r, &chat_colors)) return 0;
        if (chat_colors > 1) return 0;
        if (!packet_read_u8(&r, &skin_parts)) return 0;
        if (!packet_read_varint(&r, &main_hand)) return 0;
        if (!packet_read_u8(&r, &text_filtering)) return 0;
        if (text_filtering > 1) return 0;
        if (!packet_read_u8(&r, &allow_server_listings)) return 0;
        if (allow_server_listings > 1) return 0;
        if (!packet_read_varint(&r, &particle_status)) return 0;
        if (!ensure_consumed(&r)) return 0;

        memset(out->data.client_info.locale, 0, sizeof(out->data.client_info.locale));
        out->data.client_info.locale_len = 0;
        if (locale && locale_len) {
            size_t copy = locale_len;
            if (copy >= sizeof(out->data.client_info.locale)) copy = sizeof(out->data.client_info.locale) - 1;
            memcpy(out->data.client_info.locale, locale, copy);
            out->data.client_info.locale_len = copy;
        }
        out->data.client_info.view_distance = (int8_t)view_distance;
        out->data.client_info.chat_mode = chat_mode;
        out->data.client_info.chat_colors = (int)chat_colors;
        out->data.client_info.skin_parts = skin_parts;
        out->data.client_info.main_hand = main_hand;
        out->data.client_info.text_filtering = (int)text_filtering;
        out->data.client_info.allow_server_listings = (int)allow_server_listings;
        out->data.client_info.particle_status = particle_status;
        return 1;
    }
    case PKT_CONFIG_PLUGIN_MESSAGE: {
        if (protocol != 0 && protocol < 765) return 0;
        const char *channel = NULL;
        size_t channel_len = 0;
        const unsigned char *data = NULL;
        size_t data_len = 0;

        if (!packet_read_string(&r, 32767, &channel, &channel_len)) return 0;
        if (!packet_read_remaining(&r, &data, &data_len)) return 0;

        out->data.plugin_message.channel = channel;
        out->data.plugin_message.channel_len = channel_len;
        out->data.plugin_message.data = data;
        out->data.plugin_message.data_len = data_len;
        (void)protocol;
        return 1;
    }
    }

    return 0;
}
