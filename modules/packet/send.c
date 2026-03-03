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

static size_t encode_varlong(unsigned char *dst, long long value) {
    size_t out = 0;
    unsigned long long v = (unsigned long long)value;

    do {
        unsigned char byte = (unsigned char)(v & 0x7F);
        v >>= 7;
        if (v) byte |= 0x80;
        dst[out++] = byte;
    } while (v);

    return out;
}

static int append_bytes(unsigned char *out, size_t out_cap, size_t *off, const void *src, size_t n) {
    if (*off + n > out_cap) return 0;
    memcpy(out + *off, src, n);
    *off += n;
    return 1;
}

static int append_u8(unsigned char *out, size_t out_cap, size_t *off, unsigned char v) {
    return append_bytes(out, out_cap, off, &v, 1);
}

static int append_be16(unsigned char *out, size_t out_cap, size_t *off, unsigned short v) {
    unsigned char b[2];
    b[0] = (unsigned char)((v >> 8) & 0xFFu);
    b[1] = (unsigned char)(v & 0xFFu);
    return append_bytes(out, out_cap, off, b, 2);
}

static int append_be32(unsigned char *out, size_t out_cap, size_t *off, unsigned int v) {
    unsigned char b[4];
    b[0] = (unsigned char)((v >> 24) & 0xFFu);
    b[1] = (unsigned char)((v >> 16) & 0xFFu);
    b[2] = (unsigned char)((v >> 8) & 0xFFu);
    b[3] = (unsigned char)(v & 0xFFu);
    return append_bytes(out, out_cap, off, b, 4);
}

static int append_be64(unsigned char *out, size_t out_cap, size_t *off, unsigned long long v) {
    unsigned char b[8];
    b[0] = (unsigned char)((v >> 56) & 0xFFu);
    b[1] = (unsigned char)((v >> 48) & 0xFFu);
    b[2] = (unsigned char)((v >> 40) & 0xFFu);
    b[3] = (unsigned char)((v >> 32) & 0xFFu);
    b[4] = (unsigned char)((v >> 24) & 0xFFu);
    b[5] = (unsigned char)((v >> 16) & 0xFFu);
    b[6] = (unsigned char)((v >> 8) & 0xFFu);
    b[7] = (unsigned char)(v & 0xFFu);
    return append_bytes(out, out_cap, off, b, 8);
}

static int append_varint(unsigned char *out, size_t out_cap, size_t *off, int v) {
    unsigned char tmp[5];
    size_t n = encode_varint(tmp, v);
    return append_bytes(out, out_cap, off, tmp, n);
}

static int append_varlong(unsigned char *out, size_t out_cap, size_t *off, long long v) {
    unsigned char tmp[10];
    size_t n = encode_varlong(tmp, v);
    return append_bytes(out, out_cap, off, tmp, n);
}

static int encode_one(const char *token,
                      const PacketField *field,
                      unsigned char *out,
                      size_t out_cap,
                      size_t *off) {
    if (strcmp(token, "bool") == 0) return append_u8(out, out_cap, off, field->content.boolean ? 1 : 0);
    if (strcmp(token, "b") == 0) return append_u8(out, out_cap, off, (unsigned char)field->content.b);
    if (strcmp(token, "ub") == 0) return append_u8(out, out_cap, off, field->content.ub);
    if (strcmp(token, "sh") == 0) return append_be16(out, out_cap, off, (unsigned short)field->content.s);
    if (strcmp(token, "us") == 0) return append_be16(out, out_cap, off, field->content.us);
    if (strcmp(token, "i") == 0) return append_be32(out, out_cap, off, (unsigned int)field->content.i);
    if (strcmp(token, "l") == 0) return append_be64(out, out_cap, off, (unsigned long long)field->content.l);

    if (strcmp(token, "f") == 0) {
        unsigned int bits = 0;
        memcpy(&bits, &field->content.f, sizeof(bits));
        return append_be32(out, out_cap, off, bits);
    }
    if (strcmp(token, "d") == 0) {
        unsigned long long bits = 0;
        memcpy(&bits, &field->content.d, sizeof(bits));
        return append_be64(out, out_cap, off, bits);
    }

    if (strcmp(token, "v") == 0) return append_varint(out, out_cap, off, field->content.varint);
    if (strcmp(token, "vl") == 0) return append_varlong(out, out_cap, off, field->content.varlong);
    if (strcmp(token, "ll") == 0) return append_be64(out, out_cap, off, (unsigned long long)field->content.ll);
    if (strcmp(token, "ang") == 0) return append_u8(out, out_cap, off, field->content.angle);

    if (strcmp(token, "uuid") == 0) return append_bytes(out, out_cap, off, field->content.uuid, 16);

    if (strcmp(token, "pos") == 0) {
        int x = field->content.position.x;
        int y = field->content.position.y;
        int z = field->content.position.z;
        unsigned long long packed = (((unsigned long long)x & 0x3FFFFFFu) << 38) |
                                    (((unsigned long long)z & 0x3FFFFFFu) << 12) |
                                    ((unsigned long long)y & 0xFFFu);
        return append_be64(out, out_cap, off, packed);
    }

    if (strcmp(token, "bitset") == 0) {
        size_t longs = field->content.bytes.len / 8;
        if (field->content.bytes.len % 8 != 0) return 0;
        if (longs > (size_t)INT32_MAX) return 0;
        if (!append_varint(out, out_cap, off, (int)longs)) return 0;
        return append_bytes(out, out_cap, off, field->content.bytes.data, field->content.bytes.len);
    }

    if (strncmp(token, "fbs", 3) == 0) {
        char *end = NULL;
        long bits = strtol(token + 3, &end, 10);
        if (end == token + 3 || *end != '\0' || bits < 0) return 0;
        size_t need = ((size_t)bits + 7) / 8;
        if (field->content.bytes.len < need) return 0;
        return append_bytes(out, out_cap, off, field->content.bytes.data, need);
    }

    if (strcmp(token, "id") == 0) token = "s32767";
    if (strcmp(token, "json") == 0) token = "s262144";

    if (token[0] == 's') {
        if (field->content.string.len > (size_t)INT32_MAX) return 0;
        if (!append_varint(out, out_cap, off, (int)field->content.string.len)) return 0;
        return append_bytes(out, out_cap, off, field->content.string.data, field->content.string.len);
    }

    if (strncmp(token, "opt:", 4) == 0) {
        if (!field->content.optional.present) return 1;
        return append_bytes(out, out_cap, off, field->content.optional.data, field->content.optional.len);
    }

    if (strncmp(token, "popt:", 5) == 0) {
        if (!append_u8(out, out_cap, off, field->content.optional.present ? 1 : 0)) return 0;
        if (!field->content.optional.present) return 1;
        return append_bytes(out, out_cap, off, field->content.optional.data, field->content.optional.len);
    }

    if (strncmp(token, "arr", 3) == 0) {
        return append_bytes(out, out_cap, off, field->content.array.data, field->content.array.len);
    }

    if (strncmp(token, "parr:", 5) == 0) {
        if (field->content.array.count > (size_t)INT32_MAX) return 0;
        if (!append_varint(out, out_cap, off, (int)field->content.array.count)) return 0;
        return append_bytes(out, out_cap, off, field->content.array.data, field->content.array.len);
    }

    return 0;
}

int packet_build_template(const char *tmpl,
                          const PacketField *fields,
                          size_t field_count,
                          unsigned char *out,
                          size_t out_cap,
                          size_t *out_len) {
    if (!tmpl || !fields || !out || !out_len) return 0;

    size_t off = 0;
    size_t fi = 0;
    const char *p = tmpl;

    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p += 1;
        if (!*p) break;
        if (fi >= field_count) return 0;

        char token[64];
        size_t t = 0;
        while (p[t] && p[t] != ' ' && p[t] != '\t' && p[t] != '\n' && p[t] != '\r') {
            if (t + 1 >= sizeof(token)) return 0;
            token[t] = p[t];
            t += 1;
        }
        token[t] = '\0';
        p += t;

        if (!encode_one(token, &fields[fi], out, out_cap, &off)) return 0;
        fi += 1;
    }

    if (fi != field_count) return 0;
    *out_len = off;
    return 1;
}

int packet_send_template_fd(int fd, const char *tmpl, const PacketField *fields, size_t field_count) {
    unsigned char payload[4096];
    unsigned char framed[4101];
    size_t payload_len = 0;
    if (fd < 0) return 0;
    if (!packet_build_template(tmpl, fields, field_count, payload, sizeof(payload), &payload_len)) return 0;
    if (payload_len > (size_t)INT32_MAX) return 0;

    size_t off = 0;
    off += encode_varint(framed + off, (int)payload_len);
    if (off + payload_len > sizeof(framed)) return 0;
    memcpy(framed + off, payload, payload_len);
    off += payload_len;

    return packet_send_fd(fd, framed, off) >= 0;
}

int packet_send_template_current(const char *tmpl, const PacketField *fields, size_t field_count) {
    return packet_send_template_fd(packet_fd, tmpl, fields, field_count);
}

__attribute__((constructor))
static void start(void) {
    LOG("Module %s loaded", FILENAME);
}

