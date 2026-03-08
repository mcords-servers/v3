#include "kit.h"

typedef struct FullConn {
    int fd;
    unsigned char buf[16384];
    size_t len;
} FullConn;

PacketField packet_store[16];
PacketField *packet = packet_store;
size_t packet_count;
int packet_fd = -1;

static FullConn *conns;
static size_t conn_count;
static size_t conn_capacity;

static int decode_varint(const unsigned char *src, size_t src_len, int *value, size_t *used) {
    int result = 0;
    int shift = 0;
    size_t i = 0;

    while (i < src_len && i < 5) {
        unsigned char byte = src[i];
        result |= (int)(byte & 0x7F) << shift;
        i += 1;

        if ((byte & 0x80) == 0) {
            *value = result;
            *used = i;
            return 1;
        }

        shift += 7;
    }

    if (i >= 5) return -1;
    return 0;
}

static int decode_varlong(const unsigned char *src, size_t src_len, long long *value, size_t *used) {
    unsigned long long result = 0;
    int shift = 0;
    size_t i = 0;

    while (i < src_len && i < 10) {
        unsigned char byte = src[i];
        result |= (unsigned long long)(byte & 0x7Fu) << shift;
        i += 1;

        if ((byte & 0x80u) == 0) {
            if (value) *value = (long long)result;
            if (used) *used = i;
            return 1;
        }
        shift += 7;
    }

    if (i >= 10) return -1;
    return 0;
}

static FullConn *get_conn(int fd) {
    for (size_t i = 0; i < conn_count; i++) {
        if (conns[i].fd == fd) return &conns[i];
    }

    if (conn_count == conn_capacity) {
        size_t next = conn_capacity ? conn_capacity * 2 : 16;
        FullConn *grown = realloc(conns, next * sizeof(*grown));
        if (!grown) return NULL;
        conns = grown;
        conn_capacity = next;
    }

    FullConn *conn = &conns[conn_count++];
    memset(conn, 0, sizeof(*conn));
    conn->fd = fd;
    return conn;
}

static void remove_conn_fd(int fd) {
    for (size_t i = 0; i < conn_count; i++) {
        if (conns[i].fd != fd) continue;
        if (i + 1 < conn_count) {
            memmove(&conns[i], &conns[i + 1], (conn_count - i - 1) * sizeof(*conns));
        }
        conn_count -= 1;
        return;
    }
}

static void send_disconnect_message(int fd, const char *msg_raw) {
    size_t raw_len = strlen(msg_raw);
    char *msg = malloc(raw_len * 2 + 1);
    if (!msg) return;

    size_t j = 0;
    for (size_t i = 0; i < raw_len; i++) {
        char c = msg_raw[i];
        if (c == '"' || c == '\\') msg[j++] = '\\';
        msg[j++] = c;
    }
    msg[j] = '\0';

    int json_len = snprintf(NULL, 0, "{\"text\":\"%s\"}", msg);
    if (json_len <= 0) {
        free(msg);
        return;
    }

    char *json = malloc((size_t)json_len + 1);
    if (!json) {
        free(msg);
        return;
    }
    snprintf(json, (size_t)json_len + 1, "{\"text\":\"%s\"}", msg);
    free(msg);

    PacketField fields[2];
    memset(fields, 0, sizeof(fields));
    fields[0].content.varint = 0; /* Login Disconnect packet id */
    fields[1].content.string.data = json;
    fields[1].content.string.len = (size_t)json_len;
    packet_send_template_fd(fd, "v json", fields, 2);
    shutdown(fd, SHUT_RDWR);
    free(json);
}

static int parse_one_token(const char *token, const unsigned char *src, size_t src_len, PacketField *out, size_t *used);

static int parse_one_token(const char *token, const unsigned char *src, size_t src_len, PacketField *out, size_t *used) {
    if (strncmp(token, "popt:", 5) == 0) {
        const char *inner = token + 5;
        if (!inner[0]) return -1;
        if (src_len < 1) return 0;
        if (src[0] != 0 && src[0] != 1) return -1;

        size_t off = 1;
        if (src[0]) {
            PacketField tmp;
            size_t inner_used = 0;
            int rc = parse_one_token(inner, src + off, src_len - off, &tmp, &inner_used);
            if (rc != 1) return rc;
            off += inner_used;
        }

        out->type = PACKET_TYPE_PREFIXED_OPTIONAL;
        out->content.optional.present = (int)src[0];
        out->content.optional.data = src[0] ? (src + 1) : NULL;
        out->content.optional.len = src[0] ? (off - 1) : 0;
        *used = off;
        return 1;
    }

    if (strncmp(token, "opt:", 4) == 0) {
        const char *inner = token + 4;
        if (!inner[0]) return -1;

        PacketField tmp;
        size_t inner_used = 0;
        int rc = parse_one_token(inner, src, src_len, &tmp, &inner_used);

        out->type = PACKET_TYPE_OPTIONAL;
        if (rc == 1) {
            out->content.optional.present = 1;
            out->content.optional.data = src;
            out->content.optional.len = inner_used;
            *used = inner_used;
            return 1;
        }
        if (rc < 0) return rc;

        out->content.optional.present = 0;
        out->content.optional.data = NULL;
        out->content.optional.len = 0;
        *used = 0;
        return 1;
    }

    if (strncmp(token, "parr:", 5) == 0) {
        const char *inner = token + 5;
        if (!inner[0]) return -1;

        int count = 0;
        size_t hdr = 0;
        int rc = decode_varint(src, src_len, &count, &hdr);
        if (rc != 1) return rc;
        if (count < 0) return -1;

        size_t off = hdr;
        for (int i = 0; i < count; i++) {
            PacketField tmp;
            size_t inner_used = 0;
            rc = parse_one_token(inner, src + off, src_len - off, &tmp, &inner_used);
            if (rc != 1) return rc;
            off += inner_used;
        }

        out->type = PACKET_TYPE_PREFIXED_ARRAY;
        out->content.array.count = (size_t)count;
        out->content.array.data = src + hdr;
        out->content.array.len = off - hdr;
        *used = off;
        return 1;
    }

    if (strncmp(token, "arr", 3) == 0) {
        const char *p = token + 3;
        char *end = NULL;
        long count = strtol(p, &end, 10);
        if (end == p || count < 0 || count > INT32_MAX) return -1;
        if (*end != ':') return -1;
        const char *inner = end + 1;
        if (!inner[0]) return -1;

        size_t off = 0;
        for (long i = 0; i < count; i++) {
            PacketField tmp;
            size_t inner_used = 0;
            int rc = parse_one_token(inner, src + off, src_len - off, &tmp, &inner_used);
            if (rc != 1) return rc;
            off += inner_used;
        }

        out->type = PACKET_TYPE_ARRAY;
        out->content.array.count = (size_t)count;
        out->content.array.data = src;
        out->content.array.len = off;
        *used = off;
        return 1;
    }

    if (strcmp(token, "bool") == 0) {
        if (src_len < 1) return 0;
        if (src[0] != 0 && src[0] != 1) return -1;
        out->type = PACKET_TYPE_BOOL;
        out->content.boolean = (int)src[0];
        *used = 1;
        return 1;
    }

    if (strcmp(token, "b") == 0) {
        if (src_len < 1) return 0;
        out->type = PACKET_TYPE_BYTE;
        out->content.b = (signed char)src[0];
        *used = 1;
        return 1;
    }

    if (strcmp(token, "ub") == 0) {
        if (src_len < 1) return 0;
        out->type = PACKET_TYPE_UBYTE;
        out->content.ub = src[0];
        *used = 1;
        return 1;
    }

    if (strcmp(token, "sh") == 0) {
        if (src_len < 2) return 0;
        out->type = PACKET_TYPE_SHORT;
        out->content.s = (short)(((unsigned short)src[0] << 8) | (unsigned short)src[1]);
        *used = 2;
        return 1;
    }

    if (strcmp(token, "v") == 0) {
        int value = 0;
        size_t n = 0;
        int rc = decode_varint(src, src_len, &value, &n);
        if (rc != 1) return rc;
        out->type = PACKET_TYPE_VARINT;
        out->content.varint = value;
        *used = n;
        return 1;
    }

    if (strcmp(token, "vl") == 0) {
        long long value = 0;
        size_t n = 0;
        int rc = decode_varlong(src, src_len, &value, &n);
        if (rc != 1) return rc;
        out->type = PACKET_TYPE_VARLONG;
        out->content.varlong = value;
        *used = n;
        return 1;
    }

    if (strcmp(token, "us") == 0) {
        if (src_len < 2) return 0;
        out->type = PACKET_TYPE_US;
        out->content.us = (unsigned short)(((unsigned short)src[0] << 8) | (unsigned short)src[1]);
        *used = 2;
        return 1;
    }

    if (strcmp(token, "i") == 0) {
        if (src_len < 4) return 0;
        out->type = PACKET_TYPE_INT;
        out->content.i = (int)(((unsigned int)src[0] << 24) |
                               ((unsigned int)src[1] << 16) |
                               ((unsigned int)src[2] << 8) |
                               (unsigned int)src[3]);
        *used = 4;
        return 1;
    }

    if (strcmp(token, "l") == 0) {
        if (src_len < 8) return 0;
        out->type = PACKET_TYPE_LONG;
        out->content.l =
            ((long long)src[0] << 56) |
            ((long long)src[1] << 48) |
            ((long long)src[2] << 40) |
            ((long long)src[3] << 32) |
            ((long long)src[4] << 24) |
            ((long long)src[5] << 16) |
            ((long long)src[6] << 8) |
            (long long)src[7];
        *used = 8;
        return 1;
    }

    if (strcmp(token, "f") == 0) {
        if (src_len < 4) return 0;
        unsigned int bits = ((unsigned int)src[0] << 24) |
                            ((unsigned int)src[1] << 16) |
                            ((unsigned int)src[2] << 8) |
                            (unsigned int)src[3];
        float value = 0.0f;
        memcpy(&value, &bits, sizeof(value));
        out->type = PACKET_TYPE_FLOAT;
        out->content.f = value;
        *used = 4;
        return 1;
    }

    if (strcmp(token, "d") == 0) {
        if (src_len < 8) return 0;
        unsigned long long bits =
            ((unsigned long long)src[0] << 56) |
            ((unsigned long long)src[1] << 48) |
            ((unsigned long long)src[2] << 40) |
            ((unsigned long long)src[3] << 32) |
            ((unsigned long long)src[4] << 24) |
            ((unsigned long long)src[5] << 16) |
            ((unsigned long long)src[6] << 8) |
            (unsigned long long)src[7];
        double value = 0.0;
        memcpy(&value, &bits, sizeof(value));
        out->type = PACKET_TYPE_DOUBLE;
        out->content.d = value;
        *used = 8;
        return 1;
    }

    if (strcmp(token, "ll") == 0) {
        if (src_len < 8) return 0;
        out->type = PACKET_TYPE_LONG_LONG;
        out->content.ll =
            ((long long)src[0] << 56) |
            ((long long)src[1] << 48) |
            ((long long)src[2] << 40) |
            ((long long)src[3] << 32) |
            ((long long)src[4] << 24) |
            ((long long)src[5] << 16) |
            ((long long)src[6] << 8) |
            (long long)src[7];
        *used = 8;
        return 1;
    }

    if (strcmp(token, "pos") == 0) {
        if (src_len < 8) return 0;
        unsigned long long packed =
            ((unsigned long long)src[0] << 56) |
            ((unsigned long long)src[1] << 48) |
            ((unsigned long long)src[2] << 40) |
            ((unsigned long long)src[3] << 32) |
            ((unsigned long long)src[4] << 24) |
            ((unsigned long long)src[5] << 16) |
            ((unsigned long long)src[6] << 8) |
            (unsigned long long)src[7];
        int x = (int)((packed >> 38) & 0x3FFFFFFu);
        int z = (int)((packed >> 12) & 0x3FFFFFFu);
        int y = (int)(packed & 0xFFFu);
        if (x >= (1 << 25)) x -= (1 << 26);
        if (z >= (1 << 25)) z -= (1 << 26);
        if (y >= (1 << 11)) y -= (1 << 12);

        out->type = PACKET_TYPE_POSITION;
        out->content.position.x = x;
        out->content.position.y = y;
        out->content.position.z = z;
        *used = 8;
        return 1;
    }

    if (strcmp(token, "ang") == 0) {
        if (src_len < 1) return 0;
        out->type = PACKET_TYPE_ANGLE;
        out->content.angle = src[0];
        *used = 1;
        return 1;
    }

    if (strcmp(token, "uuid") == 0) {
        if (src_len < 16) return 0;
        out->type = PACKET_TYPE_UUID;
        memcpy(out->content.uuid, src, 16);
        *used = 16;
        return 1;
    }

    if (strcmp(token, "bitset") == 0) {
        int longs = 0;
        size_t hdr = 0;
        int rc = decode_varint(src, src_len, &longs, &hdr);
        if (rc != 1) return rc;
        if (longs < 0) return -1;
        size_t bytes_len = (size_t)longs * 8;
        if (hdr + bytes_len > src_len) return 0;
        out->type = PACKET_TYPE_BITSET;
        out->content.bytes.data = src + hdr;
        out->content.bytes.len = bytes_len;
        *used = hdr + bytes_len;
        return 1;
    }

    if (strncmp(token, "fbs", 3) == 0) {
        char *end = NULL;
        long n = strtol(token + 3, &end, 10);
        if (end == token + 3 || *end != '\0' || n < 0 || n > INT32_MAX) return -1;
        size_t bytes_len = ((size_t)n + 7) / 8;
        if (bytes_len > src_len) return 0;
        out->type = PACKET_TYPE_FIXED_BITSET;
        out->content.bytes.data = src;
        out->content.bytes.len = bytes_len;
        *used = bytes_len;
        return 1;
    }

    if (strcmp(token, "id") == 0) token = "s32767";
    if (strcmp(token, "json") == 0) token = "s262144";

    if (token[0] == 's') {
        char *end = NULL;
        long max_len = strtol(token + 1, &end, 10);
        if (end == token + 1 || *end != '\0' || max_len <= 0 || max_len > INT32_MAX) return -1;

        int str_len = 0;
        size_t hdr = 0;
        int rc = decode_varint(src, src_len, &str_len, &hdr);
        if (rc != 1) return rc;
        if (str_len < 0 || str_len > max_len) return -1;
        if (hdr + (size_t)str_len > src_len) return 0;

        out->type = PACKET_TYPE_STRING;
        out->content.string.data = (const char *)(src + hdr);
        out->content.string.len = (size_t)str_len;
        if (strcmp(token, "s32767") == 0) out->type = PACKET_TYPE_IDENTIFIER;
        if (strcmp(token, "s262144") == 0) out->type = PACKET_TYPE_JSON_TEXT;
        *used = hdr + (size_t)str_len;
        return 1;
    }

    return -1;
}

static int parse_by_template(const unsigned char *data, size_t data_len, const char *tmpl, PacketField *out, size_t out_cap, size_t *out_n) {
    size_t off = 0;
    size_t count = 0;
    const char *p = tmpl;

    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p += 1;
        if (!*p) break;
        if (count >= out_cap) return -1;

        char token[32];
        size_t t = 0;
        while (p[t] && p[t] != ' ' && p[t] != '\t' && p[t] != '\n' && p[t] != '\r') {
            if (t + 1 >= sizeof(token)) return -1;
            token[t] = p[t];
            t += 1;
        }
        token[t] = '\0';
        p += t;

        size_t used = 0;
        int rc = parse_one_token(token, data + off, data_len - off, &out[count], &used);
        if (rc != 1) return rc;
        off += used;
        count += 1;
    }

    if (off != data_len) return -1;
    *out_n = count;
    return 1;
}

/*
 * Template token legend for packet_parse_template_fields():
 * Primitive tokens:
 *   bool   : Boolean (1 byte, must be 0 or 1)
 *   b      : signed byte (1 byte)
 *   ub     : unsigned byte (1 byte)
 *   sh     : signed short, big-endian (2 bytes)
 *   us     : unsigned short, big-endian (2 bytes)
 *   i      : signed int, big-endian (4 bytes)
 *   l      : signed long long, big-endian (8 bytes)
 *   f      : float32, IEEE754, big-endian bytes (4 bytes)
 *   d      : float64/double, IEEE754, big-endian bytes (8 bytes)
 *   ll     : signed long long, big-endian (8 bytes)
 *   v      : VarInt
 *   vl     : VarLong
 *   pos    : Minecraft packed position (x/z/y in 64 bits)
 *   ang    : angle byte
 *   uuid   : UUID bytes (16 bytes)
 *   bitset : VarInt count + count*8 bytes
 *   fbsN   : fixed bitset with N bits (ceil(N/8) bytes), e.g. fbs24
 *
 * String-like tokens:
 *   sN     : String with VarInt length prefix and max length N, e.g. s16, s32767
 *   id     : alias for s32767 (identifier)
 *   json   : alias for s262144 (JSON text)
 *
 * Composite tokens:
 *   arrN:T   : fixed array of N elements of token T, e.g. arr3:uuid
 *   parr:T   : VarInt-prefixed array of token T
 *   opt:T    : optional T (present if T parses at current offset)
 *   popt:T   : prefixed optional T (1-byte flag 0/1, then T if flag is 1)
 *
 * Return codes:
 *   0  -> success
 *   1  -> incomplete input buffer
 *  -1  -> invalid data/template
 */
int packet_parse_template_fields(const unsigned char *data,
                                 size_t data_len,
                                 const char *tmpl,
                                 PacketField *out,
                                 size_t out_cap,
                                 size_t *out_n) {
    int rc = parse_by_template(data, data_len, tmpl, out, out_cap, out_n);
    if (rc == 1) return 0; /* success */
    if (rc == 0) return 1; /* incomplete */
    return -1; /* invalid */
}

static void on_raw_packet(ptr unused) {
    (void)unused;
    if (packet_buffer.n <= 0) return;
    if ((size_t)packet_buffer.n > sizeof(packet_buffer.buf)) return;

    FullConn *conn = get_conn(packet_buffer.fd);
    if (!conn) return;

    size_t in_len = (size_t)packet_buffer.n;
    if (conn->len + in_len > sizeof(conn->buf)) conn->len = 0;
    memcpy(conn->buf + conn->len, packet_buffer.buf, in_len);
    conn->len += in_len;

    size_t consumed = 0;
    while (consumed < conn->len) {
        int frame_len = 0;
        size_t header_len = 0;
        int rc = decode_varint(conn->buf + consumed, conn->len - consumed, &frame_len, &header_len);
        if (rc == 0) break;
        if (rc < 0 || frame_len < 0) {
            conn->len = 0;
            return;
        }

        size_t packet_start = consumed + header_len;
        if (packet_start + (size_t)frame_len > conn->len) break;

        packet_fd = conn->fd;
        int packet_id = 0;
        size_t id_len = 0;
        int id_rc = decode_varint(conn->buf + packet_start, (size_t)frame_len, &packet_id, &id_len);
        if (id_rc != 1 || id_len > (size_t)frame_len) {
            send_disconnect_message(conn->fd, "Hello, Reverse Engineer!");
            remove_conn_fd(conn->fd);
            return;
        }

        packet_store[0].type = PACKET_TYPE_VARINT;
        packet_store[0].content.varint = packet_id;
        packet_store[1].type = PACKET_TYPE_RAW;
        packet_store[1].content.bytes.data = conn->buf + packet_start + id_len;
        packet_store[1].content.bytes.len = (size_t)frame_len - id_len;
        packet_count = 2;

        call_event(EVENT_PKT, packet);
        consumed = packet_start + (size_t)frame_len;
    }

    if (consumed == 0) return;
    if (consumed < conn->len) {
        memmove(conn->buf, conn->buf + consumed, conn->len - consumed);
    }
    conn->len -= consumed;
}

static void full_cleanup(ptr unused) {
    (void)unused;
    free(conns);
    conns = NULL;
    conn_count = 0;
    conn_capacity = 0;
}

__attribute__((constructor))
static void start() {
    LOG("Module %s loaded", FILENAME);
    on_event(EVENT_PKT_RAW, on_raw_packet);
    on_event(EVENT_FRE, full_cleanup);
}
