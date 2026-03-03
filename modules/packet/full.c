#include "kit.h"

enum {
    PKT_VARINT = 1,
    PKT_STRING = 2,
    PKT_US = 3,
    PKT_LL = 4
};

typedef struct FullConn {
    int fd;
    unsigned char buf[16384];
    size_t len;
} FullConn;

typedef struct PacketTemplate {
    const char *name;
    const char *tmpl;
    size_t expected_count;
} PacketTemplate;

PacketField packet_store[16];
PacketField *packet = packet_store;
size_t packet_count;
int packet_fd = -1;

static FullConn *conns;
static size_t conn_count;
static size_t conn_capacity;

static const PacketTemplate templates[] = {
    { "handshake", "v v s255 us v", 5 },
    { "status_request", "v", 1 },
    { "status_ping", "v ll", 2 }
};

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

    int packet_len = 1 + (int)encode_varint((unsigned char[5]){0}, json_len) + json_len;
    size_t total_len = encode_varint((unsigned char[5]){0}, packet_len) + (size_t)packet_len;
    unsigned char *out = malloc(total_len);
    if (!out) {
        free(json);
        return;
    }

    size_t off = 0;
    off += encode_varint(out + off, packet_len);
    off += encode_varint(out + off, 0); /* Login Disconnect packet id */
    off += encode_varint(out + off, json_len);
    memcpy(out + off, json, (size_t)json_len);
    off += (size_t)json_len;

    packet_send_fd(fd, out, off);
    shutdown(fd, SHUT_RDWR);
    free(out);
    free(json);
}

static int parse_one_token(const char *token, const unsigned char *src, size_t src_len, PacketField *out, size_t *used) {
    if (strcmp(token, "v") == 0) {
        int value = 0;
        size_t n = 0;
        int rc = decode_varint(src, src_len, &value, &n);
        if (rc != 1) return rc;
        out->type = PKT_VARINT;
        out->content.varint = value;
        *used = n;
        return 1;
    }

    if (strcmp(token, "us") == 0) {
        if (src_len < 2) return 0;
        out->type = PKT_US;
        out->content.us = (unsigned short)(((unsigned short)src[0] << 8) | (unsigned short)src[1]);
        *used = 2;
        return 1;
    }

    if (strcmp(token, "ll") == 0) {
        if (src_len < 8) return 0;
        out->type = PKT_LL;
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

        out->type = PKT_STRING;
        out->content.string.data = (const char *)(src + hdr);
        out->content.string.len = (size_t)str_len;
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

static int parse_packet_against_templates(const unsigned char *packet_data, size_t packet_len) {
    for (size_t i = 0; i < sizeof(templates) / sizeof(templates[0]); i++) {
        size_t n = 0;
        int rc = parse_by_template(packet_data, packet_len, templates[i].tmpl, packet_store, sizeof(packet_store) / sizeof(packet_store[0]), &n);
        if (rc != 1) continue;
        if (n != templates[i].expected_count) continue;
        packet_count = n;
        return 1;
    }
    return 0;
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
        if (!parse_packet_against_templates(conn->buf + packet_start, (size_t)frame_len)) {
            LOG("Dropping fd=%d: no template match", conn->fd);
            send_disconnect_message(conn->fd, "Hello, Reverse Engineer");
            remove_conn_fd(conn->fd);
            return;
        }

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
