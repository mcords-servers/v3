#include "kit.h"

typedef struct StatusConn {
    int fd;
    int seen_handshake;
    int status_mode;
    int protocol_version;
    unsigned char buf[16384];
    size_t len;
} StatusConn;

static StatusConn *conns;
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

static size_t varint_size(int value) {
    unsigned char tmp[5];
    return encode_varint(tmp, value);
}

static StatusConn *get_conn(int fd) {
    for (size_t i = 0; i < conn_count; i++) {
        if (conns[i].fd == fd) return &conns[i];
    }

    if (conn_count == conn_capacity) {
        size_t next = conn_capacity ? conn_capacity * 2 : 16;
        StatusConn *grown = realloc(conns, next * sizeof(*grown));
        if (!grown) return NULL;
        conns = grown;
        conn_capacity = next;
    }

    StatusConn *conn = &conns[conn_count++];
    memset(conn, 0, sizeof(*conn));
    conn->fd = fd;
    return conn;
}

static char *escape_json(const char *raw) {
    if (!raw) raw = "";
    size_t n = strlen(raw);
    char *out = malloc(n * 2 + 1);
    if (!out) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        char c = raw[i];
        if (c == '"' || c == '\\') out[j++] = '\\';
        out[j++] = c;
    }
    out[j] = '\0';
    return out;
}

static const char *motd_value(void) {
    const char *raw = getenv("MCORDS_MOTD");
    return (raw && raw[0]) ? raw : "MCords v3";
}

static int default_protocol(void) {
    const char *raw = getenv("MCORDS_PROTOCOL");
    if (!raw || !raw[0]) return 767;

    char *end = NULL;
    long v = strtol(raw, &end, 10);
    if (end == raw || *end != '\0' || v <= 0 || v > INT32_MAX) return 767;
    return (int)v;
}

static void send_status_json(int fd, int protocol_version) {
    char *motd = escape_json(motd_value());
    if (!motd) return;

    int proto = protocol_version > 0 ? protocol_version : default_protocol();
    int json_len = snprintf(NULL, 0,
                            "{\"version\":{\"name\":\"MCords\",\"protocol\":%d},"
                            "\"players\":{\"max\":0,\"online\":0,\"sample\":[]},"
                            "\"description\":{\"text\":\"%s\"}}",
                            proto, motd);
    if (json_len <= 0) {
        free(motd);
        return;
    }

    char *json = malloc((size_t)json_len + 1);
    if (!json) {
        free(motd);
        return;
    }

    snprintf(json, (size_t)json_len + 1,
             "{\"version\":{\"name\":\"MCords\",\"protocol\":%d},"
             "\"players\":{\"max\":0,\"online\":0,\"sample\":[]},"
             "\"description\":{\"text\":\"%s\"}}",
             proto, motd);
    free(motd);

    int inner_len = 1 + (int)varint_size(json_len) + json_len;
    size_t total_len = varint_size(inner_len) + (size_t)inner_len;
    unsigned char *out = malloc(total_len);
    if (!out) {
        free(json);
        return;
    }

    size_t off = 0;
    off += encode_varint(out + off, inner_len);
    off += encode_varint(out + off, 0);
    off += encode_varint(out + off, json_len);
    memcpy(out + off, json, (size_t)json_len);
    off += (size_t)json_len;

    packet_send_fd(fd, out, off);
    free(out);
    free(json);
}

static void send_pong(int fd, const unsigned char *payload8) {
    unsigned char out[16];
    size_t off = 0;

    off += encode_varint(out + off, 9);
    off += encode_varint(out + off, 1);
    memcpy(out + off, payload8, 8);
    off += 8;

    packet_send_fd(fd, out, off);
}

static int try_handle_handshake(StatusConn *conn, const unsigned char *payload, size_t payload_len) {
    size_t off = 0;
    int protocol = 0;
    int host_len = 0;
    int next_state = 0;
    size_t used = 0;

    if (decode_varint(payload + off, payload_len - off, &protocol, &used) != 1) return 0;
    off += used;

    if (decode_varint(payload + off, payload_len - off, &host_len, &used) != 1) return 0;
    off += used;
    if (host_len < 0 || off + (size_t)host_len + 2 > payload_len) return 0;
    off += (size_t)host_len;

    off += 2; /* server port */
    if (decode_varint(payload + off, payload_len - off, &next_state, &used) != 1) return 0;

    conn->protocol_version = protocol;
    conn->seen_handshake = 1;
    conn->status_mode = (next_state == 1);
    return 1;
}

static void handle_packet(StatusConn *conn, const unsigned char *packet, size_t packet_len) {
    int packet_id = 0;
    size_t id_len = 0;
    int rc = decode_varint(packet, packet_len, &packet_id, &id_len);
    if (rc != 1) return;

    const unsigned char *payload = packet + id_len;
    size_t payload_len = packet_len - id_len;

    /* Always allow a fresh handshake on packet id 0 to recover from fd reuse. */
    if (packet_id == 0 && try_handle_handshake(conn, payload, payload_len)) {
        return;
    }

    if (!conn->seen_handshake) return;
    if (!conn->status_mode) return;

    if (packet_id == 0) {
        send_status_json(conn->fd, conn->protocol_version);
        return;
    }

    if (packet_id == 1 && payload_len == 8) {
        send_pong(conn->fd, payload);
    }
}

static void on_raw_packet(ptr unused) {
    (void)unused;

    if (packet_buffer.n <= 0) return;
    if ((size_t)packet_buffer.n > sizeof(packet_buffer.buf)) return;

    StatusConn *conn = get_conn(packet_buffer.fd);
    if (!conn) return;

    size_t in_len = (size_t)packet_buffer.n;
    if (conn->len + in_len > sizeof(conn->buf)) conn->len = 0;
    memcpy(conn->buf + conn->len, packet_buffer.buf, in_len);
    conn->len += in_len;

    size_t consumed = 0;
    while (consumed < conn->len) {
        int frame_len = 0;
        size_t header_len = 0;
        int frame_rc = decode_varint(conn->buf + consumed, conn->len - consumed, &frame_len, &header_len);
        if (frame_rc == 0) break;
        if (frame_rc < 0 || frame_len < 0) {
            conn->len = 0;
            return;
        }

        size_t packet_start = consumed + header_len;
        if (packet_start + (size_t)frame_len > conn->len) break;

        handle_packet(conn, conn->buf + packet_start, (size_t)frame_len);
        consumed = packet_start + (size_t)frame_len;
    }

    if (consumed == 0) return;
    if (consumed < conn->len) {
        memmove(conn->buf, conn->buf + consumed, conn->len - consumed);
    }
    conn->len -= consumed;
}

static void status_cleanup(ptr unused) {
    (void)unused;
    free(conns);
    conns = NULL;
    conn_count = 0;
    conn_capacity = 0;
}

__attribute__((constructor))
static void status_start(void) {
    LOG("Module %s loaded", FILENAME);
    on_event(EVENT_PKT_RAW, on_raw_packet);
    on_event(EVENT_FRE, status_cleanup);
}
