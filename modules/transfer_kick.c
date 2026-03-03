#include "kit.h"

typedef struct GuardConn {
    int fd;
    unsigned char buf[8192];
    size_t len;
} GuardConn;

static GuardConn *conns;
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

static const char *kick_message(void) {
    const char *raw = getenv("MCORDS_KICK_MESSAGE");
    return (raw && raw[0]) ? raw : "This server only accepts status ping";
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

static void send_disconnect_message(int fd) {
    char *msg = escape_json(kick_message());
    if (!msg) return;

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

    int packet_len = 1 + (int)varint_size(json_len) + json_len; /* id=0 + reason string */
    size_t total_len = varint_size(packet_len) + (size_t)packet_len;

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
    free(out);
    free(json);
}

static GuardConn *get_conn(int fd) {
    for (size_t i = 0; i < conn_count; i++) {
        if (conns[i].fd == fd) return &conns[i];
    }

    if (conn_count == conn_capacity) {
        size_t next = conn_capacity ? conn_capacity * 2 : 16;
        GuardConn *grown = realloc(conns, next * sizeof(*grown));
        if (!grown) return NULL;
        conns = grown;
        conn_capacity = next;
    }

    GuardConn *conn = &conns[conn_count++];
    memset(conn, 0, sizeof(*conn));
    conn->fd = fd;
    return conn;
}

static int parse_handshake_next_state(const unsigned char *packet, size_t packet_len, int *next_state) {
    int packet_id = 0;
    int protocol = 0;
    int host_len = 0;
    size_t off = 0;
    size_t used = 0;

    if (decode_varint(packet + off, packet_len - off, &packet_id, &used) != 1) return 0;
    off += used;
    if (packet_id != 0) return 0;

    if (decode_varint(packet + off, packet_len - off, &protocol, &used) != 1) return 0;
    off += used;

    if (decode_varint(packet + off, packet_len - off, &host_len, &used) != 1) return 0;
    off += used;
    if (host_len < 0 || off + (size_t)host_len + 2 > packet_len) return 0;
    off += (size_t)host_len;

    off += 2; /* server port */
    if (decode_varint(packet + off, packet_len - off, next_state, &used) != 1) return 0;
    (void)protocol;
    return 1;
}

static void guard_raw_packet(ptr unused) {
    (void)unused;

    if (packet_buffer.n <= 0) return;
    if ((size_t)packet_buffer.n > sizeof(packet_buffer.buf)) return;

    GuardConn *conn = get_conn(packet_buffer.fd);
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

        int next_state = 0;
        if (parse_handshake_next_state(conn->buf + packet_start, (size_t)frame_len, &next_state)) {
            if (next_state == 3) {
                LOG("Dropping fd=%d: non-status handshake next_state=%d", conn->fd, next_state);
                send_disconnect_message(conn->fd);
                shutdown(conn->fd, SHUT_RDWR);
            }
        }

        consumed = packet_start + (size_t)frame_len;
    }

    if (consumed == 0) return;
    if (consumed < conn->len) {
        memmove(conn->buf, conn->buf + consumed, conn->len - consumed);
    }
    conn->len -= consumed;
}

static void guard_cleanup(ptr unused) {
    (void)unused;
    free(conns);
    conns = NULL;
    conn_count = 0;
    conn_capacity = 0;
}

__attribute__((constructor))
static void guard_start(void) {
    LOG("Module %s loaded", FILENAME);
    on_event(EVENT_PKT_RAW, guard_raw_packet);
    on_event(EVENT_FRE, guard_cleanup);
}
