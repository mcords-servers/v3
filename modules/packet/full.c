#include "kit.h"

typedef struct FullConn {
    int fd;
    unsigned char buf[16384];
    size_t len;
} FullConn;

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
            if (value) *value = result;
            if (used) *used = i;
            return 1;
        }

        shift += 7;
    }

    if (i >= 5) return -1;
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

    PacketOut out;
    out.kind = PKT_OUT_LOGIN_DISCONNECT;
    out.data.login_disconnect.json = json;
    out.data.login_disconnect.json_len = (size_t)json_len;
    packet_send_kind(fd, PKT_OUT_LOGIN_DISCONNECT, 0, &out);
    shutdown(fd, SHUT_RDWR);
    free(json);
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

        int packet_id = 0;
        size_t id_len = 0;
        int id_rc = decode_varint(conn->buf + packet_start, (size_t)frame_len, &packet_id, &id_len);
        if (id_rc != 1 || id_len > (size_t)frame_len) {
            send_disconnect_message(conn->fd, "Hello, Reverse Engineer!");
            remove_conn_fd(conn->fd);
            return;
        }

        PacketView view;
        view.fd = conn->fd;
        view.id = packet_id;
        view.payload = conn->buf + packet_start + id_len;
        view.payload_len = (size_t)frame_len - id_len;

        call_event(EVENT_PKT, &view);
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
