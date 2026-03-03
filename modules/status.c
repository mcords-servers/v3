#include "kit.h"

typedef struct StatusConn {
    int fd;
    int seen_handshake;
    int status_mode;
    int protocol_version;
} StatusConn;

static StatusConn *conns;
static size_t conn_count;
static size_t conn_capacity;

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

    PacketField fields[2];
    memset(fields, 0, sizeof(fields));
    fields[0].content.varint = 0; /* status response packet id */
    fields[1].content.string.data = json;
    fields[1].content.string.len = (size_t)json_len;
    packet_send_template_fd(fd, "v s262144", fields, 2);
    free(json);
}

static void send_pong_ll(int fd, long long value) {
    PacketField fields[2];
    memset(fields, 0, sizeof(fields));
    fields[0].content.varint = 1; /* pong packet id */
    fields[1].content.ll = value;
    packet_send_template_fd(fd, "v ll", fields, 2);
}

static int try_handle_handshake(StatusConn *conn, const PacketField *pkt) {
    if (packet_count != 5) return 0;
    if (pkt[0].type != PACKET_TYPE_VARINT || pkt[0].content.varint != 0) return 0; /* packet id */
    if (pkt[1].type != PACKET_TYPE_VARINT) return 0; /* protocol */
    if (pkt[2].type != PACKET_TYPE_STRING) return 0; /* host */
    if (pkt[3].type != PACKET_TYPE_US) return 0; /* port */
    if (pkt[4].type != PACKET_TYPE_VARINT) return 0; /* next_state */

    conn->protocol_version = pkt[1].content.varint;
    conn->seen_handshake = 1;
    conn->status_mode = (pkt[4].content.varint == 1);
    return 1;
}

static void on_packet(ptr p) {
    PacketField *pkt = (PacketField *)p;
    if (!pkt) return;
    if (packet_fd < 0) return;

    StatusConn *conn = get_conn(packet_fd);
    if (!conn) return;

    if (try_handle_handshake(conn, pkt)) {
        return;
    }

    if (!conn->seen_handshake) return;
    if (!conn->status_mode) return;

    if (packet_count == 1 && pkt[0].type == PACKET_TYPE_VARINT && pkt[0].content.varint == 0) {
        send_status_json(conn->fd, conn->protocol_version);
        return;
    }

    if (packet_count == 2 && pkt[0].type == PACKET_TYPE_VARINT && pkt[0].content.varint == 1 && pkt[1].type == PACKET_TYPE_LONG_LONG) {
        send_pong_ll(conn->fd, pkt[1].content.ll);
    }
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
    on_event(EVENT_PKT, on_packet);
    on_event(EVENT_FRE, status_cleanup);
}
