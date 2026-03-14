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
static const char *STATUS_JSON_FMT =
    "{\"version\":{\"name\":\"MCords\",\"protocol\":%d},"
    "\"players\":{\"max\":0,\"online\":0,\"sample\":[{\"name\":\"Status: ok\",\"id\":\"4566e69f-c907-48ee-8d71-d7ba5aa00d20\"}]},"
    "\"description\":{\"text\":\"%s\"}}";

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
    int json_len = snprintf(NULL, 0, STATUS_JSON_FMT, proto, motd);
    if (json_len <= 0) {
        free(motd);
        return;
    }

    char *json = malloc((size_t)json_len + 1);
    if (!json) {
        free(motd);
        return;
    }

    snprintf(json, (size_t)json_len + 1, STATUS_JSON_FMT, proto, motd);
    free(motd);

    PacketOut out;
    out.kind = PKT_OUT_STATUS_RESPONSE;
    out.data.status_response.json = json;
    out.data.status_response.json_len = (size_t)json_len;
    packet_send_kind(fd, PKT_OUT_STATUS_RESPONSE, protocol_version, &out);
    free(json);
}

static void send_pong_ll(int fd, int protocol, long long value) {
    PacketOut out;
    out.kind = PKT_OUT_PONG;
    out.data.pong.value = value;
    packet_send_kind(fd, PKT_OUT_PONG, protocol, &out);
}

static int try_handle_handshake(StatusConn *conn, const PacketView *pkt) {
    PacketParsed parsed;
    if (!packet_parse(PKT_HANDSHAKE, 0, pkt->payload, pkt->payload_len, &parsed)) return 0;

    conn->protocol_version = parsed.data.handshake.protocol;
    conn->seen_handshake = 1;
    conn->status_mode = (parsed.data.handshake.next_state == 1);
    fds_set(conn->fd, "status", (ptr)(long)(parsed.data.handshake.next_state));
    fds_set(conn->fd, "protocol", (ptr)(long)(parsed.data.handshake.protocol));
    return 1;
}

static void on_packet(ptr p) {
    PacketView *pkt = (PacketView *)p;
    if (!pkt) return;

    StatusConn *conn = get_conn(pkt->fd);
    if (!conn) return;

    if (pkt->id == 0 && try_handle_handshake(conn, pkt)) {
        return;
    }

    if (!conn->seen_handshake) return;
    if (!conn->status_mode) return;

    if (pkt->id == 0 && pkt->payload_len == 0) {
        send_status_json(conn->fd, conn->protocol_version);
        return;
    }

    if (pkt->id == 1) {
        PacketParsed parsed;
        if (packet_parse(PKT_STATUS_PING, 0, pkt->payload, pkt->payload_len, &parsed)) {
            send_pong_ll(conn->fd, conn->protocol_version, parsed.data.ping.value);
        }
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
