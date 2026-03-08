#include "kit.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>

static int listen_fd = -1;
static int *clients;
static size_t client_count;
static size_t client_capacity;
Bytes packet_buffer;
int fd_disconnected = -1;

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static uint16_t get_listen_port(void) {
    const char *raw = getenv("MCORDS_TCP_PORT");
    if (!raw || !raw[0]) return 25565;

    char *end = NULL;
    long parsed = strtol(raw, &end, 10);
    if (end == raw || *end != '\0' || parsed <= 0 || parsed > 65535) {
        LOG("Invalid MCORDS_TCP_PORT='%s', using 25565", raw);
        return 25565;
    }

    return (uint16_t)parsed;
}

static void remove_client_at(size_t idx) {
    if (idx >= client_count) return;
    fd_disconnected = clients[idx];
    call_event(EVENT_FDC, NULL);
    fds_clear_fd(fd_disconnected);
    close(fd_disconnected);
    if (idx + 1 < client_count) {
        memmove(&clients[idx], &clients[idx + 1], (client_count - idx - 1) * sizeof(*clients));
    }
    client_count -= 1;
}

static int remove_client_fd(int fd) {
    PlayerInfo* p = fds_get(fd, "player");
    if (p) call_event(EVENT_WRLD, p);
    for (size_t i = 0; i < client_count; i++) {
        if (clients[i] != fd) continue;
        remove_client_at(i);
        return 1;
    }
    return 0;
}

int disconnect_fd(int fd) {
    if (fd < 0) return 0;
    shutdown(fd, SHUT_RDWR);
    return remove_client_fd(fd);
}

static int add_client(int fd) {
    if (client_count == client_capacity) {
        size_t next_capacity = client_capacity ? client_capacity * 2 : 8;
        int *next = realloc(clients, next_capacity * sizeof(*next));
        if (!next) return 0;
        clients = next;
        client_capacity = next_capacity;
    }
    clients[client_count++] = fd;
    return 1;
}

static ssize_t send_nonblocking(int fd, const void *data, size_t len) {
    const char *buf = (const char *)data;
    size_t total = 0;

    while (total < len) {
        ssize_t n = send(fd, buf + total, len - total, MSG_NOSIGNAL);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }

        if (n == 0) break;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        return -1;
    }

    return (ssize_t)total;
}

ssize_t packet_send_fd(int fd, const void *data, size_t len) {
    if (!data || len == 0 || fd < 0) return 0;

    ssize_t written = send_nonblocking(fd, data, len);
    if (written < 0) {
        // LOG("send failed on fd=%d: %s", fd, strerror(errno));
        remove_client_fd(fd);
        return -1;
    }
    return written;
}

size_t packet_send_all(const void *data, size_t len) {
    if (!data || len == 0) return 0;

    size_t total_written = 0;
    for (size_t i = 0; i < client_count;) {
        int fd = clients[i];
        ssize_t written = send_nonblocking(fd, data, len);
        if (written < 0) {
            LOG("broadcast send failed on fd=%d: %s", fd, strerror(errno));
            remove_client_at(i);
            continue;
        }

        total_written += (size_t)written;
        i += 1;
    }

    return total_written;
}

ssize_t packet_send_bytes(const Bytes *packet) {
    if (!packet) return 0;
    if (packet->n <= 0) return 0;
    if ((size_t)packet->n > sizeof(packet->buf)) return -1;
    return packet_send_fd(packet->fd, packet->buf, (size_t)packet->n);
}

static void recv_tick(ptr unused) {
    (void)unused;
    if (listen_fd < 0) return;

    for (;;) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno != EINTR) LOG("accept failed: %s", strerror(errno));
            break;
        }

        if (!set_nonblocking(client_fd)) {
            LOG("Failed to make client fd non-blocking");
            close(client_fd);
            continue;
        }

        if (!add_client(client_fd)) {
            LOG("Out of memory while tracking client");
            close(client_fd);
            continue;
        }
    }

    for (size_t i = 0; i < client_count;) {
        int fd = clients[i];
        int dropped = 0;

        for (;;) {
            char buf[4096];
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n > 0) {
                memcpy(packet_buffer.buf, buf, (size_t)n);
                packet_buffer.fd=fd;
                packet_buffer.n=n;

                call_event(EVENT_PKT_RAW, NULL);

                // LOG("TCP fd=%d: received %zd bytes", fd, n);
                // I was
                // I
                // Nah that's an insane amout of stdout
                continue;
            }

            if (n == 0) {
                dropped = 1;
                break;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            // LOG("recv failed on fd=%d: %s", fd, strerror(errno));
            dropped = 1;
            break;
        }

        if (dropped) {
            remove_client_at(i);
            continue;
        }
        i += 1;
    }
}

static void recv_cleanup(ptr unused) {
    (void)unused;
    if (listen_fd >= 0) {
        close(listen_fd);
        listen_fd = -1;
    }

    for (size_t i = 0; i < client_count; i++) {
        close(clients[i]);
    }
    free(clients);
    clients = NULL;
    client_count = 0;
    client_capacity = 0;
}

__attribute__((constructor))
static void start() {
    uint16_t port = get_listen_port();
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        LOG("socket failed: %s", strerror(errno));
        return;
    }

    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
        close(listen_fd);
        listen_fd = -1;
        return;
    }

    if (!set_nonblocking(listen_fd)) {
        LOG("Failed to make listen socket non-blocking");
        close(listen_fd);
        listen_fd = -1;
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG("bind failed on port %u: %s", (unsigned)port, strerror(errno));
        close(listen_fd);
        listen_fd = -1;
        return;
    }

    if (listen(listen_fd, 64) < 0) {
        LOG("listen failed: %s", strerror(errno));
        close(listen_fd);
        listen_fd = -1;
        return;
    }

    LOG("Module %s loaded, listening on TCP port %u (non-blocking)", FILENAME, (unsigned)port);
    on_event(EVENT_LPS, recv_tick);
    on_event(EVENT_FRE, recv_cleanup);
}
