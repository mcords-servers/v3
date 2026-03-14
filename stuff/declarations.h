#ifndef D_H
#define D_H

#include "kit.h"

typedef struct HttpResponse HttpResponse;
typedef struct FdData FdData;
typedef struct Memory Memory;

void on_event(ptr event, ptr func);
void call_event(ptr event, ptr ptr);

void http_init(void);
void http_cleanup(void);
void http_perform(void);
HttpResponse *http_post(const char *url, const char *data, const char *content_type);
HttpResponse *http_post_headers(const char *url, const char *data, const char *content_type, const char *const *headers, size_t header_count);
HttpResponse *http_get(const char *url);
HttpResponse *http_get_headers(const char *url, const char *const *headers, size_t header_count);
void http_free(HttpResponse *req);
int http_done(HttpResponse *req);
long http_status(HttpResponse *req);
const char *http_body(HttpResponse *req);
size_t http_body_length(HttpResponse *req);

typedef struct Bytes {
    char buf[4096];
    ssize_t n;
    int fd;
} Bytes;

typedef struct PacketView {
    int fd;
    int id;
    const unsigned char *payload;
    size_t payload_len;
} PacketView;

typedef struct PacketReader {
    const unsigned char *buf;
    size_t len;
    size_t off;
} PacketReader;

typedef struct PacketWriter {
    unsigned char *buf;
    size_t cap;
    size_t len;
} PacketWriter;

typedef enum PacketKind {
    PKT_HANDSHAKE,
    PKT_STATUS_PING,
    PKT_LOGIN_START,
    PKT_CONFIG_CLIENT_INFORMATION,
    PKT_CONFIG_PLUGIN_MESSAGE
} PacketKind;

typedef struct PacketParsed {
    PacketKind kind;
    union {
        struct {
            int protocol;
            const char *address;
            size_t address_len;
            unsigned short port;
            int next_state;
        } handshake;
        struct {
            long long value;
        } ping;
        struct {
            const char *username;
            size_t username_len;
            unsigned char uuid[16];
        } login_start;
        struct {
            char locale[16];
            size_t locale_len;
            int8_t view_distance;
            int chat_mode;
            int chat_colors;
            unsigned char skin_parts;
            int main_hand;
            int text_filtering;
            int allow_server_listings;
            int particle_status;
        } client_info;
        struct {
            const char *channel;
            size_t channel_len;
            const unsigned char *data;
            size_t data_len;
        } plugin_message;
    } data;
} PacketParsed;

typedef enum PacketOutKind {
    PKT_OUT_LOGIN_DISCONNECT,
    PKT_OUT_STATUS_RESPONSE,
    PKT_OUT_PONG,
    PKT_OUT_LOGIN_SUCCESS,
    PKT_OUT_CONFIG_KNOWN_PACKS,
    PKT_OUT_CONFIG_PLUGIN_MESSAGE,
    PKT_OUT_REGISTRY_DATA
} PacketOutKind;

typedef struct PacketOut {
    PacketOutKind kind;
    union {
        struct {
            const char *json;
            size_t json_len;
        } login_disconnect;
        struct {
            const char *json;
            size_t json_len;
        } status_response;
        struct {
            long long value;
        } pong;
        struct {
            unsigned char uuid[16];
            const char *username;
            size_t username_len;
            int properties_count;
        } login_success;
        struct {
            int count;
            const char *ns;
            size_t ns_len;
            const char *id;
            size_t id_len;
            const char *version;
            size_t version_len;
        } known_packs;
        struct {
            const char *channel;
            size_t channel_len;
            const char *value;
            size_t value_len;
        } plugin_message;
        struct {
            const char *registry_id;
            size_t registry_id_len;
            const char **entries;
            size_t entry_count;
        } registry_data;
    } data;
} PacketOut;
extern int fd_disconnected;

ssize_t packet_send_fd(int fd, const void *data, size_t len);
size_t packet_send_all(const void *data, size_t len);
ssize_t packet_send_bytes(const Bytes *packet);
int disconnect_fd(int fd);

void packet_reader_init(PacketReader *r, const unsigned char *buf, size_t len);
int packet_read_varint(PacketReader *r, int *out);
int packet_read_u8(PacketReader *r, unsigned char *out);
int packet_read_u16(PacketReader *r, unsigned short *out);
int packet_read_i64(PacketReader *r, long long *out);
int packet_read_string(PacketReader *r, size_t max_len, const char **data, size_t *len);
int packet_read_uuid(PacketReader *r, unsigned char out[16]);
int packet_read_remaining(PacketReader *r, const unsigned char **data, size_t *len);

void packet_writer_init(PacketWriter *w, unsigned char *buf, size_t cap);
int packet_write_varint(PacketWriter *w, int value);
int packet_write_u8(PacketWriter *w, unsigned char value);
int packet_write_u16(PacketWriter *w, unsigned short value);
int packet_write_i64(PacketWriter *w, long long value);
int packet_write_string(PacketWriter *w, const char *data, size_t len);
int packet_write_uuid(PacketWriter *w, const unsigned char uuid[16]);
int packet_write_bytes(PacketWriter *w, const unsigned char *data, size_t len);

int packet_send(int fd, int packet_id, const unsigned char *payload, size_t payload_len);
int packet_send_writer(int fd, int packet_id, PacketWriter *w);

int packet_parse(PacketKind kind, int protocol, const unsigned char *payload, size_t payload_len, PacketParsed *out);
int packet_send_kind(int fd, PacketOutKind kind, int protocol, const PacketOut *out);

struct FdData {
    char *key;
    void *ptr;
    int owned;
    FdData *next;
};

struct Memory {
    void *ptr;
    Memory *next;
};

typedef struct PlayerInfo PlayerInfo;
struct PlayerInfo {
    int fd;
    enum {
        LOGIN,
        CONFIG,
        PLAY
    } state;
    char* username;
    char* brand;
    char* world;
    struct __attribute__((packed)) {
        char locale[16];
        int8_t view_distance;

        struct {
            unsigned chat_mode:2;
            unsigned chat_colors:1;

            union {
                unsigned skin_parts_mask:8;
                struct {
                    unsigned cape:1;
                    unsigned jacket:1;
                    unsigned left_sleeve:1;
                    unsigned right_sleeve:1;
                    unsigned left_pants:1;
                    unsigned right_pants:1;
                    unsigned hat:1;
                    unsigned unused:1;
                };
            };
            unsigned main_hand:1;
            unsigned text_filtering:1;
            unsigned allow_server_listings:1;
            unsigned particle_status:2;
        };
    } info;
};

void *fds_set(int fd, const char *key, void *ptr);
void *fds_get(int fd, const char *key);
void *fds_del(int fd, const char *key);
int fds_incr(int fd, const char *key);
void fds_clear_fd(int fd);
void fds_clear_all(void);
void *mem_add(int fd, void *ptr);
void mem_free(int fd);

#define EVENT (void *)0
#define EVENT_LPS (void *)1
#define EVENT_FRE (void *)2
#define EVENT_PKT_RAW (void *)3
#define EVENT_PKT (void *)4
#define EVENT_FDC (void *)5
#define EVENT_REG (void *)6
#define EVENT_WRLD (void *)7

#define disconnect(fd) {disconnect_fd(fd); return;}

#endif
