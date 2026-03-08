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

typedef struct PacketField {
    int type;
    union {
        int boolean;
        signed char b;
        unsigned char ub;
        short s;
        unsigned short us;
        int i;
        long long l;
        float f;
        double d;
        int varint;
        long long varlong;
        struct {
            const char *data;
            size_t len;
        } string;
        long long ll;
        struct {
            int x;
            int y;
            int z;
        } position;
        unsigned char angle;
        unsigned char uuid[16];
        struct {
            const unsigned char *data;
            size_t len;
        } bytes;
        struct {
            int present;
            const unsigned char *data;
            size_t len;
        } optional;
        struct {
            size_t count;
            const unsigned char *data;
            size_t len;
        } array;
    } content;
} PacketField;

#define PACKET_TYPE_BOOL 1
#define PACKET_TYPE_BYTE 2
#define PACKET_TYPE_UBYTE 3
#define PACKET_TYPE_SHORT 4
#define PACKET_TYPE_US 5
#define PACKET_TYPE_INT 6
#define PACKET_TYPE_LONG 7
#define PACKET_TYPE_FLOAT 8
#define PACKET_TYPE_DOUBLE 9
#define PACKET_TYPE_STRING 10
#define PACKET_TYPE_VARINT 11
#define PACKET_TYPE_VARLONG 12
#define PACKET_TYPE_POSITION 13
#define PACKET_TYPE_ANGLE 14
#define PACKET_TYPE_UUID 15
#define PACKET_TYPE_BITSET 16
#define PACKET_TYPE_FIXED_BITSET 17
#define PACKET_TYPE_JSON_TEXT 18
#define PACKET_TYPE_IDENTIFIER 19
#define PACKET_TYPE_LONG_LONG 20
#define PACKET_TYPE_OPTIONAL 21
#define PACKET_TYPE_PREFIXED_OPTIONAL 22
#define PACKET_TYPE_ARRAY 23
#define PACKET_TYPE_PREFIXED_ARRAY 24
#define PACKET_TYPE_RAW 25

extern PacketField *packet;
extern size_t packet_count;
extern int packet_fd;
extern int fd_disconnected;

ssize_t packet_send_fd(int fd, const void *data, size_t len);
size_t packet_send_all(const void *data, size_t len);
ssize_t packet_send_bytes(const Bytes *packet);
int disconnect_fd(int fd);
int packet_build_template(const char *tmpl,
                          const PacketField *fields,
                          size_t field_count,
                          unsigned char *out,
                          size_t out_cap,
                          size_t *out_len);
int packet_parse_template_fields(const unsigned char *data,
                                 size_t data_len,
                                 const char *tmpl,
                                 PacketField *out,
                                 size_t out_cap,
                                 size_t *out_n);
int packet_send_template_fd(int fd, const char *tmpl, const PacketField *fields, size_t field_count);
int packet_send_template_current(const char *tmpl, const PacketField *fields, size_t field_count);

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

#define disconnect(fd) {disconnect_fd(fd); return;}

#endif
