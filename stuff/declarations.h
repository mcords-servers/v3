#ifndef D_H
#define D_H

#include "kit.h"

typedef struct HttpResponse HttpResponse;

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
        int varint;
        unsigned short us;
        struct {
            const char *data;
            size_t len;
        } string;
        long long ll;
    } content;
} PacketField;

extern PacketField *packet;
extern size_t packet_count;
extern int packet_fd;

ssize_t packet_send_fd(int fd, const void *data, size_t len);
size_t packet_send_all(const void *data, size_t len);
ssize_t packet_send_bytes(const Bytes *packet);

#define EVENT (void *)0
#define EVENT_LPS (void *)1
#define EVENT_FRE (void *)2
#define EVENT_PKT_RAW (void *)3
#define EVENT_PKT (void *)4

#endif
