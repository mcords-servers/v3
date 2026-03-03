#include "kit.h"
#include <curl/curl.h>

typedef struct HttpBuffer {
    char *data;
    size_t length;
} HttpBuffer;

typedef struct HttpResponse {
    CURL *easy;
    struct curl_slist *headers;
    HttpBuffer body;

    char *url;
    char *post_data;
    int is_post;

    long status;
    int done;
    int started;
} HttpResponse;

static CURLM *multi;
static HttpResponse **requests;
static size_t request_count;
static int http_ready;

static size_t write_callback(void *data, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    HttpBuffer *buf = (HttpBuffer *)userp;

    char *next = realloc(buf->data, buf->length + total + 1);
    if (!next) return 0;

    buf->data = next;
    memcpy(buf->data + buf->length, data, total);
    buf->length += total;
    buf->data[buf->length] = '\0';

    return total;
}

static void free_request(HttpResponse *req) {
    if (!req) return;

    if (req->easy && multi && req->started) {
        curl_multi_remove_handle(multi, req->easy);
    }
    if (req->easy) curl_easy_cleanup(req->easy);
    if (req->headers) curl_slist_free_all(req->headers);

    free(req->url);
    free(req->post_data);
    free(req->body.data);
    free(req);
}

static int add_header(HttpResponse *req, const char *header) {
    if (!req || !header || !header[0]) return 1;
    struct curl_slist *tmp = curl_slist_append(req->headers, header);
    if (!tmp) return 0;
    req->headers = tmp;
    return 1;
}

static HttpResponse *create_request(const char *url, const char *data, const char *content_type,
                                    const char *const *headers, size_t header_count, int is_post) {
    if (!url || (is_post && !data)) return NULL;

    http_init();
    if (!http_ready) return NULL;

    HttpResponse *req = calloc(1, sizeof(*req));
    if (!req) return NULL;

    req->url = strdup(url);
    req->is_post = is_post;
    if (is_post) req->post_data = strdup(data);

    if (!req->url || (is_post && !req->post_data)) {
        free_request(req);
        return NULL;
    }

    if (content_type) {
        char header[256];
        snprintf(header, sizeof(header), "Content-Type: %s", content_type);
        if (!add_header(req, header)) {
            free_request(req);
            return NULL;
        }
    }

    for (size_t i = 0; i < header_count; i++) {
        if (!add_header(req, headers[i])) {
            free_request(req);
            return NULL;
        }
    }

    HttpResponse **tmp = realloc(requests, (request_count + 1) * sizeof(*requests));
    if (!tmp) {
        free_request(req);
        return NULL;
    }

    requests = tmp;
    requests[request_count++] = req;
    return req;
}

void http_init(void) {
    if (http_ready) return;

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return;
    multi = curl_multi_init();
    if (!multi) {
        curl_global_cleanup();
        return;
    }

    http_ready = 1;
}

void http_cleanup(void) {
    if (!http_ready) return;

    for (size_t i = 0; i < request_count; i++) {
        free_request(requests[i]);
    }
    free(requests);
    requests = NULL;
    request_count = 0;

    curl_multi_cleanup(multi);
    multi = NULL;
    curl_global_cleanup();
    http_ready = 0;
}

void http_free(HttpResponse *req) {
    if (!req || !requests) return;

    for (size_t i = 0; i < request_count; i++) {
        if (requests[i] != req) continue;

        free_request(req);

        if (i + 1 < request_count) {
            memmove(&requests[i], &requests[i + 1],
                    (request_count - i - 1) * sizeof(*requests));
        }

        request_count -= 1;
        if (request_count == 0) {
            free(requests);
            requests = NULL;
        } else {
            HttpResponse **tmp = realloc(requests, request_count * sizeof(*requests));
            if (tmp) requests = tmp;
        }
        return;
    }
}

HttpResponse *http_post_headers(const char *url, const char *data, const char *content_type,
                                const char *const *headers, size_t header_count) {
    return create_request(url, data, content_type, headers, header_count, 1);
}

HttpResponse *http_post(const char *url, const char *data, const char *content_type) {
    return http_post_headers(url, data, content_type, NULL, 0);
}

HttpResponse *http_get_headers(const char *url, const char *const *headers, size_t header_count) {
    return create_request(url, NULL, NULL, headers, header_count, 0);
}

HttpResponse *http_get(const char *url) {
    return http_get_headers(url, NULL, 0);
}

void http_perform(void) {
    if (!http_ready || !multi) return;

    for (size_t i = 0; i < request_count; i++) {
        HttpResponse *req = requests[i];

        if (req->started) continue;

        req->easy = curl_easy_init();
        if (!req->easy) {
            req->done = 1;
            continue;
        }

        curl_easy_setopt(req->easy, CURLOPT_URL, req->url);
        if (req->is_post) {
            curl_easy_setopt(req->easy, CURLOPT_POSTFIELDS, req->post_data);
        } else {
            curl_easy_setopt(req->easy, CURLOPT_HTTPGET, 1L);
        }
        curl_easy_setopt(req->easy, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(req->easy, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(req->easy, CURLOPT_WRITEDATA, &req->body);
        curl_easy_setopt(req->easy, CURLOPT_PRIVATE, req);

        if (req->headers) curl_easy_setopt(req->easy, CURLOPT_HTTPHEADER, req->headers);

        curl_multi_add_handle(multi, req->easy);
        req->started = 1;
    }

    int still_running = 0;
    curl_multi_perform(multi, &still_running);

    int numfds = 0;
    curl_multi_wait(multi, NULL, 0, 0, &numfds);

    int msgs_left = 0;
    CURLMsg *msg = NULL;
    while ((msg = curl_multi_info_read(multi, &msgs_left))) {
        if (msg->msg != CURLMSG_DONE) continue;

        HttpResponse *req = NULL;
        curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, (void **)&req);
        if (!req) continue;

        curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &req->status);
        req->done = 1;
        curl_multi_remove_handle(multi, msg->easy_handle);
    }
}

int http_done(HttpResponse *req) {
    return req ? req->done : 1;
}

long http_status(HttpResponse *req) {
    return req ? req->status : 0;
}

const char *http_body(HttpResponse *req) {
    return (req && req->body.data) ? req->body.data : "";
}

size_t http_body_length(HttpResponse *req) {
    return req ? req->body.length : 0;
}

static void tick_requests(ptr unused) {
    (void)unused;
    http_perform();
}

static void cleanup_requests(ptr unused) {
    (void)unused;
    http_cleanup();
}

__attribute__((constructor))
static void start(void) {
    LOG("Module %s loaded", FILENAME);
    http_init();
    on_event(EVENT_LPS, tick_requests);
    on_event(EVENT_FRE, cleanup_requests);
}
