#include "kit.h"

static FdData **fd_store;
static size_t fd_store_cap;

static int ensure_cap(int fd) {
    if (fd < 0) return 0;
    size_t need = (size_t)fd + 1;
    if (need <= fd_store_cap) return 1;

    size_t next = fd_store_cap ? fd_store_cap : 64;
    while (next < need) next *= 2;
    FdData **grown = realloc(fd_store, next * sizeof(*grown));
    if (!grown) return 0;
    memset(grown + fd_store_cap, 0, (next - fd_store_cap) * sizeof(*grown));
    fd_store = grown;
    fd_store_cap = next;
    return 1;
}

static FdData *find_node(int fd, const char *key, FdData **prev_out) {
    if (prev_out) *prev_out = NULL;
    if (fd < 0 || !key) return NULL;
    if ((size_t)fd >= fd_store_cap) return NULL;

    FdData *prev = NULL;
    FdData *cur = fd_store[fd];
    while (cur) {
        if (strcmp(cur->key, key) == 0) {
            if (prev_out) *prev_out = prev;
            return cur;
        }
        prev = cur;
        cur = cur->next;
    }

    if (prev_out) *prev_out = prev;
    return NULL;
}

void *fds_set(int fd, const char *key, void *ptr) {
    if (fd < 0 || !key) return NULL;
    if (!ensure_cap(fd)) return NULL;

    FdData *prev = NULL;
    FdData *cur = find_node(fd, key, &prev);
    if (cur) {
        if (cur->owned && cur->ptr) free(cur->ptr);
        cur->ptr = ptr;
        cur->owned = 0;
        return cur;
    }

    FdData *node = malloc(sizeof(*node));
    if (!node) return NULL;
    node->key = strdup(key);
    if (!node->key) {
        free(node);
        return NULL;
    }
    node->ptr = ptr;
    node->owned = 0;
    node->next = NULL;

    if (!prev) fd_store[fd] = node;
    else prev->next = node;
    return node;
}

void *fds_get(int fd, const char *key) {
    FdData *node = find_node(fd, key, NULL);
    return node ? node->ptr : NULL;
}

void *fds_del(int fd, const char *key) {
    if (fd < 0 || !key) return NULL;
    if ((size_t)fd >= fd_store_cap) return NULL;

    FdData *prev = NULL;
    FdData *cur = find_node(fd, key, &prev);
    if (!cur) return NULL;

    if (!prev) fd_store[fd] = cur->next;
    else prev->next = cur->next;

    void *ret = cur->ptr;
    if (cur->owned && ret) {
        free(ret);
        ret = NULL;
    }
    free(cur->key);
    free(cur);
    return ret;
}

int fds_incr(int fd, const char *key) {
    int *counter = (int *)fds_get(fd, key);
    if (!counter) {
        counter = malloc(sizeof(*counter));
        if (!counter) return -1;
        *counter = 0;
        FdData *node = (FdData *)fds_set(fd, key, counter);
        if (!node) {
            free(counter);
            return -1;
        }
        node->owned = 0;
        if (!mem_add(fd, counter)) {
            (void)fds_del(fd, key);
            free(counter);
            return -1;
        }
    }

    *counter += 1;
    return *counter;
}

void fds_clear_fd(int fd) {
    if (fd < 0) return;
    if ((size_t)fd >= fd_store_cap) return;

    mem_free(fd);

    FdData *cur = fd_store[fd];
    while (cur) {
        FdData *next = cur->next;
        if (cur->owned && cur->ptr) free(cur->ptr);
        free(cur->key);
        free(cur);
        cur = next;
    }
    fd_store[fd] = NULL;
}

void fds_clear_all(void) {
    for (size_t fd = 0; fd < fd_store_cap; fd++) {
        if (!fd_store[fd]) continue;
        fds_clear_fd((int)fd);
    }
    free(fd_store);
    fd_store = NULL;
    fd_store_cap = 0;
}

static void fds_cleanup(ptr unused) {
    (void)unused;
    fds_clear_all();
}

__attribute__((constructor))
static void start(void) {
    LOG("Module %s loaded", FILENAME);
    on_event(EVENT_FRE, fds_cleanup);
}
