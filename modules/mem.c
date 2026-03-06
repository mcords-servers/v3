#include "kit.h"

void *mem_add(int fd, void *ptr) {
    Memory *mem = (Memory *)fds_get(fd, "__memory");

    if (!mem) {
        mem = malloc(sizeof(*mem));
        if (!mem) return NULL;

        mem->ptr = ptr;
        mem->next = NULL;
        fds_set(fd, "__memory", mem);
        return ptr;
    }

    Memory *current = mem;
    while (current) {
        if (current->ptr == ptr) return ptr;
        if (!current->next) break;
        current = current->next;
    }

    Memory *node = malloc(sizeof(*node));
    if (!node) return NULL;
    node->ptr = ptr;
    node->next = NULL;
    current->next = node;
    return ptr;
}

void mem_free(int fd) {
    Memory *mem = (Memory *)fds_get(fd, "__memory");
    while (mem) {
        free(mem->ptr);
        Memory *next = mem->next;
        free(mem);
        mem = next;
    }
    (void)fds_del(fd, "__memory");
}

__attribute__((constructor))
static void start(void) {
    LOG("Module %s loaded", FILENAME);
}

