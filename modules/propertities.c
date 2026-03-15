#include "kit.h"
#include <ctype.h>

typedef struct ConfigEntry {
    char *key;
    char *value;
} ConfigEntry;

static ConfigEntry *entries;
static size_t entry_count;
static char entries_loaded;

static size_t entry_len(void) {
    size_t n = 0;
    while (entries && entries[n].key) n++;
    return n;
}

static char *trim_ws(char *s) {
    if (!s) return s;
    while (*s && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')) s++;
    if (*s == '\0') return s;

    char *end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end-- = '\0';
    }
    return s;
}

static int set_entry(const char *key, const char *value) {
    if (!key || !key[0]) return 0;
    size_t len = entry_len();
    for (size_t i = 0; i < len; i++) {
        if (strcmp(entries[i].key, key) == 0) {
            char *next = strdup(value ? value : "");
            if (!next) return 0;
            free(entries[i].value);
            entries[i].value = next;
            return 1;
        }
    }

    ConfigEntry *grown = realloc(entries, (len + 2) * sizeof(*grown));
    if (!grown) return 0;
    entries = grown;

    entries[len].key = strdup(key);
    entries[len].value = strdup(value ? value : "");
    if (!entries[len].key || !entries[len].value) {
        free(entries[len].key);
        free(entries[len].value);
        return 0;
    }
    entries[len + 1].key = NULL;
    entries[len + 1].value = NULL;
    return 1;
}

static void load_properties_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        char *raw = trim_ws(line);
        if (raw[0] == '\0') continue;
        if (raw[0] == '#' || raw[0] == ';') continue;
        if (!isalpha((unsigned char)raw[0])) continue;

        char *eq = strchr(raw, '=');
        char *key = NULL;
        char *value = NULL;
        if (eq) {
            *eq = '\0';
            key = trim_ws(raw);
            value = trim_ws(eq + 1);
        } else {
            key = trim_ws(raw);
            value = "";
        }

        entry_count += 1;
        if (!key || key[0] == '\0') continue;
        if (strpbrk(key, " \t")) continue;
        if (!value || value[0] == '\0') continue;
        if (!set_entry(key, value)) {
            LOG("Failed to store config '%s'", key);
        }
    }

    fclose(f);
}

static inline void ensure_loaded(void) {
    if (entries_loaded) return;
    entries_loaded = 1;
    load_properties_file("server.properties");
}

char *get_config(char *name) {
    if (!name || !name[0]) return NULL;
    ensure_loaded();
    for (size_t i = 0; entries && entries[i].key; i++) {
        if (strcmp(entries[i].key, name) == 0) return entries[i].value;
    }
    return NULL;
}

static void config_cleanup(ptr unused) {
    (void)unused;
    for (size_t i = 0; entries && entries[i].key; i++) {
        free(entries[i].key);
        free(entries[i].value);
    }
    free(entries);
    entries = NULL;
    entry_count = 0;
    entries_loaded = 0;
}

__attribute__((constructor))
static void properties_start(void) {
    ensure_loaded();
    LOG("Module %s loaded (%zu config entries)", FILENAME, entry_count);
    on_event(EVENT_FRE, config_cleanup);
}
