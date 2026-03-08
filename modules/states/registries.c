#include "kit.h"

static size_t append_varint(unsigned char *dst, int value) {
    size_t out = 0;
    unsigned int v = (unsigned int)value;
    do {
        unsigned char byte = (unsigned char)(v & 0x7F);
        v >>= 7;
        if (v) byte |= 0x80;
        dst[out++] = byte;
    } while (v);
    return out;
}

static size_t append_identifier(unsigned char *dst, const char *id) {
    size_t len = strlen(id);
    size_t off = append_varint(dst, (int)len);
    memcpy(dst + off, id, len);
    return off + len;
}

static void send_registry(PlayerInfo *p, const char *registry_id, const char **entries, size_t entry_count) {
    unsigned char encoded[4096];
    size_t off = 0;

    for (size_t i = 0; i < entry_count; i++) {
        off += append_identifier(encoded + off, entries[i]);
        encoded[off++] = 0; /* TAG_End => null/absent NBT payload */
    }

    PacketField fields[4];
    fields[0].content.varint = 0x07; /* Clientbound Registry Data (Configuration) */
    fields[1].content.string.data = registry_id;
    fields[1].content.string.len = strlen(registry_id);
    fields[2].content.varint = (int)entry_count;
    fields[3].content.array.data = encoded;
    fields[3].content.array.len = off;
    packet_send_template_fd(p->fd, "v id v arr", fields, 4);
}

static void on_packet(PlayerInfo *p) {
    if (!p) return;

    static const char *optional_registries[] = {
        "minecraft:worldgen/biome",
        "minecraft:chat_type",
        "minecraft:dimension_type",
        "minecraft:dialog",
        "minecraft:banner_pattern",
        "minecraft:enchantment",
        "minecraft:jukebox_song",
        "minecraft:instrument",
        "minecraft:test_environment",
        "minecraft:test_instance",
        "minecraft:trim_material",
        "minecraft:trim_pattern"
    };

    static const char *damage_type_entries[] = {
        "minecraft:cactus",
        "minecraft:campfire",
        "minecraft:cramming",
        "minecraft:dragon_breath",
        "minecraft:drown",
        "minecraft:dry_out",
        "minecraft:ender_pearl",
        "minecraft:fall",
        "minecraft:fly_into_wall",
        "minecraft:freeze",
        "minecraft:generic",
        "minecraft:generic_kill",
        "minecraft:hot_floor",
        "minecraft:in_fire",
        "minecraft:in_wall",
        "minecraft:lava",
        "minecraft:lightning_bolt",
        "minecraft:magic",
        "minecraft:on_fire",
        "minecraft:out_of_world",
        "minecraft:outside_border",
        "minecraft:stalagmite",
        "minecraft:starve",
        "minecraft:sweet_berry_bush",
        "minecraft:wither"
    };

    static const char *cat_variant_entries[] = {"minecraft:tabby"};
    static const char *chicken_variant_entries[] = {"minecraft:temperate"};
    static const char *cow_variant_entries[] = {"minecraft:temperate"};
    static const char *frog_variant_entries[] = {"minecraft:temperate"};
    static const char *painting_variant_entries[] = {"minecraft:kebab"};
    static const char *pig_variant_entries[] = {"minecraft:temperate"};
    static const char *wolf_sound_variant_entries[] = {"minecraft:classic"};
    static const char *wolf_variant_entries[] = {"minecraft:pale"};

    for (size_t i = 0; i < sizeof(optional_registries) / sizeof(optional_registries[0]); i++) {
        send_registry(p, optional_registries[i], NULL, 0);
    }

    send_registry(p, "minecraft:cat_variant", cat_variant_entries, 1);
    send_registry(p, "minecraft:chicken_variant", chicken_variant_entries, 1);
    send_registry(p, "minecraft:cow_variant", cow_variant_entries, 1);
    send_registry(p, "minecraft:frog_variant", frog_variant_entries, 1);
    send_registry(p, "minecraft:painting_variant", painting_variant_entries, 1);
    send_registry(p, "minecraft:pig_variant", pig_variant_entries, 1);
    send_registry(p, "minecraft:wolf_sound_variant", wolf_sound_variant_entries, 1);
    send_registry(p, "minecraft:wolf_variant", wolf_variant_entries, 1);
    send_registry(
        p,
        "minecraft:damage_type",
        damage_type_entries,
        sizeof(damage_type_entries) / sizeof(damage_type_entries[0])
    );
}

__attribute__((constructor))
static void start(void) {
    on_event(EVENT_REG, on_packet);
}
