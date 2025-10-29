#include "lantern/genesis/genesis.h"

#include "lantern/support/strings.h"
#include "lantern/support/secure_mem.h"
#include "internal/yaml_parser.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void free_validator_registry(struct lantern_validator_registry *registry);
static void free_validator_config(struct lantern_validator_config *config);
static void free_validator_config_entry(struct lantern_validator_config_entry *entry);

static int parse_chain_config(const char *path, struct lantern_chain_config *config);
static int parse_validator_registry(const char *path, struct lantern_validator_registry *registry);
static int parse_validator_registry_mapping(const char *path, struct lantern_validator_registry *registry);
static int parse_validator_config(const char *path, struct lantern_validator_config *config);
static int parse_nodes_file(const char *path, struct lantern_enr_record_list *list);
static int read_state_blob(const char *path, uint8_t **bytes, size_t *size);

static uint64_t parse_u64(const char *value, int *ok);
static char *dup_trimmed(const char *value);
static const char *yaml_object_value(const LanternYamlObject *object, const char *key);
static int read_scalar_value(const char *path, const char *key, char **out_value);

void lantern_genesis_artifacts_init(struct lantern_genesis_artifacts *artifacts) {
    if (!artifacts) {
        return;
    }
    memset(&artifacts->chain_config, 0, sizeof(artifacts->chain_config));
    lantern_enr_record_list_init(&artifacts->enrs);
    artifacts->validator_registry.records = NULL;
    artifacts->validator_registry.count = 0;
    artifacts->validator_config.shuffle = NULL;
    artifacts->validator_config.entries = NULL;
    artifacts->validator_config.count = 0;
    artifacts->state_bytes = NULL;
    artifacts->state_size = 0;
}

void lantern_genesis_artifacts_reset(struct lantern_genesis_artifacts *artifacts) {
    if (!artifacts) {
        return;
    }
    lantern_enr_record_list_reset(&artifacts->enrs);
    free_validator_registry(&artifacts->validator_registry);
    free_validator_config(&artifacts->validator_config);
    free(artifacts->state_bytes);
    artifacts->state_bytes = NULL;
    artifacts->state_size = 0;
    artifacts->chain_config.genesis_time = 0;
    artifacts->chain_config.validator_count = 0;
}

int lantern_genesis_load(struct lantern_genesis_artifacts *artifacts, const struct lantern_genesis_paths *paths) {
    if (!artifacts || !paths) {
        return -1;
    }

    if (!paths->config_path || !paths->validator_registry_path || !paths->nodes_path || !paths->state_path
        || !paths->validator_config_path) {
        fprintf(stderr, "lantern: missing required genesis path\n");
        return -1;
    }

    lantern_genesis_artifacts_reset(artifacts);
    lantern_genesis_artifacts_init(artifacts);

    if (parse_chain_config(paths->config_path, &artifacts->chain_config) != 0) {
        fprintf(stderr, "lantern: failed to parse chain config at %s\n", paths->config_path);
        goto error;
    }

    if (parse_validator_registry(paths->validator_registry_path, &artifacts->validator_registry) != 0) {
        fprintf(stderr, "lantern: failed to parse validator registry at %s\n", paths->validator_registry_path);
        goto error;
    }

    if (parse_nodes_file(paths->nodes_path, &artifacts->enrs) != 0) {
        fprintf(stderr, "lantern: failed to parse nodes at %s\n", paths->nodes_path);
        goto error;
    }

    if (parse_validator_config(paths->validator_config_path, &artifacts->validator_config) != 0) {
        fprintf(stderr, "lantern: failed to parse validator-config at %s\n", paths->validator_config_path);
        goto error;
    }

    if (read_state_blob(paths->state_path, &artifacts->state_bytes, &artifacts->state_size) != 0) {
        fprintf(stderr, "lantern: failed to read genesis state at %s\n", paths->state_path);
        goto error;
    }

    return 0;

error:
    lantern_genesis_artifacts_reset(artifacts);
    return -1;
}

const struct lantern_validator_config_entry *lantern_validator_config_find(
    const struct lantern_validator_config *config,
    const char *name) {
    if (!config || !name) {
        return NULL;
    }
    for (size_t i = 0; i < config->count; ++i) {
        if (config->entries[i].name && strcmp(config->entries[i].name, name) == 0) {
            return &config->entries[i];
        }
    }
    return NULL;
}

static void free_validator_registry(struct lantern_validator_registry *registry) {
    if (!registry || !registry->records) {
        return;
    }
    for (size_t i = 0; i < registry->count; ++i) {
        free(registry->records[i].pubkey_hex);
        free(registry->records[i].withdrawal_credentials_hex);
    }
    free(registry->records);
    registry->records = NULL;
    registry->count = 0;
}

static void free_validator_config(struct lantern_validator_config *config) {
    if (!config) {
        return;
    }
    if (config->entries) {
        for (size_t i = 0; i < config->count; ++i) {
            free_validator_config_entry(&config->entries[i]);
        }
        free(config->entries);
    }
    config->entries = NULL;
    config->count = 0;
    free(config->shuffle);
    config->shuffle = NULL;
}

static void free_validator_config_entry(struct lantern_validator_config_entry *entry) {
    if (!entry) {
        return;
    }
    free(entry->name);
    entry->name = NULL;
    if (entry->privkey_hex) {
        size_t len = strlen(entry->privkey_hex);
        if (len > 0) {
            lantern_secure_zero(entry->privkey_hex, len);
        }
        free(entry->privkey_hex);
    }
    entry->privkey_hex = NULL;
    free(entry->enr.ip);
    entry->enr.ip = NULL;
    entry->enr.quic_port = 0;
    entry->enr.sequence = 0;
    entry->count = 0;
}

static char *trim_whitespace(char *value) {
    while (*value && isspace((unsigned char)*value)) {
        ++value;
    }
    char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)*(end - 1))) {
        --end;
    }
    *end = '\0';
    return value;
}

static int parse_chain_config(const char *path, struct lantern_chain_config *config) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("lantern: fopen chain config");
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim_whitespace(line);
        if (*trimmed == '#' || *trimmed == '\0') {
            continue;
        }

        char *sep = strchr(trimmed, ':');
        if (!sep) {
            continue;
        }
        *sep = '\0';
        char *key = trimmed;
        char *value = trim_whitespace(sep + 1);

        if (strcmp(key, "GENESIS_TIME") == 0) {
            int ok = 0;
            config->genesis_time = parse_u64(value, &ok);
            if (!ok) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "VALIDATOR_COUNT") == 0) {
            int ok = 0;
            config->validator_count = parse_u64(value, &ok);
            if (!ok) {
                fclose(fp);
                return -1;
            }
        }
    }

    fclose(fp);

    if (config->genesis_time == 0 || config->validator_count == 0) {
        return -1;
    }
    return 0;
}

static int parse_validator_registry(const char *path, struct lantern_validator_registry *registry) {
    size_t count = 0;
    LanternYamlObject *objects = lantern_yaml_read_array(path, "validators", &count);
    if (!objects || count == 0) {
        lantern_yaml_free_objects(objects, count);
        return parse_validator_registry_mapping(path, registry);
    }

    bool has_pubkey_field = false;
    for (size_t i = 0; i < count; ++i) {
        if (yaml_object_value(&objects[i], "pubkey")) {
            has_pubkey_field = true;
            break;
        }
    }

    if (!has_pubkey_field) {
        lantern_yaml_free_objects(objects, count);
        return parse_validator_registry_mapping(path, registry);
    }

    bool have_explicit_indices = false;
    size_t max_index = 0;
    for (size_t i = 0; i < count; ++i) {
        const char *index_val = yaml_object_value(&objects[i], "index");
        if (!index_val) {
            continue;
        }
        int ok = 0;
        uint64_t parsed_index = parse_u64(index_val, &ok);
        if (ok) {
            have_explicit_indices = true;
            if (parsed_index > SIZE_MAX) {
                lantern_yaml_free_objects(objects, count);
                return -1;
            }
            if ((size_t)parsed_index > max_index) {
                max_index = (size_t)parsed_index;
            }
        }
    }

    size_t record_count = have_explicit_indices ? (max_index + 1) : count;
    struct lantern_validator_record *records = calloc(record_count, sizeof(*records));
    if (!records) {
        lantern_yaml_free_objects(objects, count);
        return -1;
    }

    bool *assigned = calloc(record_count, sizeof(*assigned));
    if (!assigned) {
        free(records);
        lantern_yaml_free_objects(objects, count);
        return -1;
    }

    for (size_t i = 0; i < count; ++i) {
        size_t slot = i;
        if (have_explicit_indices) {
            const char *index_val = yaml_object_value(&objects[i], "index");
            int ok = 0;
            uint64_t parsed_index = parse_u64(index_val, &ok);
            if (!index_val || !ok || parsed_index >= record_count) {
                free(assigned);
                free_validator_registry(&(struct lantern_validator_registry){.records = records, .count = record_count});
                lantern_yaml_free_objects(objects, count);
                return -1;
            }
            slot = (size_t)parsed_index;
        }

        if (assigned[slot]) {
            free(assigned);
            free_validator_registry(&(struct lantern_validator_registry){.records = records, .count = record_count});
            lantern_yaml_free_objects(objects, count);
            return -1;
        }

        const char *pubkey = yaml_object_value(&objects[i], "pubkey");
        const char *withdrawal = yaml_object_value(&objects[i], "withdrawal_credentials");
        if (!pubkey || !withdrawal) {
            free(assigned);
            free_validator_registry(&(struct lantern_validator_registry){.records = records, .count = record_count});
            lantern_yaml_free_objects(objects, count);
            return -1;
        }

        char *pubkey_hex = dup_trimmed(pubkey);
        char *withdrawal_hex = dup_trimmed(withdrawal);
        if (!pubkey_hex || !withdrawal_hex) {
            free(pubkey_hex);
            free(withdrawal_hex);
            free(assigned);
            free_validator_registry(&(struct lantern_validator_registry){.records = records, .count = record_count});
            lantern_yaml_free_objects(objects, count);
            return -1;
        }

        records[slot].index = (uint64_t)slot;
        records[slot].pubkey_hex = pubkey_hex;
        records[slot].withdrawal_credentials_hex = withdrawal_hex;
        assigned[slot] = true;
    }

    if (have_explicit_indices) {
        for (size_t i = 0; i < record_count; ++i) {
            if (!assigned[i]) {
                free(assigned);
                free_validator_registry(&(struct lantern_validator_registry){.records = records, .count = record_count});
                lantern_yaml_free_objects(objects, count);
                return -1;
            }
        }
    }

    free(assigned);
    lantern_yaml_free_objects(objects, count);
    registry->records = records;
    registry->count = record_count;
    return 0;
}

static int parse_validator_registry_mapping(const char *path, struct lantern_validator_registry *registry) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    size_t *indices = NULL;
    size_t count = 0;
    size_t capacity = 0;
    size_t max_index = 0;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim_whitespace(line);
        if (!trimmed || *trimmed != '-') {
            continue;
        }
        ++trimmed;
        while (*trimmed && isspace((unsigned char)*trimmed)) {
            ++trimmed;
        }
        if (*trimmed == '\0') {
            continue;
        }
        char *endptr = NULL;
        unsigned long long value = strtoull(trimmed, &endptr, 10);
        if (endptr == trimmed) {
            continue;
        }
        if (value > SIZE_MAX) {
            fclose(fp);
            free(indices);
            return -1;
        }
        if (count == capacity) {
            size_t new_capacity = capacity == 0 ? 8 : capacity * 2;
            size_t *new_indices = realloc(indices, new_capacity * sizeof(*new_indices));
            if (!new_indices) {
                fclose(fp);
                free(indices);
                return -1;
            }
            indices = new_indices;
            capacity = new_capacity;
        }
        indices[count++] = (size_t)value;
        if ((size_t)value > max_index) {
            max_index = (size_t)value;
        }
    }
    fclose(fp);

    if (count == 0) {
        free(indices);
        return -1;
    }

    size_t record_count = max_index + 1;
    struct lantern_validator_record *records = calloc(record_count, sizeof(*records));
    if (!records) {
        free(indices);
        return -1;
    }

    const char *zero_hex = "0x00";
    for (size_t i = 0; i < record_count; ++i) {
        records[i].index = i;
        records[i].pubkey_hex = strdup(zero_hex);
        records[i].withdrawal_credentials_hex = strdup(zero_hex);
        if (!records[i].pubkey_hex || !records[i].withdrawal_credentials_hex) {
            free_validator_registry(&(struct lantern_validator_registry){.records = records, .count = record_count});
            free(indices);
            return -1;
        }
    }

    registry->records = records;
    registry->count = record_count;
    free(indices);
    return 0;
}

static int parse_validator_config(const char *path, struct lantern_validator_config *config) {
    if (read_scalar_value(path, "shuffle", &config->shuffle) != 0) {
        return -1;
    }

    size_t count = 0;
    LanternYamlObject *objects = lantern_yaml_read_array(path, "validators", &count);
    if (!objects || count == 0) {
        lantern_yaml_free_objects(objects, count);
        return -1;
    }

    struct lantern_validator_config_entry *entries = calloc(count, sizeof(*entries));
    if (!entries) {
        lantern_yaml_free_objects(objects, count);
        return -1;
    }

    for (size_t i = 0; i < count; ++i) {
        const char *name_val = yaml_object_value(&objects[i], "name");
        const char *priv_val = yaml_object_value(&objects[i], "privkey");
        const char *count_val = yaml_object_value(&objects[i], "count");
        const char *ip_val = yaml_object_value(&objects[i], "ip");
        const char *quic_val = yaml_object_value(&objects[i], "quic");
        const char *seq_val = yaml_object_value(&objects[i], "seq");

        entries[i].name = dup_trimmed(name_val);
        entries[i].privkey_hex = dup_trimmed(priv_val);

        int ok = 0;
        entries[i].count = parse_u64(count_val, &ok);
        if (!ok) {
            lantern_yaml_free_objects(objects, count);
            free_validator_config_entry(&entries[i]);
            free(entries);
            return -1;
        }

        entries[i].enr.ip = dup_trimmed(ip_val);
        uint64_t quic_port = parse_u64(quic_val, &ok);
        if (!ok || quic_port > UINT16_MAX) {
            lantern_yaml_free_objects(objects, count);
            free_validator_config_entry(&entries[i]);
            free(entries);
            return -1;
        }
        entries[i].enr.quic_port = (uint16_t)quic_port;

        entries[i].enr.sequence = parse_u64(seq_val, &ok);
        if (!ok) {
            lantern_yaml_free_objects(objects, count);
            free_validator_config_entry(&entries[i]);
            free(entries);
            return -1;
        }
    }

    lantern_yaml_free_objects(objects, count);
    config->entries = entries;
    config->count = count;
    return 0;
}

static int parse_nodes_file(const char *path, struct lantern_enr_record_list *list) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("lantern: fopen nodes");
        return -1;
    }

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim_whitespace(line);
        if (*trimmed == '#' || *trimmed == '\0') {
            continue;
        }
        char *enr = strstr(trimmed, "enr:");
        if (!enr) {
            continue;
        }
        enr = trim_whitespace(enr);
        if (*enr == '\0') {
            continue;
        }
        if (lantern_enr_record_list_append(list, enr) != 0) {
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

static int read_state_blob(const char *path, uint8_t **bytes, size_t *size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("lantern: fopen genesis ssz");
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    uint8_t *buffer = malloc((size_t)file_size);
    if (!buffer) {
        fclose(fp);
        return -1;
    }

    size_t read_bytes = fread(buffer, 1, (size_t)file_size, fp);
    fclose(fp);
    if (read_bytes != (size_t)file_size) {
        free(buffer);
        return -1;
    }

    *bytes = buffer;
    *size = read_bytes;
    return 0;
}

static uint64_t parse_u64(const char *value, int *ok) {
    if (ok) {
        *ok = 0;
    }
    if (!value) {
        return 0;
    }

    char *end = NULL;
    errno = 0;
    uint64_t parsed = strtoull(value, &end, 0);
    if (errno != 0 || end == value) {
        return 0;
    }
    if (ok) {
        *ok = 1;
    }
    return parsed;
}

static char *dup_trimmed(const char *value) {
    if (!value) {
        return NULL;
    }
    const char *start = value;
    while (*start && isspace((unsigned char)*start)) {
        ++start;
    }
    const char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)*(end - 1))) {
        --end;
    }

    if (end - start >= 2 && ((*start == '"' && *(end - 1) == '"') || (*start == '\'' && *(end - 1) == '\''))) {
        ++start;
        --end;
    }

    return lantern_string_duplicate_len(start, (size_t)(end - start));
}

static const char *yaml_object_value(const LanternYamlObject *object, const char *key) {
    if (!object || !key) {
        return NULL;
    }
    for (size_t i = 0; i < object->num_pairs; ++i) {
        if (object->pairs[i].key && strcmp(object->pairs[i].key, key) == 0) {
            return object->pairs[i].value;
        }
    }
    return NULL;
}

static int read_scalar_value(const char *path, const char *key, char **out_value) {
    if (!path || !key || !out_value) {
        return -1;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("lantern: fopen validator-config");
        return -1;
    }

    char line[1024];
    size_t key_len = strlen(key);
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim_whitespace(line);
        if (*trimmed == '#' || *trimmed == '\0') {
            continue;
        }

        if (strncmp(trimmed, key, key_len) != 0) {
            continue;
        }
        if (trimmed[key_len] != ':') {
            continue;
        }

        char *value = trim_whitespace(trimmed + key_len + 1);
        *out_value = dup_trimmed(value);
        fclose(fp);
        return *out_value ? 0 : -1;
    }

    fclose(fp);
    return -1;
}
