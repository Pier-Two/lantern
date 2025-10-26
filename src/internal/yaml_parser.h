#ifndef LANTERN_INTERNAL_YAML_PARSER_H
#define LANTERN_INTERNAL_YAML_PARSER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char *key;
    char *value;
} LanternYamlKeyValPair;

typedef struct {
    LanternYamlKeyValPair *pairs;
    size_t num_pairs;
    size_t capacity;
} LanternYamlObject;

LanternYamlObject *lantern_yaml_read_array(const char *file_path, const char *array_name, size_t *out_count);
void lantern_yaml_free_objects(LanternYamlObject *objects, size_t count);

#endif /* LANTERN_INTERNAL_YAML_PARSER_H */
