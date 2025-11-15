#ifndef LANTERN_FIXTURE_RUNNER_H
#define LANTERN_FIXTURE_RUNNER_H

#include <stdbool.h>
#include <stddef.h>

struct lantern_fixture_run_config {
    const char *suite_name;
    const char *state_transition_subdir;
    const char *fork_choice_subdir; /* Optional when include_fork_choice is false */
    bool include_fork_choice;
};

int lantern_run_fixture_suite(const struct lantern_fixture_run_config *config);

#endif /* LANTERN_FIXTURE_RUNNER_H */
