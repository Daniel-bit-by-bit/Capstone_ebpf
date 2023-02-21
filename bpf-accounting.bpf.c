// +build ignore
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

// ---------------------------------------------
// -- The real program will be somewhere here --
struct bpf_map_def SEC("maps") cgroup_counters_map = {
    .type = BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    .key_size = sizeof(struct bpf_cgroup_storage_key),
    .value_size = sizeof(__u64),
};

// ---------------------------------------------

char __license[] __attribute__((section("license"), used)) = "MIT";
