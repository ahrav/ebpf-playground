// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") counting_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 3, // Store bytes allocated, page count, and total page bytes
};

struct kmem_cache_alloc_info
{
  unsigned long pad;       // first 8 bytes padded
  unsigned long call_site; // offset 8
  const void *ptr;         // offset 16
  size_t bytes_req;        // offset 24
  size_t bytes_alloc;      // offset 32
  unsigned int gfp_flags;  // offset 40
};

struct mm_page_alloc_info {
    unsigned short common_type;         // offset 0
    unsigned char common_flags;         // offset 2
    unsigned char common_preempt_count; // offset 3
    int common_pid;                     // offset 4
    unsigned long pfn;                  // offset 8
    unsigned int order;                 // offset 16
    unsigned int gfp_flags;             // offset 20
    int migratetype;                    // offset 24
};

// Add a map to store our PID
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} pid_map SEC(".maps");

struct allocation_info {
    __u32 pid;
    char comm[16];
    __u32 order;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/kmem/kmem_cache_alloc")
int kmem_cache_alloc(struct kmem_cache_alloc_info *info)
{
  u32 key = 0;
  u32 *our_pid = bpf_map_lookup_elem(&pid_map, &key);
  if (our_pid && *our_pid == (bpf_get_current_pid_tgid() >> 32)) {
    return 0;
  }

  u64 *valp;

  valp = bpf_map_lookup_elem(&counting_map, &key);
  if (!valp)
  {
    u64 initval = info->bytes_alloc;
    bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
    return 0;
  }
  __sync_fetch_and_add(valp, info->bytes_alloc);
  return 0;
}

SEC("tracepoint/kmem/mm_page_alloc")
int mm_page_alloc(struct mm_page_alloc_info *info)
{
  u32 key = 0;
  u32 *our_pid = bpf_map_lookup_elem(&pid_map, &key);
  if (our_pid && (bpf_get_current_pid_tgid() >> 32) == *our_pid) {
    return 0;
  }

  struct allocation_info *event;
  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    return 0;
  }

  event->pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));
  event->order = info->order;
  event->timestamp = bpf_ktime_get_ns();

  bpf_ringbuf_submit(event, 0);

  // Update page count
  key = 1; // Key 1 for page count
  u64 *valp;

  valp = bpf_map_lookup_elem(&counting_map, &key);
  if (!valp)
  {
    u64 initval = 1;
    bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
  }
  else
  {
    __sync_fetch_and_add(valp, 1);
  }

  // Update total page bytes
  key = 2; // Key 2 for total page bytes
  valp = bpf_map_lookup_elem(&counting_map, &key);
  u64 page_bytes = ((u64)1 << info->order) * 4096; // 4096 is the page size
  if (!valp)
  {
    bpf_map_update_elem(&counting_map, &key, &page_bytes, BPF_ANY);
  }
  else
  {
    __sync_fetch_and_add(valp, page_bytes);
  }

  return 0;
}
