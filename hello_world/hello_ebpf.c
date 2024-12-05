// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event
{
  u32 pid;
  u8 comm[100];
};

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096 * 2);
} events SEC(".maps");

// Force emitting struct event into the ELF
const struct event *unused __attribute__((unused));

SEC("kprobe/sys_execve")
int hello_execve(struct pt_regs *ctx)
{
  u64 id = bpf_get_current_pid_tgid();
  pid_t pid = id >> 32;
  pid_t tid = (u32)id;

  if (pid != tid)
    return 0;

  struct event *e;

  e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!e)
  {
    return 0;
  }

  e->pid = pid;
  bpf_get_current_comm(&e->comm, 100);

  bpf_ringbuf_submit(e, 0);

  return 0;
}
