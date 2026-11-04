// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler BPF core.
 *
 * One entry file with ordered includes and an upstream pair queue.
 * Tasks enter the pair queue by vtime, else fall back to the LLC DSQ.
 * Dispatch drains pair, then LLC, then fallback safety net. Single LLC
 * bypasses pairing and uses the LLC DSQ directly. Stats are per LLC
 * with queued charged to the enqueue LLC and dispatched counted on
 * the dispatch LLC. Pair mode is strict priority and picks the lowest
 * vtime with ties going to strand A. A running snapshot with slice
 * decay drives threshold preempt. Requeue keeps remaining slice and
 * advances vtime through the per pair sequence. Stealing walks own
 * pair, same node pairs, remote pairs, LLC queues. A per CPU hint
 * tracks burnt share and asks the governor for full speed when busy
 * and half speed when idle. The hint needs the schedutil governor
 * and hardware support and never changes placement. A task with one
 * allowed CPU or with migration disabled bypasses pairing and goes
 * straight to the local queue of its allowed CPU with its enqueue
 * flags kept. Exiting tasks keep single ownership through the queued
 * flag, then wait on the local queue of the target CPU with a minimal
 * slice and an idle kick only. When no local target exists they fall
 * back to the LLC or fallback queue with the same minimal slice so
 * no wakeup is lost. Dispatch pops with a bounded retry so one stale
 * or exiting entry never stalls the queue. Every pop either reaches
 * local or goes back to a victim or fallback queue with no loss.
 * Kick preempts only when the target is allowed, else it wakes idle.
 * Dispatch moves a task to local only when the peeked head
 * can run on this CPU, else the DSQ is left alone with no loss. No SMT
 * probe runs and each CPU stands single with fail closed choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <lib/arena_map.h>
#include <lib/dhq.h>
#include <lib/minheap.h>
#include <lib/sdt_alloc.h>
#include <lib/spinlock.h>
#include "intf.h"
/* The verifier ties a program to the arena on address use. */
/* Keep one use in each program that reaches arena memory. */
/* Init plus enqueue plus dispatch reach the arena, the rest use only */
/* maps and task storage and need no touch. Enqueue reaches the arena */
/* through insert, dispatch covers pop to local through the same touch. */
#define TOUCH_ARENA() do { asm volatile("" :: "r"(&arena)); } while (0)
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
/* Maps plus pair tables. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_ctx);
} cpu_ctx_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_LLCS);
	__type(key, u32);
	__type(value, struct flow_llc_stats);
} llc_stats_stor SEC(".maps");
volatile u64 flow_nr_cpus;
volatile u64 flow_nr_llcs;
scx_dhq_t *flow_pair_dhqs[FLOW_MAX_PAIRS];
u64 flow_llc_pair[FLOW_MAX_LLCS];
u64 flow_llc_strand[FLOW_MAX_LLCS];
u32 flow_node_count[FLOW_MAX_NODES];
u64 flow_node_last_pair[FLOW_MAX_NODES];
u32 flow_pair_count;
/* Per CPU running snapshot. Zero init means empty. */
struct flow_running_state flow_running_state[FLOW_MAX_CPUS];
/* Per CPU hint state. Zero init means empty. Persists across events. */
struct flow_freq_state flow_freq_state[FLOW_MAX_CPUS];
/* Per pair last vtime for monotonic unique assign. Zero init. */
s64 flow_dhq_seq[FLOW_MAX_PAIRS];
/* Node per pair for hierarchy walk. Zero init. */
u32 flow_pair_node[FLOW_MAX_PAIRS];
static __always_inline struct flow_llc_stats *flow_stats_for(u32 llc)
{
	return bpf_map_lookup_elem(&llc_stats_stor, &llc);
}
/* Increment one counter by one with unsigned add. */
static __always_inline void flow_stat_inc(u32 llc, u64 off)
{
	struct flow_llc_stats *st = flow_stats_for(llc);
	u64 *cell;
	if (!st)
		return;
	if (off == 0)
		cell = &st->queued;
	else if (off == 1)
		cell = &st->dispatched;
	else if (off == 2)
		cell = &st->fallback;
	else
		cell = &st->steal;
	__sync_fetch_and_add(cell, 1ULL);
}
/* Decrement queued by one with saturation at zero. */
static __always_inline void flow_queued_dec(u32 llc)
{
	struct flow_llc_stats *st = flow_stats_for(llc);
	if (!st)
		return;
	if (READ_ONCE(st->queued) == 0)
		return;
	__sync_fetch_and_sub(&st->queued, 1ULL);
}
/* Stale discard. Queued belongs to an exited task so attribute the */
/* decrement to a victim with backlog. This keeps the total correct */
/* and avoids a wrap on an empty thief. Fallback counts the discard. */
static __always_inline void flow_stale_account(u32 thief)
{
	u32 li;
	flow_stat_inc(thief, 2);
	bpf_for(li, 0, FLOW_MAX_LLCS) {
		struct flow_llc_stats *st;
		if ((u64)li >= flow_nr_llcs)
			break;
		if (!flow_llc_ok(li))
			continue;
		st = flow_stats_for(li);
		if (!st)
			continue;
		if (READ_ONCE(st->queued) == 0)
			continue;
		__sync_fetch_and_sub(&st->queued, 1ULL);
		break;
	}
}
/* Pinned when only one CPU is allowed or migration is disabled. */
/* Null task fails closed with no bypass. */
static __always_inline bool flow_is_pinned(struct task_struct *p)
{
	if (!p)
		return false;
	if (p->nr_cpus_allowed == 1)
		return true;
	return is_migration_disabled(p);
}
/* True when cpu is in the task mask. Null mask fails closed. */
static __always_inline bool flow_cpu_allowed(s32 cpu, struct task_struct *p)
{
	u32 c;
	if (!p || !p->cpus_ptr)
		return false;
	if (cpu < 0)
		return false;
	c = (u32)cpu;
	if (!flow_cpu_ok(c))
		return false;
	return bpf_cpumask_test_cpu(c, p->cpus_ptr);
}
/* True when the peeked head of a DSQ can run on cpu. Null peek fails */
/* closed with no move. This keeps a pinned head on its allowed CPU and */
/* skips a steal that would run off mask with no loss. Peek is hint only */
/* but pinned tasks wait in per CPU local queues so shared heads are */
/* migratable in the common case. */
static __always_inline bool flow_dsq_head_allowed(u64 dsq, u32 cpu)
{
	struct task_struct *p;
	if (!flow_cpu_ok(cpu))
		return false;
	p = __COMPAT_scx_bpf_dsq_peek(dsq);
	if (!p)
		return false;
	return flow_cpu_allowed((s32)cpu, p);
}
/* Saturated vtime plus slice. Caps at max on overflow. */
static __always_inline s64 flow_vtime_add_slice(s64 v)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	s64 sl = (s64)FLOW_SLICE_NS;
	if (v > vmax - sl)
		return vmax;
	return v + sl;
}
/* Blend prior level with a fresh sample. Keeps three parts prior plus */
/* one part fresh so a single spike never flips the hint. Integer only. */
static __always_inline u64 flow_freq_smooth(u64 prior, u64 fresh)
{
	return (prior - (prior >> 2)) + (fresh >> 2);
}
/* Fold one stop sample into the per CPU level. Used holds nanos burnt */
/* this run. Wall holds nanos since the prior stop. Caps the raw ratio */
/* at full speed then blends it. Zero time plus missing state plus zero */
/* wall keep the prior level with no change. */
static __always_inline void flow_freq_sample(u32 cpu, u64 used)
{
	struct flow_freq_state *st;
	u64 now;
	u64 wall;
	u64 raw;
	if (!flow_cpu_ok(cpu))
		return;
	st = &flow_freq_state[cpu];
	now = bpf_ktime_get_ns();
	if (!now)
		return;
	if (!st->last) {
		st->last = now;
		return;
	}
	if (now <= st->last)
		return;
	wall = now - st->last;
	if (!wall)
		return;
	st->last = now;
	raw = used * (u64)SCX_CPUPERF_ONE / wall;
	if (raw > (u64)SCX_CPUPERF_ONE)
		raw = (u64)SCX_CPUPERF_ONE;
	st->level = flow_freq_smooth(st->level, raw);
}
/* Map a smoothed level to a hint for the governor. At or above three */
/* quarters ask for full speed so a busy core stays ready. At or below */
/* one quarter ask for half speed so an idle core rests but stays awake. */
/* Between the bands keep the smoothed value to avoid rapid flips. */
static __always_inline u64 flow_freq_hint(u64 level)
{
	u64 low = (u64)SCX_CPUPERF_ONE / 4;
	u64 high = (u64)SCX_CPUPERF_ONE - low;
	u64 half = (u64)SCX_CPUPERF_ONE / 2;
	if (level >= high)
		return (u64)SCX_CPUPERF_ONE;
	if (level <= low)
		return half;
	return level;
}
/* Push the hint for one CPU to the governor. Reads the smoothed level, */
/* maps through the band, sets one CPU only. Never sends zero so wake */
/* stays bounded. Clamps at full speed. */
static __always_inline void flow_freq_apply(s32 cpu)
{
	u32 id;
	struct flow_freq_state *st;
	u64 hint;
	if (cpu < 0)
		return;
	id = (u32)cpu;
	if (!flow_cpu_ok(id))
		return;
	st = &flow_freq_state[id];
	hint = flow_freq_hint(st->level);
	if (!hint)
		hint = (u64)SCX_CPUPERF_ONE / 2;
	if (hint > (u64)SCX_CPUPERF_ONE)
		hint = (u64)SCX_CPUPERF_ONE;
	scx_bpf_cpuperf_set(cpu, (u32)hint);
}
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	u64 n;
	u64 want = 0;
	s32 cpu;
	u32 llc;
	TOUCH_ARENA();
	n = scx_bpf_nr_cpu_ids();
	if (n == 0) {
		scx_bpf_error("no CPUs found");
		return -EINVAL;
	}
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	flow_nr_cpus = n;
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		u32 key;
		struct flow_cpu_ctx *cc;
		u32 id;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		key = (u32)cpu;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (!cc)
			continue;
		id = READ_ONCE(cc->llc_id);
		if (!flow_llc_ok(id))
			continue;
		if ((u64)id + 1 > want)
			want = (u64)id + 1;
	}
	if (want == 0)
		want = 1;
	if (want > (u64)FLOW_MAX_LLCS) {
		scx_bpf_error("LLC count over bound");
		return -E2BIG;
	}
	flow_nr_llcs = want;
	if (n + want + 1 > 4096ULL) {
		scx_bpf_error("queue count over bound");
		return -E2BIG;
	}
	bpf_for(llc, 0, FLOW_MAX_LLCS) {
		u64 dsq;
		s32 ret;
		if ((u64)llc >= want)
			break;
		dsq = flow_llc_dsq(llc);
		if (!flow_dsq_ok(dsq)) {
			scx_bpf_error("dsq id over bound");
			return -EINVAL;
		}
		ret = scx_bpf_create_dsq(dsq, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("dsq create failed");
			return ret;
		}
	}
	{
		s32 ret = scx_bpf_create_dsq((u64)FLOW_FALLBACK_DSQ, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("fallback dsq create failed");
			return ret;
		}
	}
	if (want <= 1)
		return 0;
	/* Size the static area before the first pair queue use. */
	/* The pair queue draws from this area so it must be ready first. */
	/* Eight pages hold 32KiB. One pair with cap n times 4 needs the */
	/* queue header plus two heaps plus cap times 16 bytes of entries. */
	/* A 16 CPU host needs about one KiB per pair and fits with margin. */
	/* Overflow takes a fresh block and leaves old pages mapped, so an */
	/* oversize host still fails closed with no reuse. Single LLC above */
	/* uses only DSQs and creates no pair, so skipping init there is by */
	/* design. Enqueue and dispatch guard every pair use on more than one */
	/* LLC, so a future static user must move this init above that return. */
	{
		int ret = scx_static_init(8);
		if (ret) {
			scx_bpf_error("static init failed");
			return ret;
		}
	}
	bpf_for(llc, 0, FLOW_MAX_LLCS) {
		u32 node = 0;
		u32 cnt;
		u64 strand;
		u64 idx;
		u64 cap;
		bool first = false;
		u32 c;
		u64 got = (u64)-1;
		if ((u64)llc >= want)
			break;
		first = false;
		bpf_for(c, 0, FLOW_MAX_CPUS) {
			struct flow_cpu_ctx *cc;
			u32 key = c;
			if ((u64)c >= n)
				break;
			cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
			if (!cc)
				continue;
			if (READ_ONCE(cc->llc_id) == llc) {
				node = READ_ONCE(cc->node_id);
				first = true;
				break;
			}
		}
		if (!first)
			node = 0;
		if (!flow_node_ok(node)) {
			scx_bpf_error("node over bound");
			return -EINVAL;
		}
		cnt = flow_node_count[node];
		strand = (u64)(cnt % 2);
		if (strand == (u64)SCX_DHQ_STRAND_A) {
			idx = flow_pair_count;
			if (idx >= (u64)FLOW_MAX_PAIRS) {
				scx_bpf_error("pair over bound");
				return -EINVAL;
			}
			cap = n * 4;
			if (cap < 8)
				cap = 8;
			got = scx_dhq_create_balanced(false, cap,
						      SCX_DHQ_MODE_PRIORITY,
						      (u64)FLOW_DHQ_MAX_IMBALANCE);
			if (!got) {
				scx_bpf_error("pair create failed");
				return -ENOMEM;
			}
			flow_pair_dhqs[idx] = (scx_dhq_t *)got;
			flow_pair_count += 1;
			flow_node_last_pair[node] = idx;
		} else {
			idx = flow_node_last_pair[node];
			if (idx >= (u64)FLOW_MAX_PAIRS) {
				scx_bpf_error("pair over bound");
				return -EINVAL;
			}
			if (!flow_pair_dhqs[idx]) {
				scx_bpf_error("pair null for strand B");
				return -EINVAL;
			}
		}
		flow_llc_pair[llc] = idx;
		flow_llc_strand[llc] = strand;
		flow_node_count[node] = cnt + 1;
		if (idx < (u64)FLOW_MAX_PAIRS)
			flow_pair_node[(u32)idx] = node;
	}
	return 0;
}
void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *t;
	s64 v;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return;
	v = (s64)p->scx.dsq_vtime;
	t->vtime = v;
	t->deadline = flow_vtime_add_slice(v);
	t->slice_rem = (u64)FLOW_SLICE_NS;
	t->gen = 0;
	t->strand = (u32)FLOW_STRAND_A;
	t->llc_id = 0;
	t->flags = 0;
	t->pad = 0;
}
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_cpu_ctx *cc;
	u32 llc = 0;
	u32 strand = (u32)FLOW_STRAND_A;
	u32 key;
	struct flow_running_state *rs;
	u64 sl;
	u64 ng;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	key = cpu;
	cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (cc) {
		if (flow_llc_ok(READ_ONCE(cc->llc_id)))
			llc = READ_ONCE(cc->llc_id);
		if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
			u64 idx = flow_llc_pair[llc];
			if (idx < (u64)FLOW_MAX_PAIRS && flow_pair_dhqs[(u32)idx]) {
				u32 s = (u32)flow_llc_strand[llc];
				if (s == (u32)FLOW_STRAND_A || s == (u32)FLOW_STRAND_B)
					strand = s;
			}
		}
	} else {
		if (flow_llc_ok(t->llc_id))
			llc = t->llc_id;
		if (t->strand == (u32)FLOW_STRAND_A || t->strand == (u32)FLOW_STRAND_B)
			strand = t->strand;
	}
	sl = p->scx.slice;
	if (!sl || sl > (u64)FLOW_SLICE_NS)
		sl = (u64)FLOW_SLICE_NS;
	rs = &flow_running_state[cpu];
	ng = rs->gen + 1;
	if (ng == 0)
		ng = 1;
	rs->vtime = t->vtime;
	rs->deadline = t->deadline;
	rs->slice_rem = sl;
	rs->llc_id = llc;
	rs->strand = strand;
	rs->gen = ng;
	t->gen = ng;
	t->slice_rem = sl;
	t->llc_id = llc;
	t->strand = strand;
	__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
	/* Act at start. Send the smoothed hint for this one CPU only. */
	/* Placement plus vtime plus slice handling stay unchanged. */
	flow_freq_apply(task_cpu);
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 sl;
	(void)runnable;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	sl = p->scx.slice;
	if (sl > (u64)FLOW_SLICE_NS)
		sl = (u64)FLOW_SLICE_NS;
	t->slice_rem = sl;
	rs = &flow_running_state[cpu];
	rs->slice_rem = sl;
	/* Sense load at stop. Burnt nanos over wall feed the smoothed level. */
	/* Placement plus vtime plus slice handling stay unchanged. */
	if ((u64)FLOW_SLICE_NS >= sl)
		flow_freq_sample(cpu, (u64)FLOW_SLICE_NS - sl);
	else
		flow_freq_sample(cpu, 0);
}
void BPF_STRUCT_OPS(flow_tick, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_running_state *rs;
	u64 sl;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	rs = &flow_running_state[cpu];
	if (rs->gen == 0)
		return;
	sl = p->scx.slice;
	if (sl > (u64)FLOW_SLICE_NS)
		sl = (u64)FLOW_SLICE_NS;
	rs->slice_rem = sl;
}
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct flow_task_ctx *t;
	(void)deq_flags;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
}
/* No SMT probe runs. Each CPU stands single and a missing sibling */
/* fails closed with no move. Select stays through the shared picker. */
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool idle = false;
	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &idle);
}
/* Preempt when the running vtime is ahead by at least the threshold */
/* and the running slice is past the tail. Uses unsigned gap so the */
/* compare stays valid across wrap. Preempt is not counted as steal. */
/* Kick preempts only when the target is allowed, else it wakes idle. */
/* Idle kick validates the target first and skips when no allowed CPU */
/* exists so an offline or disallowed target never takes a wake. */
static __always_inline void flow_kick_for_enq(s32 task_cpu, s64 use_v, struct task_struct *p)
{
	u32 cpu;
	struct flow_running_state *rs;
	u64 gap;
	if (task_cpu < 0)
		return;
	if (!flow_cpu_allowed(task_cpu, p))
		goto idle;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		goto idle;
	rs = &flow_running_state[cpu];
	if (rs->gen == 0)
		goto idle;
	if (rs->slice_rem <= (u64)FLOW_PREEMPT_TAIL)
		goto idle;
	if (rs->vtime <= use_v)
		goto idle;
	gap = (u64)(rs->vtime - use_v);
	if (gap >= (u64)FLOW_PREEMPT_THRESH) {
		scx_bpf_kick_cpu(task_cpu, SCX_KICK_PREEMPT);
		return;
	}
idle:
	if (!flow_cpu_allowed(task_cpu, p))
		return;
	scx_bpf_kick_cpu(task_cpu, SCX_KICK_IDLE);
}
/* Wake idle only for inserts without task context. No preempt. */
static __always_inline void flow_kick_idle_only(s32 task_cpu, struct task_struct *p)
{
	if (task_cpu < 0)
		return;
	if (!flow_cpu_allowed(task_cpu, p))
		return;
	scx_bpf_kick_cpu(task_cpu, SCX_KICK_IDLE);
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	TOUCH_ARENA();
	if (!p)
		return;
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	u32 llc = 0;
	u32 strand = (u32)SCX_DHQ_STRAND_A;
	s64 kv;
	s64 use_v;
	s64 use_d;
	u64 use_sl;
	u32 use_strand;
	u32 use_llc;
	int carry = 0;
	u32 pair_u = 0;
	int have_pair = 0;
	bool pinned = false;
	struct flow_task_ctx *t;
	scx_dhq_t *dhq = NULL;
	int ret;
	u32 old_flags;
	if (task_cpu < 0)
		task_cpu = bpf_get_smp_processor_id();
	if (p->cpus_ptr && !flow_cpu_allowed(task_cpu, p)) {
		u32 first = bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(first))
			task_cpu = (s32)first;
	}
	cpu = (u32)task_cpu;
	if (flow_cpu_ok(cpu)) {
		struct flow_cpu_ctx *cc;
		u32 key = cpu;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (cc && flow_llc_ok(READ_ONCE(cc->llc_id)))
			llc = READ_ONCE(cc->llc_id);
	}
	kv = (s64)p->scx.dsq_vtime;
	use_v = kv;
	use_d = flow_vtime_add_slice(kv);
	use_sl = (u64)FLOW_SLICE_NS;
	use_strand = strand;
	use_llc = llc;
	pinned = flow_is_pinned(p);
	if (pinned) {
		dhq = NULL;
		have_pair = 0;
	} else if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
		u64 idx = flow_llc_pair[llc];
		if (idx < (u64)FLOW_MAX_PAIRS) {
			dhq = flow_pair_dhqs[(u32)idx];
			strand = (u32)flow_llc_strand[llc];
			if (strand != (u32)SCX_DHQ_STRAND_A &&
			    strand != (u32)SCX_DHQ_STRAND_B)
				strand = (u32)SCX_DHQ_STRAND_A;
			use_strand = strand;
			pair_u = (u32)idx;
			have_pair = 1;
		}
	}
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t) {
		/* No context means no duplicate state exists. Exiting */
		/* without context still needs no loss, so try local */
		/* then fall back to the LLC queue with a minimal slice. */
		if (p->flags & PF_EXITING) {
			if (task_cpu >= 0 && flow_cpu_ok((u32)task_cpu) &&
			    flow_cpu_allowed(task_cpu, p)) {
				u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)task_cpu;
				scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS,
						   enq_flags);
				flow_stat_inc(llc, 0);
				flow_kick_idle_only(task_cpu, p);
				return;
			}
			{
				u64 dsq = flow_llc_dsq(llc);
				if (!flow_dsq_ok(dsq))
					dsq = (u64)FLOW_FALLBACK_DSQ;
				scx_bpf_dsq_insert_vtime(p, dsq,
							 (u64)FLOW_EXIT_SLICE_NS,
							 (u64)kv, enq_flags);
				flow_stat_inc(llc, 0);
				flow_kick_idle_only(task_cpu, p);
				return;
			}
		}
		goto insert_only;
	}
	old_flags = __sync_fetch_and_or(&t->flags, (u32)FLOW_FLAG_QUEUED);
	if (old_flags & (u32)FLOW_FLAG_QUEUED) {
		flow_stat_inc(llc, 2);
		return;
	}
	/* Exiting keeps single ownership through the queued guard above. */
	/* A task already queued keeps its first entry and this requeue */
	/* drops as duplicate, so no second local queue forms. Pair plus */
	/* sequence are skipped. Local uses FIFO, shared fallback keeps */
	/* vtime order. Enqueue keeps caller flags, dispatch synthesizes */
	/* zero, same split as the normal path. Idle kick only, no preempt. */
	/* No drop exists. A missing local target falls back to LLC so an */
	/* exiting wakeup always queues. Bound check is best effort. */
	/* Hotplug needs restart, same risk as the pinned path. */
	if (p->flags & PF_EXITING) {
		if (task_cpu >= 0 && flow_cpu_ok((u32)task_cpu) &&
		    flow_cpu_allowed(task_cpu, p)) {
			u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)task_cpu;
			scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
			flow_stat_inc(llc, 0);
			flow_kick_idle_only(task_cpu, p);
			return;
		}
		{
			u64 dsq = flow_llc_dsq(llc);
			if (!flow_dsq_ok(dsq))
				dsq = (u64)FLOW_FALLBACK_DSQ;
			scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_EXIT_SLICE_NS,
						 (u64)kv, enq_flags);
			flow_stat_inc(llc, 0);
			flow_kick_idle_only(task_cpu, p);
			return;
		}
	}
	if (t->gen != 0 &&
	    (t->strand == (u32)FLOW_STRAND_A || t->strand == (u32)FLOW_STRAND_B) &&
	    flow_llc_ok(t->llc_id) &&
	    t->deadline == flow_vtime_add_slice(t->vtime)) {
		if (flow_cpu_ok(cpu)) {
			struct flow_running_state *rs = &flow_running_state[cpu];
			if (rs->gen != 0 && rs->gen == t->gen &&
			    flow_llc_ok(rs->llc_id) &&
			    (rs->strand == (u32)FLOW_STRAND_A ||
			     rs->strand == (u32)FLOW_STRAND_B)) {
				s64 charged;
				u64 used;
				u64 rem = t->slice_rem;
				if (rem > (u64)FLOW_SLICE_NS)
					rem = (u64)FLOW_SLICE_NS;
				if ((u64)FLOW_SLICE_NS >= rem)
					used = (u64)FLOW_SLICE_NS - rem;
				else
					used = 0;
				if (used > (u64)FLOW_SLICE_NS)
					used = (u64)FLOW_SLICE_NS;
				charged = t->vtime;
				if (used != 0) {
					const s64 vmax = (s64)0x7fffffffffffffffLL;
					if (charged <= vmax - (s64)used)
						charged += (s64)used;
					else
						charged = vmax;
				}
				if (have_pair && pair_u < (u32)FLOW_MAX_PAIRS) {
					s64 last = flow_dhq_seq[pair_u];
					if (charged <= last) {
						if (last == (s64)0x7fffffffffffffffLL)
							charged = last;
						else
							charged = last + 1;
					}
					flow_dhq_seq[pair_u] = charged;
				}
				carry = 1;
				use_v = charged;
				use_d = flow_vtime_add_slice(charged);
				use_sl = rem;
				use_strand = t->strand;
				use_llc = t->llc_id;
			}
		}
	}
	/* Pinned carry keeps vtime plus slice but follows the current LLC. */
	/* This keeps the task context aligned with the queue it waits in */
	/* so later victim accounting stays on the enqueue LLC. */
	if (pinned)
		use_llc = llc;
	if (!carry) {
		if (dhq && have_pair && pair_u < (u32)FLOW_MAX_PAIRS) {
			s64 last = flow_dhq_seq[pair_u];
			s64 fresh;
			if (kv > last)
				fresh = kv;
			else if (last == (s64)0x7fffffffffffffffLL)
				fresh = last;
			else
				fresh = last + 1;
			flow_dhq_seq[pair_u] = fresh;
			use_v = fresh;
			use_d = flow_vtime_add_slice(fresh);
			use_sl = (u64)FLOW_SLICE_NS;
			use_strand = strand;
			use_llc = llc;
		} else {
			use_v = kv;
			use_d = flow_vtime_add_slice(kv);
			use_sl = (u64)FLOW_SLICE_NS;
			use_strand = strand;
			use_llc = llc;
		}
		t->vtime = use_v;
		t->deadline = use_d;
		t->slice_rem = use_sl;
		t->strand = use_strand;
		t->llc_id = use_llc;
		t->gen = 0;
	} else {
		t->vtime = use_v;
		t->deadline = use_d;
		t->slice_rem = use_sl;
		t->strand = use_strand;
		t->llc_id = use_llc;
	}
	scx_bpf_task_set_dsq_vtime(p, (u64)use_v);
insert_only:
	/* Pinned tasks wait in the local queue of the allowed CPU only. */
	/* This keeps them out of shared LLC queues so no other CPU can */
	/* steal them off mask. Falls through to the LLC queue only when */
	/* no allowed local target exists as safety against loss. */
	if (pinned) {
		if (task_cpu >= 0 && flow_cpu_allowed(task_cpu, p)) {
			u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)task_cpu;
			scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_SLICE_NS, enq_flags);
			flow_stat_inc(llc, 0);
			if (!t)
				flow_kick_idle_only(task_cpu, p);
			else
				flow_kick_for_enq(task_cpu, use_v, p);
			return;
		}
	}
	if (dhq) {
		ret = scx_dhq_insert_vtime(dhq, (u64)p->pid, (u64)use_v,
					   (u64)use_strand);
		if (ret == 0) {
			flow_stat_inc(llc, 0);
			if (!t)
				flow_kick_idle_only(task_cpu, p);
			else
				flow_kick_for_enq(task_cpu, use_v, p);
			return;
		}
		/* Pair full. Count the move to the LLC queue. */
		/* This counter is separate from the fallback DSQ. */
		flow_stat_inc(llc, 2);
	}
	{
		u64 dsq = flow_llc_dsq(llc);
		if (!flow_dsq_ok(dsq))
			dsq = (u64)FLOW_FALLBACK_DSQ;
		scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_SLICE_NS, (u64)use_v, enq_flags);
		flow_stat_inc(llc, 0);
		if (!t)
			flow_kick_idle_only(task_cpu, p);
		else
			flow_kick_for_enq(task_cpu, use_v, p);
	}
}
/*
 * Pop one entry from a pair queue into the local LLC queue.
 * Peek is a hint only, pop is truth. Null task is stale.
 * Queued is charged to the enqueue LLC. Dispatched stays on the
 * dispatch LLC. Returns 1 when a task reached the local queue.
 * A task that cannot run on the thief goes back to the victim
 * queue with no counter move and no loss. Stale entries retry
 * bounded so one bad entry never stalls dispatch. Four attempts
 * cover a burst of stale entries. Each attempt is one pop plus
 * one lookup, so worst cost stays negligible. Exiting tasks use
 * the same victim path with a minimal slice and never use a full
 * slice on shared queues. Cpu bound checks are best effort.
 * Hotplug needs restart, same risk as the pinned path.
 */
static __always_inline int flow_pop_to_local(scx_dhq_t *dhq, u32 llc, u32 strand,
					     int always_steal, u32 cpu)
{
	u32 attempt;
	if (!dhq)
		return 0;
	if (!flow_llc_ok(llc))
		return 0;
	if (!flow_cpu_ok(cpu))
		return 0;
	bpf_for(attempt, 0, FLOW_POP_RETRY_MAX) {
		u64 pid;
		struct task_struct *p;
		struct flow_task_ctx *t;
		u32 tst;
		u32 victim;
		u64 ins_vtime;
		u64 dsq;
		if (scx_dhq_nr_queued(dhq) == 0)
			return 0;
		if (!scx_dhq_peek(dhq))
			return 0;
		pid = scx_dhq_pop(dhq);
		if (!pid)
			return 0;
		p = bpf_task_from_pid((s32)pid);
		if (!p) {
			flow_stale_account(llc);
			continue;
		}
		tst = strand;
		victim = llc;
		ins_vtime = (u64)p->scx.dsq_vtime;
		t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		if (t) {
			tst = t->strand;
			if (t->deadline == flow_vtime_add_slice(t->vtime))
				ins_vtime = (u64)t->vtime;
			if (flow_llc_ok(t->llc_id))
				victim = t->llc_id;
		}
		/* Exiting uses the same victim path with a minimal slice. */
		/* Allowed targets run on the thief local queue and count */
		/* as dispatched. Disallowed targets go back to the victim */
		/* queue with no counter move and no loss, so exit still */
		/* runs on an allowed CPU. Local uses FIFO, shared keeps */
		/* vtime order. Dispatch synthesizes zero flags, same as */
		/* the normal path. One victim lookup serves both paths. */
		if (p->flags & PF_EXITING) {
			if (flow_cpu_allowed((s32)cpu, p)) {
				u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)cpu;
				scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, 0);
				bpf_task_release(p);
				flow_queued_dec(victim);
				flow_stat_inc(llc, 1);
				if (always_steal)
					flow_stat_inc(llc, 3);
				return 1;
			}
			{
				u64 vdsq = flow_llc_dsq(victim);
				if (!flow_dsq_ok(vdsq))
					vdsq = (u64)FLOW_FALLBACK_DSQ;
				scx_bpf_dsq_insert_vtime(p, vdsq,
							 (u64)FLOW_EXIT_SLICE_NS,
							 ins_vtime, 0);
				bpf_task_release(p);
				return 0;
			}
		}
		if (!flow_cpu_allowed((s32)cpu, p)) {
			u64 vdsq = flow_llc_dsq(victim);
			if (!flow_dsq_ok(vdsq))
				vdsq = (u64)FLOW_FALLBACK_DSQ;
			scx_bpf_dsq_insert_vtime(p, vdsq, (u64)FLOW_SLICE_NS, ins_vtime, 0);
			bpf_task_release(p);
			return 0;
		}
		dsq = flow_llc_dsq(llc);
		scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_SLICE_NS, ins_vtime, 0);
		bpf_task_release(p);
		flow_queued_dec(victim);
		if (scx_bpf_dsq_move_to_local(dsq, 0)) {
			flow_stat_inc(llc, 1);
			if (always_steal || tst != strand)
				flow_stat_inc(llc, 3);
			return 1;
		}
		flow_stat_inc(victim, 0);
		return 0;
	}
	return 0;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	TOUCH_ARENA();
	u32 c;
	u32 llc = 0;
	u32 node = 0;
	u32 strand = (u32)SCX_DHQ_STRAND_A;
	u64 dsq;
	u64 own_idx = (u64)-1;
	scx_dhq_t *dhq = NULL;
	u32 pi;
	u32 li;
	(void)prev;
	if (cpu < 0)
		return;
	c = (u32)cpu;
	if (!flow_cpu_ok(c))
		return;
	{
		u32 key = c;
		struct flow_cpu_ctx *cc;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (!cc)
			return;
		if (!flow_llc_ok(READ_ONCE(cc->llc_id)))
			return;
		llc = READ_ONCE(cc->llc_id);
		node = READ_ONCE(cc->node_id);
		if (!flow_node_ok(node))
			node = 0;
	}
	dsq = flow_llc_dsq(llc);
	if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
		u64 idx = flow_llc_pair[llc];
		if (idx < (u64)FLOW_MAX_PAIRS) {
			dhq = flow_pair_dhqs[(u32)idx];
			strand = (u32)flow_llc_strand[llc];
			if (strand != (u32)FLOW_STRAND_A &&
			    strand != (u32)FLOW_STRAND_B)
				strand = (u32)SCX_DHQ_STRAND_A;
			own_idx = idx;
		}
	}
	if (dhq) {
		if (flow_pop_to_local(dhq, llc, strand, 0, c))
			return;
		bpf_for(pi, 0, FLOW_MAX_PAIRS) {
			u64 idx = (u64)pi;
			scx_dhq_t *cand;
			if (idx == own_idx)
				continue;
			if (pi >= flow_pair_count)
				break;
			if (idx >= (u64)FLOW_MAX_PAIRS)
				continue;
			if (flow_pair_node[pi] != node)
				continue;
			cand = flow_pair_dhqs[pi];
			if (!cand)
				continue;
			if (flow_pop_to_local(cand, llc, strand, 1, c))
				return;
		}
		bpf_for(pi, 0, FLOW_MAX_PAIRS) {
			u64 idx = (u64)pi;
			scx_dhq_t *cand;
			if (idx == own_idx)
				continue;
			if (pi >= flow_pair_count)
				break;
			if (idx >= (u64)FLOW_MAX_PAIRS)
				continue;
			if (flow_pair_node[pi] == node)
				continue;
			cand = flow_pair_dhqs[pi];
			if (!cand)
				continue;
			if (flow_pop_to_local(cand, llc, strand, 1, c))
				return;
		}
	}
	if (flow_dsq_head_allowed(dsq, c) && scx_bpf_dsq_move_to_local(dsq, 0)) {
		flow_stat_inc(llc, 1);
		flow_queued_dec(llc);
		return;
	}
	bpf_for(li, 0, FLOW_MAX_LLCS) {
		u64 odsq;
		if (li == llc)
			continue;
		if ((u64)li >= flow_nr_llcs)
			break;
		if (!flow_llc_ok(li))
			continue;
		odsq = flow_llc_dsq(li);
		if (!flow_dsq_ok(odsq))
			continue;
		if (!flow_dsq_head_allowed(odsq, c))
			continue;
		if (scx_bpf_dsq_move_to_local(odsq, 0)) {
			flow_stat_inc(llc, 1);
			flow_queued_dec(li);
			flow_stat_inc(llc, 3);
			return;
		}
	}
	/* Fallback DSQ is safety only. It stays empty unless LLC validation fails. */
	if (flow_dsq_head_allowed((u64)FLOW_FALLBACK_DSQ, c) &&
	    scx_bpf_dsq_move_to_local((u64)FLOW_FALLBACK_DSQ, 0)) {
		u32 li2;
		flow_stat_inc(llc, 1);
		bpf_for(li2, 0, FLOW_MAX_LLCS) {
			struct flow_llc_stats *st;
			if ((u64)li2 >= flow_nr_llcs)
				break;
			if (!flow_llc_ok(li2))
				continue;
			st = flow_stats_for(li2);
			if (!st)
				continue;
			if (READ_ONCE(st->queued) == 0)
				continue;
			__sync_fetch_and_sub(&st->queued, 1ULL);
			break;
		}
		return;
	}
}
SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dequeue			= (void *)flow_dequeue,
	       .dispatch		= (void *)flow_dispatch,
	       .running			= (void *)flow_running,
	       .stopping		= (void *)flow_stopping,
	       .tick			= (void *)flow_tick,
	       .enable			= (void *)flow_enable,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
