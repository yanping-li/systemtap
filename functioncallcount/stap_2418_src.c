
#define STAP_MSG_RUNTIME_H_01 "myproc-unprivileged tapset function called without is_myproc checking for pid %d (euid %d)"
#define STAP_MSG_LOC2C_01 "read fault [man error::fault] at 0x%p (%s)"
#define STAP_MSG_LOC2C_02 "write fault [man error::fault] at 0x%p (%s)"
#define STAP_MSG_LOC2C_03 "divide by zero in DWARF operand (%s)"
#define STAP_VERSION(a, b) ( ((a) << 8) + (b) )
#ifndef STAP_COMPAT_VERSION
#define STAP_COMPAT_VERSION STAP_VERSION(3, 0)
#endif
#include "runtime_defines.h"
#include "linux/perf_read.h"
#define STP_PR_STAPUSR 0x2
#define STP_PR_STAPSYS 0x4
#define STP_PR_STAPDEV 0x8
#define STP_PRIVILEGE 0x8
int stp_required_privilege __attribute__ ((section (".stap_privilege"))) = STP_PRIVILEGE;
#ifndef MAXNESTING
#define MAXNESTING 1
#endif
#define STAPREGEX_MAX_STATE0
#define STAPREGEX_MAX_TAG0
#define STP_SKIP_BADVARS 0
#define STP_PROBE_COUNT 2
static void systemtap_module_refresh (const char* modname);
#include "runtime.h"
#include <linux/mutex.h>
static DEFINE_MUTEX(module_refresh_mutex);
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
#define STP_ON_THE_FLY_TIMER_ENABLE
#endif

struct context {
  #include "common_probe_context.h"
  union {
    struct probe_2786_locals {
      string_t l___stable___global_ppfunc__overload_0_value;
      union { /* block_statement: functioncallcount.stp:8 */
        struct { /* source: functioncallcount.stp:8 */
          string_t __tmp0;
        };
        struct { /* source: functioncallcount.stp:8 */
          string_t __tmp3;
        };
      };
    } probe_2786;
    struct probe_2787_locals {
      string_t l_fn;
      union { /* block_statement: functioncallcount.stp:13 */
        struct { /* source: functioncallcount.stp:14 */
          struct map_node *__tmp0;
          string_t __tmp1;
          int64_t __tmp2;
          struct stat_data *__tmp3;
          int64_t __tmp4;
        };
      };
    } probe_2787;
  } probe_locals;
  union {
    struct function___global_exit__overload_0_locals {
      /* no return value */
    } function___global_exit__overload_0;
    struct function___global_ppfunc__overload_0_locals {
      char * __retvalue;
    } function___global_ppfunc__overload_0;
  } locals [MAXNESTING+1];
  #if MAXNESTING < 0
  #error "MAXNESTING must be positive"
  #endif
  #ifndef STP_LEGACY_PRINT
  union {
    struct stp_printf_1_locals {
      const char* arg0;
      int64_t arg1;
    } stp_printf_1;
  } printf_locals;
  #endif // STP_LEGACY_PRINT
};

#include "runtime_context.h"
#include "alloc.c"
#define VALUE_TYPE STAT
#define KEY1_TYPE STRING
#define MAP_DO_PMAP 1
#include "map-gen.c"
#undef MAP_DO_PMAP
#undef VALUE_TYPE
#undef KEY1_TYPE
#include "map.c"
#ifndef STP_LEGACY_PRINT

static void stp_printf_1 (struct context* __restrict__ c) {
  struct stp_printf_1_locals * __restrict__ l = & c->printf_locals.stp_printf_1;
  char *str = NULL, *end = NULL;
  const char *src;
  int width;
  int precision;
  unsigned long ptr_value;
  int num_bytes;
  (void) width;
  (void) precision;
  (void) ptr_value;
  (void) num_bytes;
  num_bytes = 0;
  width = -1;
  precision = -1;
  num_bytes += _stp_vsprint_memory_size(l->arg0, width, precision, 's', 0);
  num_bytes += sizeof(" ") - 1;
  width = -1;
  precision = -1;
  num_bytes += number_size(l->arg1, 10, width, precision, 2);
  num_bytes += sizeof("\n") - 1;
  num_bytes = clamp(num_bytes, 0, STP_BUFFER_SIZE);
  str = (char*)_stp_reserve_bytes(num_bytes);
  end = str ? str + num_bytes - 1 : 0;
  if (str && str <= end) {
    width = -1;
    precision = -1;
    str = _stp_vsprint_memory(str, end, l->arg0, width, precision, 's', 0);
    src = " ";
    while (*src && str <= end)
      *str++ = *src++;
    width = -1;
    precision = -1;
    str = number(str, end, l->arg1, 10, width, precision, 2);
    src = "\n";
    while (*src && str <= end)
      *str++ = *src++;
  }
}
#endif // STP_LEGACY_PRINT
static atomic_t need_module_refresh = ATOMIC_INIT(0);
#include <linux/workqueue.h>
static struct work_struct module_refresher_work;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void module_refresher(void *data) {
#else
static void module_refresher(struct work_struct *work) {
#endif
  systemtap_module_refresh(NULL);
}
#ifdef STP_ON_THE_FLY_TIMER_ENABLE
#include "timer.h"
static struct hrtimer module_refresh_timer;
#ifndef STP_ON_THE_FLY_INTERVAL
#define STP_ON_THE_FLY_INTERVAL (100*1000*1000)
#endif
hrtimer_return_t module_refresh_timer_cb(struct hrtimer *timer) {
  if (atomic_cmpxchg(&need_module_refresh, 1, 0) == 1)
    schedule_work(&module_refresher_work);
  hrtimer_set_expires(timer,
    ktime_add(hrtimer_get_expires(timer),
              ktime_set(0, STP_ON_THE_FLY_INTERVAL))); 
  return HRTIMER_RESTART;
}
#endif /* STP_ON_THE_FLY_TIMER_ENABLE */
#include "namespaces.h"

struct stp_globals {
  PMAP s___global_called;
  rwlock_t s___global_called_lock;
  #ifdef STP_TIMING
  atomic_t s___global_called_lock_skip_count;
  #endif

};

static struct stp_globals stp_global = {
  
};

#include "common_session_state.h"
#include "probe_lock.h" 
#ifdef STAP_NEED_GETTIMEOFDAY
#include "time.c"
#endif

static void function___global_exit__overload_0 (struct context * __restrict__ c);

static void function___global_ppfunc__overload_0 (struct context * __restrict__ c);

struct stap_probe {
  const size_t index;
  void (* const ph) (struct context*);
  unsigned cond_enabled:1;
  #if defined(STP_TIMING) || defined(STP_ALIBI)
  const char location[29];
  const char * const derivation;
  #define STAP_PROBE_INIT_TIMING(L, D) .location=(L), .derivation=(D),
  #else
  #define STAP_PROBE_INIT_TIMING(L, D)
  #endif
  const char * const pp;
  #ifdef STP_NEED_PROBE_NAME
  const char * const pn;
  #define STAP_PROBE_INIT_NAME(PN) .pn=(PN),
  #else
  #define STAP_PROBE_INIT_NAME(PN)
  #endif
  #define STAP_PROBE_INIT(I, PH, PP, PN, L, D) { .index=(I), .ph=(PH), .cond_enabled=1, .pp=(PP), STAP_PROBE_INIT_NAME(PN) STAP_PROBE_INIT_TIMING(L, D) }
} static stap_probes[];

static void probe_2786 (struct context * __restrict__ c) {
  __label__ out;
  static const struct stp_probe_lock locks[] = {
  };
  struct probe_2786_locals * __restrict__ l = & c->probe_locals.probe_2786;
  (void) l;
  #if ! STP_PRIVILEGE_CONTAINS (STP_PRIVILEGE, STP_PR_STAPDEV) && \
      ! STP_PRIVILEGE_CONTAINS (STP_PRIVILEGE, STP_PR_STAPSYS)
  #error Internal Error: Probe kernel.function("vfs_read@fs/read_write.c:448").call generated in --unprivileged mode
  #endif
  if (!stp_lock_probe(locks, ARRAY_SIZE(locks)))
    return;
  l->l___stable___global_ppfunc__overload_0_value[0] = '\0';
  if (c->actionremaining < 2) { c->last_error = "MAXACTION exceeded"; goto out; }
  {
    (void) 
    ({
      ({
        c->locals[c->nesting+1].function___global_ppfunc__overload_0.__retvalue = &l->__tmp0[0];
        function___global_ppfunc__overload_0 (c);
        if (unlikely(c->last_error)) goto out;
        if (unlikely(c->next)) { c->last_error = "all functions exhausted"; goto out; }
        (void) 0;
      });
      strlcpy (l->l___stable___global_ppfunc__overload_0_value, l->__tmp0, MAXSTRINGLEN);
      l->__tmp0;
    });
    
    (void) 
    ({
      strlcpy (l->__tmp3, l->l___stable___global_ppfunc__overload_0_value, MAXSTRINGLEN);
      c->last_stmt = "identifier 'called' at functioncallcount.stp:8:3";
      { int rc = _stp_pmap_add_sx (global(s___global_called), l->__tmp3, ((int64_t)1LL)); if (unlikely(rc)) { c->last_error = "Array overflow, check MAXMAPENTRIES"; goto out; }};
      ((int64_t)1LL);
    });
    
  }
out:
  stp_unlock_probe(locks, ARRAY_SIZE(locks));
  _stp_print_flush();
}


static void probe_2787 (struct context * __restrict__ c) {
  __label__ out;
  struct probe_2787_locals * __restrict__ l = & c->probe_locals.probe_2787;
  (void) l;
  l->l_fn[0] = '\0';
  {
    if (unlikely(NULL == _stp_pmap_agg_sx (global(s___global_called)))) {
      c->last_error = "aggregation overflow in global(s___global_called)";
      c->last_stmt = "keyword at functioncallcount.stp:14:5";
      goto out;
    }
    else
      _stp_map_sort_sx (_stp_pmap_get_agg(global(s___global_called)), SORT_COUNT, 1);
    l->__tmp0 = _stp_map_start (_stp_pmap_get_agg(global(s___global_called)));
    c->actionremaining -= 1;
    if (unlikely (c->actionremaining <= 0)) {
      c->last_error = "MAXACTION exceeded";
      c->last_stmt = "keyword at functioncallcount.stp:14:5";
      goto out;
    }
  top_0:
    if (! (l->__tmp0)) goto break_0;
    {
      strlcpy (l->l_fn, (_stp_map_key_get_str_sx (l->__tmp0, 1) ?: ""), MAXSTRINGLEN);
      (void) 
      ({
        strlcpy (l->__tmp1, l->l_fn, MAXSTRINGLEN);
        l->__tmp2 = 
        ({
          l->__tmp3 = _stp_map_get_stat_data_sx (l->__tmp0);
          if (unlikely (l->__tmp3 == NULL))
            l->__tmp4 = 0;
          else
            l->__tmp4 = l->__tmp3->count;
          l->__tmp4;
        });
        #ifndef STP_LEGACY_PRINT
          c->printf_locals.stp_printf_1.arg0 = l->__tmp1;
          c->printf_locals.stp_printf_1.arg1 = l->__tmp2;
          stp_printf_1 (c);
        #else // STP_LEGACY_PRINT
          _stp_printf ("%s %lld\n", l->__tmp1, l->__tmp2);
        #endif // STP_LEGACY_PRINT
        if (unlikely(c->last_error)) goto out;
        ((int64_t)0LL);
      });
      c->actionremaining -= 2;
      if (unlikely (c->actionremaining <= 0)) {
        c->last_error = "MAXACTION exceeded";
        c->last_stmt = "identifier 'printf' at functioncallcount.stp:16:9";
        goto out;
      }
    }
  continue_0:
    l->__tmp0 = _stp_map_iter (_stp_pmap_get_agg(global(s___global_called)), l->__tmp0);
    goto top_0;
  break_0:
    ; /* dummy statement */
    
    (void) 
    ({
      function___global_exit__overload_0 (c);
      if (unlikely(c->last_error)) goto out;
      if (unlikely(c->next)) { c->last_error = "all functions exhausted"; goto out; }
      (void) 0;
    });
    
  }
  c->actionremaining -= 1;
  if (unlikely (c->actionremaining <= 0)) {
    c->last_error = "MAXACTION exceeded";
    c->last_stmt = "operator '{' at functioncallcount.stp:13:11";
    goto out;
  }
out:
  _stp_print_flush();
}

static struct stap_probe stap_probes[] = {
  STAP_PROBE_INIT(0, &probe_2786, "kernel.function(\"vfs_read@fs/read_write.c:448\").call", "kernel.function(\"vfs_read@fs/read_write.c:448\").call", "functioncallcount.stp:7:1", " from: kernel.function(\"vfs_read@fs/read_write.c:448\").call from: kernel.function(\"vfs_read\").call"),
  STAP_PROBE_INIT(1, &probe_2787, "end", "end", "functioncallcount.stp:13:1", " from: end"),
};

static void function___global_exit__overload_0 (struct context* __restrict__ c) {
  __label__ out;
  struct function___global_exit__overload_0_locals *  __restrict__ l = & c->locals[c->nesting+1].function___global_exit__overload_0;
  (void) l;
  #define CONTEXT c
  #define THIS l
  c->last_stmt = "identifier 'exit' at /usr/share/systemtap/tapset/logging.stp:49:10";
  if (unlikely (c->nesting+1 >= MAXNESTING)) {
    c->last_error = "MAXNESTING exceeded";
    return;
  } else {
    c->nesting ++;
  }
  c->next = 0;
  #define STAP_NEXT do { c->next = 1; goto out; } while(0)
  #define STAP_RETURN() do { goto out; } while(0)
  #define STAP_PRINTF(fmt, ...) do { _stp_printf(fmt, ##__VA_ARGS__); } while (0)
  #define STAP_ERROR(...) do { snprintf(CONTEXT->error_buffer, MAXSTRINGLEN, __VA_ARGS__); CONTEXT->last_error = CONTEXT->error_buffer; goto out; } while (0)
  #define return goto out
  if (c->actionremaining < 0) { c->last_error = "MAXACTION exceeded";goto out; }
  {
     /* unprivileged */
    atomic_set (session_state(), STAP_SESSION_STOPPING);
    _stp_exit ();

  }
  #undef return
  #undef STAP_PRINTF
  #undef STAP_ERROR
  #undef STAP_RETURN
out:
  if (0) goto out;
  c->nesting --;
  #undef CONTEXT
  #undef THIS
  #undef STAP_NEXT
  #undef STAP_RETVALUE
}


static void function___global_ppfunc__overload_0 (struct context* __restrict__ c) {
  __label__ out;
  struct function___global_ppfunc__overload_0_locals *  __restrict__ l = & c->locals[c->nesting+1].function___global_ppfunc__overload_0;
  (void) l;
  #define CONTEXT c
  #define THIS l
  #define STAP_RETVALUE THIS->__retvalue
  c->last_stmt = "identifier 'ppfunc' at /usr/share/systemtap/tapset/context.stp:47:10";
  if (unlikely (c->nesting+1 >= MAXNESTING)) {
    c->last_error = "MAXNESTING exceeded";
    return;
  } else {
    c->nesting ++;
  }
  c->next = 0;
  #define STAP_NEXT do { c->next = 1; goto out; } while(0)
  l->__retvalue[0] = '\0';
  #define STAP_RETURN(v) do { strlcpy(STAP_RETVALUE, (v), MAXSTRINGLEN); goto out; } while(0)
  #define STAP_PRINTF(fmt, ...) do { _stp_printf(fmt, ##__VA_ARGS__); } while (0)
  #define STAP_ERROR(...) do { snprintf(CONTEXT->error_buffer, MAXSTRINGLEN, __VA_ARGS__); CONTEXT->last_error = CONTEXT->error_buffer; goto out; } while (0)
  #define return goto out
  if (c->actionremaining < 0) { c->last_error = "MAXACTION exceeded";goto out; }
  {
     /* pure */ /* unprivileged */ /* stable */
	char *ptr, *start;

	/* This is based on the pre-2.0 behavior of probefunc(), but without
	 * the _stp_snprint_addr fallback, so we're purely pp()-based.
	 *
	 * The obsolete inline("...") syntax is dropped, but in its place we'll
	 * look for function names in statement("...") form.
	 */

	STAP_RETVALUE[0] = '\0';
	start = strstr(CONTEXT->probe_point, "function(\"");
	ptr = start + 10;
	if (!start) {
		start = strstr(CONTEXT->probe_point, "statement(\"");
		ptr = start + 11;
	}

	if (start) {
		int len = MAXSTRINGLEN;
		char *dst = STAP_RETVALUE;
		while (*ptr != '@' && *ptr != '"' && --len > 0 && *ptr)
			*dst++ = *ptr++;
		*dst = 0;
	}

  }
  #undef return
  #undef STAP_PRINTF
  #undef STAP_ERROR
  #undef STAP_RETURN
out:
  if (0) goto out;
  c->nesting --;
  #undef CONTEXT
  #undef THIS
  #undef STAP_NEXT
  #undef STAP_RETVALUE
}


/* ---- begin/end/error probes ---- */
static struct stap_be_probe {
  const struct stap_probe * const probe;
  int state, type;
} stap_be_probes[] = {
  { .probe=(&stap_probes[1]), .state=STAP_SESSION_STOPPING, .type=1 },
};
static void enter_be_probe (struct stap_be_probe *stp) {
  #ifdef STP_ALIBI
  atomic_inc(probe_alibi(stp->probe->index));
  #else
  struct context* __restrict__ c = NULL;
  #if !INTERRUPTIBLE
  unsigned long flags;
  #endif
  #ifdef STP_TIMING
  Stat stat = probe_timing(stp->probe->index);
  #endif
  #ifdef STP_TIMING
  cycles_t cycles_atstart = get_cycles ();
  #endif
  #if !INTERRUPTIBLE
  local_irq_save (flags);
  #endif
  if (unlikely ((((unsigned long) (& c)) & (THREAD_SIZE-1))
    < (MINSTACKSPACE + sizeof (struct thread_info)))) {
    atomic_inc (skipped_count());
    #ifdef STP_TIMING
    atomic_inc (skipped_count_lowstack());
    #endif
    goto probe_epilogue;
  }
  if (atomic_read (session_state()) != stp->state)
    goto probe_epilogue;
  c = _stp_runtime_entryfn_get_context();
  if (!c) {
    #if !INTERRUPTIBLE
    atomic_inc (skipped_count());
    #endif
    #ifdef STP_TIMING
    atomic_inc (skipped_count_reentrant());
    #endif
    goto probe_epilogue;
  }
  
  c->last_stmt = 0;
  c->last_error = 0;
  c->nesting = -1;
  c->uregs = 0;
  c->kregs = 0;
  #if defined __ia64__
  c->unwaddr = 0;
  #endif
  c->probe_point = stp->probe->pp;
  #ifdef STP_NEED_PROBE_NAME
  c->probe_name = stp->probe->pn;
  #endif
  c->probe_type = stp_probe_type_been;
  memset(&c->ips, 0, sizeof(c->ips));
  c->user_mode_p = 0; c->full_uregs_p = 0;
  #ifdef STAP_NEED_REGPARM
  c->regparm = 0;
  #endif
  #if INTERRUPTIBLE
  c->actionremaining = MAXACTION_INTERRUPTIBLE;
  #else
  c->actionremaining = MAXACTION;
  #endif
  #if defined(STP_NEED_UNWIND_DATA)
  c->uwcache_user.state = uwcache_uninitialized;
  c->uwcache_kernel.state = uwcache_uninitialized;
  #endif
  (*stp->probe->ph) (c);
  #ifdef STP_TIMING
  {
    cycles_t cycles_atend = get_cycles ();
    int32_t cycles_elapsed = ((int32_t)cycles_atend > (int32_t)cycles_atstart)
      ? ((int32_t)cycles_atend - (int32_t)cycles_atstart)
      : (~(int32_t)0) - (int32_t)cycles_atstart + (int32_t)cycles_atend + 1;
    #ifdef STP_TIMING
    if (likely (stat)) _stp_stat_add(stat, cycles_elapsed);
    #endif
  }
  #endif
  c->probe_point = 0;
  #ifdef STP_NEED_PROBE_NAME
  c->probe_name = 0;
  #endif
  c->probe_type = 0;
  if (unlikely (c->last_error)) {
    if (c->last_stmt != NULL)
      _stp_softerror ("%s near %s", c->last_error, c->last_stmt);
    else
      _stp_softerror ("%s", c->last_error);
    atomic_inc (error_count());
    if (atomic_read (error_count()) > MAXERRORS) {
      atomic_set (session_state(), STAP_SESSION_ERROR);
      _stp_exit ();
    }
  }
probe_epilogue:
  if (unlikely (atomic_read (skipped_count()) > MAXSKIPPED)) {
    if (unlikely (pseudo_atomic_cmpxchg(session_state(), STAP_SESSION_RUNNING, STAP_SESSION_ERROR) == STAP_SESSION_RUNNING))
    _stp_error ("Skipped too many probes, check MAXSKIPPED or try again with stap -t for more details.");
  }
  _stp_runtime_entryfn_put_context(c);
  #if !INTERRUPTIBLE
  local_irq_restore (flags);
  #endif
  #endif // STP_ALIBI
}
/* ---- dwarf and non-dwarf kprobe-based probes ---- */
#define STAP_KPROBE_PROBE_STR_module const char module[7]
#define STAP_KPROBE_PROBE_STR_section const char section[7]
#include "linux/kprobes.c"
#undef STAP_KPROBE_PROBE_STR_module
#undef STAP_KPROBE_PROBE_STR_section
#if defined(STAPCONF_UNREGISTER_KPROBES)
static void * stap_unreg_kprobes[1];
#endif
static struct stap_kprobe stap_kprobes[1];
static struct stap_kprobe_probe stap_kprobe_probes[] = {
  { .address=(unsigned long)0x1fdc48ULL, .module="kernel", .section="_stext", .probe=(&stap_probes[0]), .kprobe=&stap_kprobes[0], },
};

static int enter_kprobe_probe (struct kprobe *inst, struct pt_regs *regs) {
  int kprobe_idx = ((uintptr_t)inst-(uintptr_t)stap_kprobes)/sizeof(struct stap_kprobe);
  struct stap_kprobe_probe *skp = &stap_kprobe_probes[((kprobe_idx >= 0 && kprobe_idx < 1)?kprobe_idx:0)];
  #ifdef STP_ALIBI
  atomic_inc(probe_alibi(skp->probe->index));
  #else
  struct context* __restrict__ c = NULL;
  #if !INTERRUPTIBLE
  unsigned long flags;
  #endif
  #ifdef STP_TIMING
  Stat stat = probe_timing(skp->probe->index);
  #endif
  #if defined(STP_TIMING) || defined(STP_OVERLOAD)
  cycles_t cycles_atstart = get_cycles ();
  #endif
  #if !INTERRUPTIBLE
  local_irq_save (flags);
  #endif
  if (unlikely ((((unsigned long) (& c)) & (THREAD_SIZE-1))
    < (MINSTACKSPACE + sizeof (struct thread_info)))) {
    atomic_inc (skipped_count());
    #ifdef STP_TIMING
    atomic_inc (skipped_count_lowstack());
    #endif
    goto probe_epilogue;
  }
  if (atomic_read (session_state()) != STAP_SESSION_RUNNING)
    goto probe_epilogue;
  c = _stp_runtime_entryfn_get_context();
  if (!c) {
    #if !INTERRUPTIBLE
    atomic_inc (skipped_count());
    #endif
    #ifdef STP_TIMING
    atomic_inc (skipped_count_reentrant());
    #endif
    goto probe_epilogue;
  }
  
  c->last_stmt = 0;
  c->last_error = 0;
  c->nesting = -1;
  c->uregs = 0;
  c->kregs = 0;
  #if defined __ia64__
  c->unwaddr = 0;
  #endif
  c->probe_point = skp->probe->pp;
  #ifdef STP_NEED_PROBE_NAME
  c->probe_name = skp->probe->pn;
  #endif
  c->probe_type = stp_probe_type_kprobe;
  memset(&c->ips, 0, sizeof(c->ips));
  c->user_mode_p = 0; c->full_uregs_p = 0;
  #ifdef STAP_NEED_REGPARM
  c->regparm = 0;
  #endif
  #if INTERRUPTIBLE
  c->actionremaining = MAXACTION_INTERRUPTIBLE;
  #else
  c->actionremaining = MAXACTION;
  #endif
  #if defined(STP_NEED_UNWIND_DATA)
  c->uwcache_user.state = uwcache_uninitialized;
  c->uwcache_kernel.state = uwcache_uninitialized;
  #endif
  c->kregs = regs;
  {
    unsigned long kprobes_ip = REG_IP(c->kregs);
    SET_REG_IP(regs, (unsigned long) inst->addr);
    (*skp->probe->ph) (c);
    SET_REG_IP(regs, kprobes_ip);
  }
  #if defined(STP_TIMING) || defined(STP_OVERLOAD)
  {
    cycles_t cycles_atend = get_cycles ();
    int32_t cycles_elapsed = ((int32_t)cycles_atend > (int32_t)cycles_atstart)
      ? ((int32_t)cycles_atend - (int32_t)cycles_atstart)
      : (~(int32_t)0) - (int32_t)cycles_atstart + (int32_t)cycles_atend + 1;
    #ifdef STP_TIMING
    if (likely (stat)) _stp_stat_add(stat, cycles_elapsed);
    #endif
    #ifdef STP_OVERLOAD
    {
      cycles_t interval = (cycles_atend > c->cycles_base)
        ? (cycles_atend - c->cycles_base)
        : (STP_OVERLOAD_INTERVAL + 1);
      c->cycles_sum += cycles_elapsed;
      if (interval > STP_OVERLOAD_INTERVAL) {
        if (c->cycles_sum > STP_OVERLOAD_THRESHOLD) {
          _stp_error ("probe overhead exceeded threshold");
          atomic_set (session_state(), STAP_SESSION_ERROR);
          atomic_inc (error_count());
        }
        c->cycles_base = cycles_atend;
        c->cycles_sum = 0;
      }
    }
    #endif
  }
  #endif
  c->probe_point = 0;
  #ifdef STP_NEED_PROBE_NAME
  c->probe_name = 0;
  #endif
  c->probe_type = 0;
  if (unlikely (c->last_error)) {
    if (c->last_stmt != NULL)
      _stp_softerror ("%s near %s", c->last_error, c->last_stmt);
    else
      _stp_softerror ("%s", c->last_error);
    atomic_inc (error_count());
    if (atomic_read (error_count()) > MAXERRORS) {
      atomic_set (session_state(), STAP_SESSION_ERROR);
      _stp_exit ();
    }
  }
probe_epilogue:
  if (unlikely (atomic_read (skipped_count()) > MAXSKIPPED)) {
    if (unlikely (pseudo_atomic_cmpxchg(session_state(), STAP_SESSION_RUNNING, STAP_SESSION_ERROR) == STAP_SESSION_RUNNING))
    _stp_error ("Skipped too many probes, check MAXSKIPPED or try again with stap -t for more details.");
  }
  _stp_runtime_entryfn_put_context(c);
  #if !INTERRUPTIBLE
  local_irq_restore (flags);
  #endif
  #endif // STP_ALIBI
  return 0;
}

static int enter_kretprobe_common (struct kretprobe_instance *inst, struct pt_regs *regs, int entry) {
  struct kretprobe *krp = inst->rp;
  int kprobe_idx = ((uintptr_t)krp-(uintptr_t)stap_kprobes)/sizeof(struct stap_kprobe);
  struct stap_kprobe_probe *skp = &stap_kprobe_probes[((kprobe_idx >= 0 && kprobe_idx < 1)?kprobe_idx:0)];
  const struct stap_probe *sp = entry ? skp->entry_probe : skp->probe;
  if (sp) {
    #ifdef STP_ALIBI
    atomic_inc(probe_alibi(sp->index));
    #else
    struct context* __restrict__ c = NULL;
    #if !INTERRUPTIBLE
    unsigned long flags;
    #endif
    #ifdef STP_TIMING
    Stat stat = probe_timing(sp->index);
    #endif
    #if defined(STP_TIMING) || defined(STP_OVERLOAD)
    cycles_t cycles_atstart = get_cycles ();
    #endif
    #if !INTERRUPTIBLE
    local_irq_save (flags);
    #endif
    if (unlikely ((((unsigned long) (& c)) & (THREAD_SIZE-1))
      < (MINSTACKSPACE + sizeof (struct thread_info)))) {
      atomic_inc (skipped_count());
      #ifdef STP_TIMING
      atomic_inc (skipped_count_lowstack());
      #endif
      goto probe_epilogue;
    }
    if (atomic_read (session_state()) != STAP_SESSION_RUNNING)
      goto probe_epilogue;
    c = _stp_runtime_entryfn_get_context();
    if (!c) {
      #if !INTERRUPTIBLE
      atomic_inc (skipped_count());
      #endif
      #ifdef STP_TIMING
      atomic_inc (skipped_count_reentrant());
      #endif
      goto probe_epilogue;
    }
    
    c->last_stmt = 0;
    c->last_error = 0;
    c->nesting = -1;
    c->uregs = 0;
    c->kregs = 0;
    #if defined __ia64__
    c->unwaddr = 0;
    #endif
    c->probe_point = sp->pp;
    #ifdef STP_NEED_PROBE_NAME
    c->probe_name = sp->pn;
    #endif
    c->probe_type = stp_probe_type_kretprobe;
    memset(&c->ips, 0, sizeof(c->ips));
    c->user_mode_p = 0; c->full_uregs_p = 0;
    #ifdef STAP_NEED_REGPARM
    c->regparm = 0;
    #endif
    #if INTERRUPTIBLE
    c->actionremaining = MAXACTION_INTERRUPTIBLE;
    #else
    c->actionremaining = MAXACTION;
    #endif
    #if defined(STP_NEED_UNWIND_DATA)
    c->uwcache_user.state = uwcache_uninitialized;
    c->uwcache_kernel.state = uwcache_uninitialized;
    #endif
    c->kregs = regs;
    c->ips.krp.pi = inst;
    c->ips.krp.pi_longs = skp->saved_longs;
    {
      unsigned long kprobes_ip = REG_IP(c->kregs);
      if (entry)
        SET_REG_IP(regs, (unsigned long) inst->rp->kp.addr);
      else
        SET_REG_IP(regs, (unsigned long)inst->ret_addr);
      (sp->ph) (c);
      SET_REG_IP(regs, kprobes_ip);
    }
    #if defined(STP_TIMING) || defined(STP_OVERLOAD)
    {
      cycles_t cycles_atend = get_cycles ();
      int32_t cycles_elapsed = ((int32_t)cycles_atend > (int32_t)cycles_atstart)
        ? ((int32_t)cycles_atend - (int32_t)cycles_atstart)
        : (~(int32_t)0) - (int32_t)cycles_atstart + (int32_t)cycles_atend + 1;
      #ifdef STP_TIMING
      if (likely (stat)) _stp_stat_add(stat, cycles_elapsed);
      #endif
      #ifdef STP_OVERLOAD
      {
        cycles_t interval = (cycles_atend > c->cycles_base)
          ? (cycles_atend - c->cycles_base)
          : (STP_OVERLOAD_INTERVAL + 1);
        c->cycles_sum += cycles_elapsed;
        if (interval > STP_OVERLOAD_INTERVAL) {
          if (c->cycles_sum > STP_OVERLOAD_THRESHOLD) {
            _stp_error ("probe overhead exceeded threshold");
            atomic_set (session_state(), STAP_SESSION_ERROR);
            atomic_inc (error_count());
          }
          c->cycles_base = cycles_atend;
          c->cycles_sum = 0;
        }
      }
      #endif
    }
    #endif
    c->probe_point = 0;
    #ifdef STP_NEED_PROBE_NAME
    c->probe_name = 0;
    #endif
    c->probe_type = 0;
    if (unlikely (c->last_error)) {
      if (c->last_stmt != NULL)
        _stp_softerror ("%s near %s", c->last_error, c->last_stmt);
      else
        _stp_softerror ("%s", c->last_error);
      atomic_inc (error_count());
      if (atomic_read (error_count()) > MAXERRORS) {
        atomic_set (session_state(), STAP_SESSION_ERROR);
        _stp_exit ();
      }
    }
  probe_epilogue:
    if (unlikely (atomic_read (skipped_count()) > MAXSKIPPED)) {
      if (unlikely (pseudo_atomic_cmpxchg(session_state(), STAP_SESSION_RUNNING, STAP_SESSION_ERROR) == STAP_SESSION_RUNNING))
      _stp_error ("Skipped too many probes, check MAXSKIPPED or try again with stap -t for more details.");
    }
    _stp_runtime_entryfn_put_context(c);
    #if !INTERRUPTIBLE
    local_irq_restore (flags);
    #endif
    #endif // STP_ALIBI
  }
  return 0;
}

#ifdef STAP_NEED_TRACEPOINTS
#include "linux/stp_tracepoint.c"
#endif

static int systemtap_module_init (void) {
  int rc = 0;
  int cpu;
  int i=0, j=0;
  const char *probe_point = "";
  {
  #ifndef STP_NO_VERREL_CHECK
    const char* release = UTS_RELEASE;
    #ifdef STAPCONF_GENERATED_COMPILE
    const char* version = UTS_VERSION;
    #endif
    if (strcmp (release, "3.10.0-514.el7.x86_64")) {
      _stp_error ("module release mismatch (%s vs %s)", release, "3.10.0-514.el7.x86_64");
      rc = -EINVAL;
    }
    #ifdef STAPCONF_GENERATED_COMPILE
    if (strcmp (utsname()->version, version)) {
      _stp_error ("module version mismatch (%s vs %s), release %s", version, utsname()->version, release);
      rc = -EINVAL;
    }
    #endif
    #endif
    if (_stp_module_check()) rc = -EINVAL;
    if (_stp_privilege_credentials == 0) {
      if (STP_PRIVILEGE_CONTAINS(STP_PRIVILEGE, STP_PR_STAPDEV) ||
          STP_PRIVILEGE_CONTAINS(STP_PRIVILEGE, STP_PR_STAPUSR)) {
        _stp_privilege_credentials = STP_PRIVILEGE;
        #ifdef DEBUG_PRIVILEGE
          _dbug("User's privilege credentials default to %s\n",
                privilege_to_text(_stp_privilege_credentials));
        #endif
      }
      else {
        _stp_error ("Unable to verify that you have the required privilege credentials to run this module (%s required). You must use staprun version 1.7 or higher.",
                    privilege_to_text(STP_PRIVILEGE));
        rc = -EINVAL;
      }
    }
    else {
      #ifdef DEBUG_PRIVILEGE
        _dbug("User's privilege credentials provided as %s\n",
              privilege_to_text(_stp_privilege_credentials));
      #endif
      if (! STP_PRIVILEGE_CONTAINS(_stp_privilege_credentials, STP_PRIVILEGE)) {
        _stp_error ("Your privilege credentials (%s) are insufficient to run this module (%s required).",
                    privilege_to_text(_stp_privilege_credentials), privilege_to_text(STP_PRIVILEGE));
        rc = -EINVAL;
      }
    }
  }
  if (rc) goto out;
  rc = stp_session_init();
  if (rc) {
    _stp_error ("couldn't initialize the main session (rc %d)", rc);
    goto out;
  }
  #ifdef STAP_NEED_GETTIMEOFDAY
  rc = _stp_init_time();
  if (rc) {
    _stp_error ("couldn't initialize gettimeofday");
    goto out;
  }
  #endif
  #ifdef STAP_NEED_TRACEPOINTS
  rc = stp_tracepoint_init();
  if (rc) {
    _stp_error ("couldn't initialize tracepoints");
    goto out;
  }
  #endif
  (void) probe_point;
  (void) i;
  (void) j;
  atomic_set (session_state(), STAP_SESSION_STARTING);
  rc = _stp_runtime_contexts_alloc();
  if (rc != 0)
    goto out;
  global_set(s___global_called, _stp_pmap_new_sx (MAXMAPENTRIES, 0, HIST_NONE)); if (global(s___global_called) == NULL) rc = -ENOMEM;
  if (rc) {
    _stp_error ("global variable '__global_called' allocation failed");
    goto out;
  }
  global_lock_init(s___global_called);
  #ifdef STP_TIMING
  atomic_set(global_skipped(s___global_called), 0);
  #endif
  _stp_print_kernel_info("3.0/0.166", (num_online_cpus() * sizeof(struct context)), 2);
  #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
  INIT_WORK(&module_refresher_work, module_refresher, NULL);
  #else
  INIT_WORK(&module_refresher_work, module_refresher);
  #endif
  for (i=0; i<1; i++) {
    struct stap_be_probe* stp = & stap_be_probes [i];
    if (stp->type == 0)
      enter_be_probe (stp); /* rc = 0 */
  }
  if (rc) {
    if (probe_point)
      _stp_error ("probe %s registration error (rc %d)", probe_point, rc);
    atomic_set (session_state(), STAP_SESSION_ERROR);
    goto out;
  }
  /* ---- dwarf and non-dwarf kprobe-based probes ---- */
  probe_point = NULL;
  rc = stapkp_init( stap_kprobe_probes, ARRAY_SIZE(stap_kprobe_probes));
  if (rc) {
    if (probe_point)
      _stp_error ("probe %s registration error (rc %d)", probe_point, rc);
    atomic_set (session_state(), STAP_SESSION_ERROR);
    for (i=0; i<1; i++) {
      struct stap_be_probe* stp = & stap_be_probes [i];
      if (stp->type == 1)
        enter_be_probe (stp);
    }
    for (i=0; i<1; i++) {
      struct stap_be_probe* stp = & stap_be_probes [i];
      if (stp->type == 2)
        enter_be_probe (stp);
    }
    goto out;
  }
  if (atomic_read (session_state()) == STAP_SESSION_STARTING)
    atomic_set (session_state(), STAP_SESSION_RUNNING);
  
  #ifdef STP_ON_THE_FLY_TIMER_ENABLE
  hrtimer_init(&module_refresh_timer, CLOCK_MONOTONIC,
               HRTIMER_MODE_REL);
  module_refresh_timer.function = &module_refresh_timer_cb;
  #endif /* STP_ON_THE_FLY_TIMER_ENABLE */
  return 0;
out:
  _stp_pmap_del (global(s___global_called));
  atomic_set (session_state(), STAP_SESSION_STOPPED);
  stp_synchronize_sched();
  #ifdef STAP_NEED_TRACEPOINTS
   stp_tracepoint_exit();
  #endif
  #ifdef STAP_NEED_GETTIMEOFDAY
   _stp_kill_time();
  #endif
  _stp_runtime_contexts_free();
  return rc;
}


static void systemtap_module_refresh (const char *modname) {
  int state;
  int i=0, j=0;
  #if defined(STP_TIMING)
  cycles_t cycles_atstart = get_cycles();
  #endif
  mutex_lock(&module_refresh_mutex);
  state = atomic_read (session_state());
  if (state != STAP_SESSION_RUNNING && state != STAP_SESSION_STARTING && state != STAP_SESSION_ERROR) {
    #if defined(__KERNEL__)
    if (state != STAP_SESSION_STOPPING)
      printk (KERN_ERR "stap module notifier triggered in unexpected state %d\n", state);
    #endif
    mutex_unlock(&module_refresh_mutex);
    return;
  }
  (void) i;
  (void) j;
  /* ---- dwarf and non-dwarf kprobe-based probes ---- */
  stapkp_refresh( modname, stap_kprobe_probes, ARRAY_SIZE(stap_kprobe_probes));
  #if defined(STP_TIMING)
  if (likely(g_refresh_timing)) {
    cycles_t cycles_atend = get_cycles ();
    int32_t cycles_elapsed = ((int32_t)cycles_atend > (int32_t)cycles_atstart)
      ? ((int32_t)cycles_atend - (int32_t)cycles_atstart)
      : (~(int32_t)0) - (int32_t)cycles_atstart + (int32_t)cycles_atend + 1;
    _stp_stat_add(g_refresh_timing, cycles_elapsed);
  }
  #endif
  mutex_unlock(&module_refresh_mutex);
}


static void systemtap_module_exit (void) {
  int i=0, j=0;
  (void) i;
  (void) j;
  if (atomic_read (session_state()) == STAP_SESSION_STARTING)
    return;
  if (atomic_read (session_state()) == STAP_SESSION_RUNNING)
    atomic_set (session_state(), STAP_SESSION_STOPPING);
  #ifdef STP_ON_THE_FLY_TIMER_ENABLE
  hrtimer_cancel(&module_refresh_timer);
  #endif
  stp_synchronize_sched();
  mutex_lock(&module_refresh_mutex);
  /* ---- dwarf and non-dwarf kprobe-based probes ---- */
  stapkp_exit( stap_kprobe_probes, ARRAY_SIZE(stap_kprobe_probes));
  for (i=0; i<1; i++) {
    struct stap_be_probe* stp = & stap_be_probes [i];
    if (stp->type == 1)
      enter_be_probe (stp);
  }
  for (i=0; i<1; i++) {
    struct stap_be_probe* stp = & stap_be_probes [i];
    if (stp->type == 2)
      enter_be_probe (stp);
  }
  mutex_unlock(&module_refresh_mutex);
  stp_synchronize_sched();
  _stp_runtime_context_wait();
  atomic_set (session_state(), STAP_SESSION_STOPPED);
  stp_synchronize_sched();
  _stp_pmap_del (global(s___global_called));
  _stp_runtime_contexts_free();
  #ifdef STAP_NEED_TRACEPOINTS
   stp_tracepoint_exit();
  #endif
  #ifdef STAP_NEED_GETTIMEOFDAY
   _stp_kill_time();
  #endif
  preempt_disable();
  #if defined(STP_TIMING) || defined(STP_ALIBI)
  _stp_printf("----- probe hit report: \n");
  for (i = 0; i < ARRAY_SIZE(stap_probes); ++i) {
    const struct stap_probe *const p = &stap_probes[i];
    #ifdef STP_ALIBI
    int alibi = atomic_read(probe_alibi(i));
    if (alibi)
      _stp_printf ("%s, (%s), hits: %d,%s, index: %d\n",
          p->pp, p->location, alibi, p->derivation, i);
    #endif
    #ifdef STP_TIMING
    if (likely (probe_timing(i))) {
      struct stat_data *stats = _stp_stat_get (probe_timing(i), 0);
      if (stats->count) {
        int64_t avg = _stp_div64 (NULL, stats->sum, stats->count);
        _stp_printf ("%s, (%s), hits: %lld, cycles: %lldmin/%lldavg/%lldmax,%s, index: %d\n",
            p->pp, p->location, (long long) stats->count,
            (long long) stats->min, (long long) avg, (long long) stats->max,
            p->derivation, i);
      }
      _stp_stat_del (probe_timing(i));
    }
    #endif
  }
  #if defined(STP_TIMING)
  _stp_printf("----- refresh report:\n");
  if (likely (g_refresh_timing)) {
    struct stat_data *stats = _stp_stat_get (g_refresh_timing, 0);
    if (stats->count) {
      int64_t avg = _stp_div64 (NULL, stats->sum, stats->count);
      _stp_printf ("hits: %lld, cycles: %lldmin/%lldavg/%lldmax\n",
          (long long) stats->count, (long long) stats->min, 
          (long long) avg, (long long) stats->max);
    }
    _stp_stat_del (g_refresh_timing);
  }
  #endif
  _stp_print_flush();
  #endif
  if (atomic_read (skipped_count()) || atomic_read (error_count()) || atomic_read (skipped_count_reentrant())) {
    _stp_warn ("Number of errors: %d, skipped probes: %d\n", (int) atomic_read (error_count()), (int) atomic_read (skipped_count()));
    #ifdef STP_TIMING
    {
      int ctr;
      ctr = atomic_read (global_skipped(s___global_called));
      if (ctr) _stp_warn ("Skipped due to global '%s' lock timeout: %d\n", "__global_called", ctr);
      ctr = atomic_read (skipped_count_lowstack());
      if (ctr) _stp_warn ("Skipped due to low stack: %d\n", ctr);
      ctr = atomic_read (skipped_count_reentrant());
      if (ctr) _stp_warn ("Skipped due to reentrancy: %d\n", ctr);
      ctr = atomic_read (skipped_count_uprobe_reg());
      if (ctr) _stp_warn ("Skipped due to uprobe register failure: %d\n", ctr);
      ctr = atomic_read (skipped_count_uprobe_unreg());
      if (ctr) _stp_warn ("Skipped due to uprobe unregister failure: %d\n", ctr);
    }
    #endif
    _stp_print_flush();
  }
  preempt_enable_no_resched();
}


static int systemtap_kernel_module_init (void) {
  int rc = 0;
  int i=0, j=0;
  if (rc) {
    goto out;
  }
  if (rc) {
    goto out;
  }
out:
  return rc;
}


static void systemtap_kernel_module_exit (void) {
  int i=0, j=0;
}


#include "stap-symbols.h"
MODULE_DESCRIPTION("systemtap-generated probe");
MODULE_LICENSE("GPL");

#undef called
