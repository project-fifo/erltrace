#include "erl_nif.h"
#include <string.h>
#include <dtrace.h>

/*
 * This is a tad unsightly:  if we didn't find the definition of the
 * llquantize() aggregating action, we're going to redefine it here (along
 * with its support cast of macros).  This allows node-libdtrace to operate
 * on a machine that has llquantize(), even if it was compiled on a machine
 * without the support.
 */
#ifndef DTRACEAGG_LLQUANTIZE

#define	DTRACEAGG_LLQUANTIZE			(DTRACEACT_AGGREGATION + 9)

#define	DTRACE_LLQUANTIZE_FACTORSHIFT		48
#define	DTRACE_LLQUANTIZE_FACTORMASK		((uint64_t)UINT16_MAX << 48)
#define	DTRACE_LLQUANTIZE_LOWSHIFT		32
#define	DTRACE_LLQUANTIZE_LOWMASK		((uint64_t)UINT16_MAX << 32)
#define	DTRACE_LLQUANTIZE_HIGHSHIFT		16
#define	DTRACE_LLQUANTIZE_HIGHMASK		((uint64_t)UINT16_MAX << 16)
#define	DTRACE_LLQUANTIZE_NSTEPSHIFT		0
#define	DTRACE_LLQUANTIZE_NSTEPMASK		UINT16_MAX

#define DTRACE_LLQUANTIZE_FACTOR(x)             \
	(uint16_t)(((x) & DTRACE_LLQUANTIZE_FACTORMASK) >> \
	DTRACE_LLQUANTIZE_FACTORSHIFT)

#define DTRACE_LLQUANTIZE_LOW(x)                \
        (uint16_t)(((x) & DTRACE_LLQUANTIZE_LOWMASK) >> \
        DTRACE_LLQUANTIZE_LOWSHIFT)

#define DTRACE_LLQUANTIZE_HIGH(x)               \
        (uint16_t)(((x) & DTRACE_LLQUANTIZE_HIGHMASK) >> \
        DTRACE_LLQUANTIZE_HIGHSHIFT)

#define DTRACE_LLQUANTIZE_NSTEP(x)              \
        (uint16_t)(((x) & DTRACE_LLQUANTIZE_NSTEPMASK) >> \
        DTRACE_LLQUANTIZE_NSTEPSHIFT)
#endif

ErlNifResourceType* dtrace_handle;

typedef struct dtrace_handle_s {
  dtrace_hdl_t* handle;
  int err;
  dtrace_prog_t *prog;
  dtrace_proginfo_t info;
  ERL_NIF_TERM reply;
  ErlNifEnv* env;
} dtrace_handle_s;

typedef struct bufhandler_env {
  dtrace_handle_s *handle;
  ErlNifEnv* env;
} bufhandler_env_t;


ERL_NIF_TERM
action(ErlNifEnv* env, const dtrace_recdesc_t *rec)
{
  dtrace_actkind_t act = rec->dtrd_action;

  switch (act) {
  case DTRACEACT_NONE: {return enif_make_string(env, "<none>", ERL_NIF_LATIN1); break;}
  case DTRACEACT_DIFEXPR: {return enif_make_string(env, "<DIF expression>", ERL_NIF_LATIN1); break;}
  case DTRACEACT_EXIT: {return enif_make_string(env, "exit()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_PRINTF: {return enif_make_string(env, "printf()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_PRINTA: {return enif_make_string(env, "printa()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_LIBACT: {return enif_make_string(env, "<library action>", ERL_NIF_LATIN1); break;}
  case DTRACEACT_USTACK: {return enif_make_string(env, "ustack()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_JSTACK: {return enif_make_string(env, "jstack()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_USYM: {return enif_make_string(env, "usym()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_UMOD: {return enif_make_string(env, "umod()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_UADDR: {return enif_make_string(env, "uaddr()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_STOP: {return enif_make_string(env, "stop()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_RAISE: {return enif_make_string(env, "raise()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_SYSTEM: {return enif_make_string(env, "system()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_FREOPEN: {return enif_make_string(env, "freopen()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_STACK: {return enif_make_string(env, "stack()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_SYM: {return enif_make_string(env, "sym()", ERL_NIF_LATIN1); break;}
  case DTRACEACT_MOD: {return enif_make_string(env, "mod()", ERL_NIF_LATIN1); break;}
  case DTRACEAGG_COUNT: {return enif_make_string(env, "count()", ERL_NIF_LATIN1); break;}
  case DTRACEAGG_MIN: {return enif_make_string(env, "min()", ERL_NIF_LATIN1); break;}
  case DTRACEAGG_MAX: {return enif_make_string(env, "max()", ERL_NIF_LATIN1); break;}
  case DTRACEAGG_AVG: {return enif_make_string(env, "avg()", ERL_NIF_LATIN1); break;}
  case DTRACEAGG_SUM: {return enif_make_string(env, "sum()", ERL_NIF_LATIN1); break;}
  case DTRACEAGG_STDDEV: {return enif_make_string(env, "stddev()", ERL_NIF_LATIN1); break;}
  case DTRACEAGG_QUANTIZE: {return enif_make_string(env, "quantize()", ERL_NIF_LATIN1); break;}
  case DTRACEAGG_LQUANTIZE: {return enif_make_string(env, "lquantize()", ERL_NIF_LATIN1); break;}
  case DTRACEAGG_LLQUANTIZE: {return enif_make_string(env, "llquantize()", ERL_NIF_LATIN1); break;}
  default: {return enif_make_string(env, "<unknown>", ERL_NIF_LATIN1);}
  };
}

static boolean_t valid(const dtrace_recdesc_t *rec)
{
  dtrace_actkind_t action = rec->dtrd_action;
  switch (action) {
  case DTRACEACT_DIFEXPR:
  case DTRACEACT_SYM:
  case DTRACEACT_MOD:
  case DTRACEACT_USYM:
  case DTRACEACT_UMOD:
  case DTRACEACT_UADDR:
    return (B_TRUE);
  default:
    return (B_FALSE);
  }
}

static ERL_NIF_TERM dtrace_err(ErlNifEnv* env, dtrace_handle_s *handle) {
  return enif_make_tuple2(env,
			  enif_make_atom(env, "error"),
			  enif_make_tuple2(env,
					   enif_make_atom(env, "dtrace"),
					   enif_make_string(env,
							    dtrace_errmsg(NULL, handle->err),
							    ERL_NIF_LATIN1)));
};

static ERL_NIF_TERM
record(dtrace_hdl_t *dtp, ErlNifEnv* env, const dtrace_recdesc_t *rec, caddr_t addr)
{
  char buf[2048], *tick, *plus;
  switch (rec->dtrd_action) {
  case DTRACEACT_DIFEXPR:
    switch (rec->dtrd_size) {
    case sizeof (uint64_t):
      return enif_make_int64(env, *((int64_t *)addr));

    case sizeof (uint32_t):
      return enif_make_int(env, *((int32_t *)addr));

    case sizeof (uint16_t):
      return enif_make_int(env, *((int16_t *)addr));

    case sizeof (uint8_t):
      return enif_make_int(env, *((int8_t *)addr));

    default:
      return enif_make_string(env, ((const char *)addr), ERL_NIF_LATIN1);
    }

  case DTRACEACT_SYM:
  case DTRACEACT_MOD:
  case DTRACEACT_USYM:
  case DTRACEACT_UMOD:
  case DTRACEACT_UADDR:

    buf[0] = '\0';

    if (DTRACEACT_CLASS(rec->dtrd_action) == DTRACEACT_KERNEL) {
      uint64_t pc = ((uint64_t *)addr)[0];
      dtrace_addr2str(dtp, pc, buf, sizeof (buf) - 1);
    } else {
      uint64_t pid = ((uint64_t *)addr)[0];
      uint64_t pc = ((uint64_t *)addr)[1];
      dtrace_uaddr2str(dtp, pid, pc, buf, sizeof (buf) - 1);
    }

    if (rec->dtrd_action == DTRACEACT_MOD ||
	rec->dtrd_action == DTRACEACT_UMOD) {
      /*
       * If we're looking for the module name, we'll
       * return everything to the left of the left-most
       * tick -- or "<undefined>" if there is none.
       */
      if ((tick = strchr(buf, '`')) == NULL)
	return enif_make_atom(env, "undefined");

      *tick = '\0';
    } else if (rec->dtrd_action == DTRACEACT_SYM ||
              rec->dtrd_action == DTRACEACT_USYM) {
      /*
       * If we're looking for the symbol name, we'll
       * return everything to the left of the right-most
       * plus sign (if there is one).
       */
      if ((plus = strrchr(buf, '+')) != NULL)
	*plus = '\0';
    }
    return enif_make_string(env, buf, ERL_NIF_LATIN1);
  default:
    return enif_make_string(env, ((const char *)addr), ERL_NIF_LATIN1);
  }
  return enif_make_int(env, *((int8_t *)addr));
}

static ERL_NIF_TERM probe_desc(ErlNifEnv* env, dtrace_probedesc_t *d) {
  return enif_make_tuple4(env,
			  enif_make_atom(env, d->dtpd_provider),
			  enif_make_atom(env, d->dtpd_mod),
			  enif_make_atom(env, d->dtpd_func),
			  enif_make_atom(env, d->dtpd_name));
}


static int
chew(const dtrace_probedata_t *data, void *arg)
{

  processorid_t cpu = data->dtpda_cpu;
  dtrace_handle_s *handle = (dtrace_handle_s *) arg;
  ERL_NIF_TERM res = enif_make_tuple3(handle->env,
				      enif_make_atom(handle->env, "chew"),
				      probe_desc(handle->env, data->dtpda_pdesc),
				      enif_make_int(handle->env, cpu));


  if (!handle->reply){
    handle->reply = enif_make_list1(handle->env, res);
  } else {
    handle->reply = enif_make_list_cell(handle->env, res, handle->reply);
  };

  return (DTRACE_CONSUME_THIS);
}

static int
chewrec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg)
{
  dtrace_handle_s *handle = (dtrace_handle_s *) arg;

  if (rec == NULL) {
    return (DTRACE_CONSUME_NEXT);
  }

  if (!valid(rec)) {
    return (DTRACE_CONSUME_ABORT);
  }

  ERL_NIF_TERM res = enif_make_tuple4(handle->env,
				      enif_make_atom(handle->env, "chewrec"),
				      probe_desc(handle->env, data->dtpda_pdesc),
				      action(handle->env, rec),
				      record(handle->handle, handle->env, rec, data->dtpda_data));
  if (!handle->reply){
    handle->reply = enif_make_list1(handle->env, res);
  } else {
    handle->reply = enif_make_list_cell(handle->env, res, handle->reply);
  };

  return (DTRACE_CONSUME_THIS);
}

static int
buffered(const dtrace_bufdata_t *bufdata, void *arg)
{
  dtrace_handle_s *handle = (dtrace_handle_s *) arg;
  dtrace_probedata_t *data = bufdata->dtbda_probe;
  const dtrace_recdesc_t *rec = bufdata->dtbda_recdesc;

  if (rec == NULL || rec->dtrd_action != DTRACEACT_PRINTF)
    return (DTRACE_HANDLE_OK);

  ERL_NIF_TERM res = enif_make_tuple3(handle->env,
				      enif_make_atom(handle->env, "printf"),
				      probe_desc(handle->env, data->dtpda_pdesc),
				      enif_make_string(handle->env, bufdata->dtbda_buffered, ERL_NIF_LATIN1));
  if (!handle->reply){
    handle->reply = enif_make_list1(handle->env, res);
  } else {
    handle->reply = enif_make_list_cell(handle->env, res, handle->reply);
  };

  return (DTRACE_HANDLE_OK);
}

ERL_NIF_TERM *
ranges_quantize(ErlNifEnv* env, dtrace_aggvarid_t varid)
{
  int64_t min, max;
  ERL_NIF_TERM *ranges;
  int i;

  ranges = (ERL_NIF_TERM*) malloc(DTRACE_QUANTIZE_NBUCKETS * sizeof(ERL_NIF_TERM));

  for (i = 0; i < DTRACE_QUANTIZE_NBUCKETS; i++) {

    if (i < DTRACE_QUANTIZE_ZEROBUCKET) {
      /*
       * If we're less than the zero bucket, our range
       * extends from negative infinity through to the
       * beginning of our zeroth bucket.
       */
      min = i > 0 ? DTRACE_QUANTIZE_BUCKETVAL(i - 1) + 1 :
	INT64_MIN;
      max = DTRACE_QUANTIZE_BUCKETVAL(i);
    } else if (i == DTRACE_QUANTIZE_ZEROBUCKET) {
      min = max = 0;
    } else {
      min = DTRACE_QUANTIZE_BUCKETVAL(i);
      max = i < DTRACE_QUANTIZE_NBUCKETS - 1 ?
	DTRACE_QUANTIZE_BUCKETVAL(i + 1) - 1 :
	INT64_MAX;
    }

    ranges[i] = enif_make_tuple2(env,
				 enif_make_int64(env, min),
				 enif_make_int64(env, max));
  }
  return ranges;
}

ERL_NIF_TERM *
ranges_lquantize(ErlNifEnv* env,
		 dtrace_aggvarid_t varid,
		 const uint64_t arg)
{
	int64_t min, max;
	ERL_NIF_TERM *ranges;

	int32_t base;
	uint16_t step, levels;
	int i;

	base = DTRACE_LQUANTIZE_BASE(arg);
	step = DTRACE_LQUANTIZE_STEP(arg);
	levels = DTRACE_LQUANTIZE_LEVELS(arg);

	ranges = (ERL_NIF_TERM*) malloc((levels + 2) * sizeof(ERL_NIF_TERM));

	for (i = 0; i <= levels + 1; i++) {
		min = i == 0 ? INT64_MIN : base + ((i - 1) * step);
		max = i > levels ? INT64_MAX : base + (i * step) - 1;
		ranges[i] = enif_make_tuple2(env,
					     enif_make_int64(env, min),
					     enif_make_int64(env, max));
	}

	return ranges;
}

ERL_NIF_TERM *
ranges_llquantize(ErlNifEnv* env,
		  dtrace_aggvarid_t varid,
		  const uint64_t arg, int nbuckets)
{
  int64_t value = 1, next, step;
  ERL_NIF_TERM *ranges;
  int bucket = 0, order;
  uint16_t factor, low, high, nsteps;


  factor = DTRACE_LLQUANTIZE_FACTOR(arg);
  low = DTRACE_LLQUANTIZE_LOW(arg);
  high = DTRACE_LLQUANTIZE_HIGH(arg);
  nsteps = DTRACE_LLQUANTIZE_NSTEP(arg);

  ranges = (ERL_NIF_TERM*) malloc(nbuckets * sizeof(ERL_NIF_TERM));

  for (order = 0; order < low; order++)
    value *= factor;
  ranges[bucket] = enif_make_tuple2(env,
				    enif_make_int64(env, 0),
				    enif_make_int64(env, value - 1));

  bucket++;

  next = value * factor;
  step = next > nsteps ? next / nsteps : 1;

  while (order <= high) {
    ranges[bucket] = enif_make_tuple2(env,
				      enif_make_int64(env, value),
				      enif_make_int64(env, value + step - 1));
    bucket++;

    if ((value += step) != next)
      continue;

    next = value * factor;
    step = next > nsteps ? next / nsteps : 1;
    order++;
  }

  ranges[bucket] = enif_make_tuple2(env,
				    enif_make_int64(env, value),
				    enif_make_int64(env, INT64_MAX));

  return ranges;
}


/*
 * DTrace aggregate walker use this instead of chew, chewrec and buffered (which just output printf)...
 */

static int walk(const dtrace_aggdata_t *agg, void *arg)
{
  dtrace_handle_s *handle = (dtrace_handle_s *) arg;
  const dtrace_aggdesc_t *aggdesc = agg->dtada_desc;
  const dtrace_recdesc_t *aggrec;
  ErlNifEnv* env = handle->env;
  ERL_NIF_TERM res, aggrfun, key = 0;

  int i;

  for (i = 1; i < aggdesc->dtagd_nrecs - 1; i++) {
    const dtrace_recdesc_t *rec = &aggdesc->dtagd_rec[i];
    caddr_t addr = agg->dtada_data + rec->dtrd_offset;

    if (!valid(rec)) {
      return (DTRACE_AGGWALK_ERROR);
    }

    res = record(handle->handle, env, rec, addr);

    if (!key){
      key = enif_make_list1(env, res);
    } else {
      key = enif_make_list_cell(env, res, key);
    };
  }

  aggrec = &aggdesc->dtagd_rec[aggdesc->dtagd_nrecs - 1];

  res = 0;
  switch (aggrec->dtrd_action) {
  case DTRACEAGG_COUNT:{ aggrfun = enif_make_atom(env, "count"); break;}
  case DTRACEAGG_MIN:{ aggrfun = enif_make_atom(env, "min"); break;}
  case DTRACEAGG_MAX:{ aggrfun = enif_make_atom(env, "max"); break;}
  case DTRACEAGG_SUM:{ aggrfun = enif_make_atom(env, "sum"); break;}
  case DTRACEAGG_AVG:{ aggrfun = enif_make_atom(env, "avg"); break;}
  case DTRACEAGG_QUANTIZE:{ aggrfun = enif_make_atom(env, "quantize"); break;}
  case DTRACEAGG_LQUANTIZE:{ aggrfun = enif_make_atom(env, "lquantize"); break;}
  case DTRACEAGG_LLQUANTIZE:{ aggrfun = enif_make_atom(env, "llquantize"); break;}
  }
  switch (aggrec->dtrd_action) {
  case DTRACEAGG_COUNT:
  case DTRACEAGG_MIN:
  case DTRACEAGG_MAX:
  case DTRACEAGG_SUM: {
    caddr_t addr = agg->dtada_data + aggrec->dtrd_offset;

    res = enif_make_int64(env, *((int64_t *)addr));
    break;
  }

  case DTRACEAGG_AVG: {
    const int64_t *data = (int64_t *)(agg->dtada_data +
				      aggrec->dtrd_offset);

    res = enif_make_double(env, data[1] / (double)data[0]);
    break;
  }

  case DTRACEAGG_QUANTIZE: {
    ERL_NIF_TERM quantize=0, datum;
    const int64_t *data = (int64_t *)(agg->dtada_data +
				      aggrec->dtrd_offset);
    ERL_NIF_TERM *ranges;
    int i = 0;

    ranges = ranges_quantize(env, aggdesc->dtagd_varid);

    for (i = 0; i < DTRACE_QUANTIZE_NBUCKETS; i++) {
      if (!data[i])
	continue;

      datum = enif_make_tuple2(env,
			       ranges[i],
			       enif_make_int64(env, data[i]));

      if (!quantize){
	quantize = enif_make_list1(env, datum);
      } else {
	quantize = enif_make_list_cell(env, datum, quantize);
      };
    }
    free(ranges);

    res = quantize;
    break;
  }

  case DTRACEAGG_LQUANTIZE:
  case DTRACEAGG_LLQUANTIZE: {
    ERL_NIF_TERM lquantize = 0;
    const int64_t *data = (int64_t *)(agg->dtada_data +
				      aggrec->dtrd_offset);
    ERL_NIF_TERM *ranges, datum;
    int i = 0;

    uint64_t arg = *data++;
    int levels = (aggrec->dtrd_size / sizeof (uint64_t)) - 1;

    ranges = (aggrec->dtrd_action == DTRACEAGG_LQUANTIZE ?
	      ranges_lquantize(env, aggdesc->dtagd_varid, arg) :
	      ranges_llquantize(env, aggdesc->dtagd_varid, arg, levels));

    for (i = 0; i < levels; i++) {
      if (!data[i])
	continue;

      datum = enif_make_tuple2(env,
			       ranges[i],
			       enif_make_int64(env, data[i]));

      if (!lquantize){
	lquantize = enif_make_list1(env, datum);
      } else {
	lquantize = enif_make_list_cell(env, datum, lquantize);
      };
    }

    free(ranges);
    res = lquantize;
    break;
  }

  default:
    return (DTRACE_AGGWALK_ERROR);
  }

  res =  enif_make_tuple3(env,
			  aggrfun,
			  key,
			  res);
  if (!handle->reply){
    handle->reply = enif_make_list1(env, res);
  } else {
    handle->reply = enif_make_list_cell(env, res, handle->reply);
  };

  return (DTRACE_AGGWALK_REMOVE);
}

static void handle_dtor(ErlNifEnv* env, void* handle) {
  dtrace_close(((dtrace_handle_s*)handle)->handle);
  enif_release_resource(handle);
};

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
  ErlNifResourceFlags flags = (ErlNifResourceFlags)(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);
  dtrace_handle = enif_open_resource_type(env,
					  "erltrace",
					  "handle",
					  &handle_dtor,
					  flags,
					  0);
  return 0;
};

static ERL_NIF_TERM open_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  dtrace_handle_s *handle;

  handle = (dtrace_handle_s *)enif_alloc_resource(dtrace_handle, sizeof(dtrace_handle_s));
  handle->prog = NULL;
  handle->handle = dtrace_open(DTRACE_VERSION, 0, &(handle->err));

  if (handle->handle == NULL) { // if the handle could not be generated.
    fprintf(stderr, "Unable to get hold of an dtrace handle: %s\n", dtrace_errmsg(NULL, handle->err));
    return enif_make_tuple2(env,
			    enif_make_atom(env, "error"),
			    enif_make_string(env, dtrace_errmsg(NULL, handle->err), ERL_NIF_LATIN1));
  };

  dtrace_setopt(handle->handle, "bufsize", "4m");
  dtrace_setopt(handle->handle, "aggsize", "4m");

  if (dtrace_handle_buffered(handle->handle, &buffered, handle) == -1) {
    return enif_make_tuple2(env,
			    enif_make_atom(env, "error"),
			    enif_make_string(env, dtrace_errmsg(NULL, handle->err), ERL_NIF_LATIN1));
  }

  return  enif_make_tuple2(env,
			   enif_make_atom(env, "ok"),
			   enif_make_resource(env, handle));
};

static ERL_NIF_TERM setopt_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  char opt[1024];
  char val[1024];
  dtrace_handle_s *handle;
  if (argc < 3) {
    return enif_make_badarg(env);
  }

  if (!enif_get_resource(env, argv[0], dtrace_handle, (void **)&handle)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_string(env, argv[1], (char*)&opt, 1023, ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_string(env, argv[2], (char*)&val, 1023, ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }

  if (dtrace_setopt(handle->handle, opt, val) != 0) {
    fprintf(stderr, "Unable to set bufsize option: %s\n", dtrace_errmsg(NULL, handle->err));
    return enif_make_tuple2(env,
			    enif_make_atom(env, "error"),
			    enif_make_string(env, dtrace_errmsg(NULL, handle->err), ERL_NIF_LATIN1));

  }
  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM compile_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  char script[10240];
  dtrace_handle_s *handle;
  if (argc < 2) {
    return enif_make_badarg(env);
  }

  if (!enif_get_resource(env, argv[0], dtrace_handle, (void **)&handle)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_string(env, argv[1], (char*)&script, 10239, ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }
  if (handle->prog) {
    return enif_make_tuple2(env,
			    enif_make_atom(env, "error"),
			    enif_make_atom(env, "already_running"));

  }

  handle->prog = dtrace_program_strcompile(handle->handle, script, DTRACE_PROBESPEC_NAME, DTRACE_C_ZDEFS, 0, NULL);
  if (handle->prog == NULL) {
    fprintf(stderr, "Unable to compile d script: %s\n", dtrace_errmsg(NULL, handle->err));
    return dtrace_err(env, handle);
  };
  dtrace_program_exec(handle->handle, handle->prog, &(handle->info));
  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM go_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  dtrace_handle_s *handle;
  if (argc < 1) {
    return enif_make_badarg(env);
  }

  if (!enif_get_resource(env, argv[0], dtrace_handle, (void **)&handle)) {
    return enif_make_badarg(env);
  }

  if (!handle->prog) {
    return enif_make_tuple2(env,
			    enif_make_atom(env, "error"),
			    enif_make_atom(env, "no_prog"));
  }
  dtrace_go(handle->handle);
  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM stop_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  dtrace_handle_s *handle;
  if (argc < 1) {
    return enif_make_badarg(env);
  }

  if (!enif_get_resource(env, argv[0], dtrace_handle, (void **)&handle)) {
    return enif_make_badarg(env);
  }

  if (!handle->prog) {
    return enif_make_tuple2(env,
			    enif_make_atom(env, "error"),
			    enif_make_atom(env, "no_prog"));
  }
  dtrace_stop(handle->handle);
  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM consume_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  dtrace_handle_s *handle;
  if (argc < 1) {
    return enif_make_badarg(env);
  }

  if (!enif_get_resource(env, argv[0], dtrace_handle, (void **)&handle)) {
    return enif_make_badarg(env);
  }

  if (!handle->prog) {
    return enif_make_tuple2(env,
			    enif_make_atom(env, "error"),
			    enif_make_atom(env, "no_prog"));
  }
  handle->env = env;
  handle->reply = 0;
  dtrace_sleep(handle->handle);

  dtrace_work(handle->handle, NULL, chew, chewrec, handle);

  if (handle->reply) {
    return handle->reply;
  };

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM walk_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  dtrace_handle_s *handle;
  if (argc < 1) {
    return enif_make_badarg(env);
  }

  if (!enif_get_resource(env, argv[0], dtrace_handle, (void **)&handle)) {
    return enif_make_badarg(env);
  }

  if (!handle->prog) {
    return enif_make_tuple2(env,
			    enif_make_atom(env, "error"),
			    enif_make_atom(env, "no_prog"));
  }
  handle->env = env;
  handle->reply = 0;

  int status = dtrace_status(handle->handle);
  switch(status) {
  case DTRACE_STATUS_EXITED:  {return enif_make_atom(env, "exited");};
  case DTRACE_STATUS_FILLED:  {return enif_make_atom(env, "filled");};
  case DTRACE_STATUS_STOPPED: {return enif_make_atom(env, "stopped");};
  case -1: {return dtrace_err(env, handle);};
  }


  if (dtrace_aggregate_snap(handle->handle) != 0) {
    return dtrace_err(env, handle);
  }

  // Instead of print -> we'll walk...dtrace_aggregate_print(handle, stdout, NULL);
  if (dtrace_aggregate_walk(handle->handle, walk, handle) != 0) {
    return dtrace_err(env, handle);
  }

  if (handle->reply) {
    return handle->reply;
  };

  return enif_make_atom(env, "ok");
}

static ErlNifFunc nif_funcs[] = {
  {"open", 0, open_nif},
  {"setopt", 3, setopt_nif},
  {"compile", 2, compile_nif},
  {"go", 1, go_nif},
  {"stop", 1, stop_nif},
  {"consume", 1, consume_nif},
  {"walk", 1, walk_nif},

};

ERL_NIF_INIT(erltrace, nif_funcs, *load, NULL, NULL, NULL)
