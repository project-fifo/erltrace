#include "erl_nif.h"
#include <string.h>
#include <dtrace.h>


ErlNifResourceType* dtrace_handle;

typedef struct dtrace_handle_s {
  dtrace_hdl_t* handle;
  int err;
  dtrace_prog_t *prog;
  dtrace_proginfo_t info;
  ErlNifPid* pid;
} dtrace_handle_s;

typedef struct bufhandler_env {
  dtrace_handle_s *handle;
  ErlNifEnv* env;
} bufhandler_env_t;



static void handle_dtor(ErlNifEnv* env, void* handle) {
  dtrace_close(((dtrace_handle_s*)handle)->handle);
  enif_release_resource(handle);
};


static ERL_NIF_TERM probe_desc(ErlNifEnv* env, dtrace_probedesc_t *d) {
  return enif_make_tuple4(env,
			  enif_make_atom(env, d->dtpd_provider),
			  enif_make_atom(env, d->dtpd_mod),
			  enif_make_atom(env, d->dtpd_func),
			  enif_make_atom(env, d->dtpd_name));
}

static int bufhandler(const dtrace_bufdata_t *bufdata, void *arg)
{
  fprintf(stdout, " +--> In buffered: %s", bufdata->dtbda_buffered);

  dtrace_probedata_t *data = bufdata->dtbda_probe;
  const dtrace_recdesc_t *rec = bufdata->dtbda_recdesc;
  bufhandler_env_t *env = (bufhandler_env_t *) arg;
  if (rec == NULL || rec->dtrd_action != DTRACEACT_PRINTF)
    return (DTRACE_HANDLE_OK);
  ErlNifEnv* menv = enif_alloc_env();
  enif_send(menv,
	    env->handle->pid,
	    menv,
	    enif_make_tuple3(menv,
			     enif_make_atom(menv, "printf"),
			     probe_desc(menv, data->dtpda_pdesc),
			     enif_make_string(menv, bufdata->dtbda_buffered, ERL_NIF_LATIN1)));

  return (DTRACE_HANDLE_OK);
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
  }

  return enif_make_atom(env, "undefined");
}

static int consume(const dtrace_probedata_t *data,
	    const dtrace_recdesc_t *rec, void *arg)
{
  printf("1\n");
  bufhandler_env_t *env = (bufhandler_env_t *) arg;
  ErlNifEnv* menv = enif_alloc_env();
  ERL_NIF_TERM probe = probe_desc(menv, data->dtpda_pdesc);
  printf("2\n");

  if (rec == NULL) {
    printf("3\n");
    enif_send(menv,
	      env->handle->pid,
	      menv,
	      enif_make_tuple3(menv,
			       enif_make_atom(menv, "probe"),
			       probe,
			       enif_make_atom(menv, "undefined")));
    printf("4\n");

    return (DTRACE_CONSUME_NEXT);
  }
  printf("5\n");

  if (!valid(rec)) {
    printf("6\n");

    /*
     * If this is a printf(), we'll defer to the bufhandlera.
     */
    if (rec->dtrd_action == DTRACEACT_PRINTF)
      return (DTRACE_CONSUME_THIS);
    printf("7\n");

    return (DTRACE_CONSUME_ABORT);
  }
  printf("8\n");

    enif_send(menv,
	    env->handle->pid,
	    menv,
	    enif_make_tuple3(menv,
			     enif_make_atom(menv, "probe"),
			     probe,
			     record(env->handle->handle, menv, rec, data->dtpda_data)));
  printf("9\n");
  return (DTRACE_CONSUME_THIS);
}

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
  ErlNifPid pid;
  bufhandler_env_t bufenv;

  if (argc < 1) {
    return enif_make_badarg(env);
  }

  handle = (dtrace_handle_s *)enif_alloc_resource(dtrace_handle, sizeof(dtrace_handle_s));
  if (!enif_get_local_pid(env, argv[0], &pid)) {
    return enif_make_badarg(env);
  }
  handle->pid = &pid;
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

  bufenv.env = env;
  bufenv.handle = handle;

  if (dtrace_handle_buffered(handle->handle, &bufhandler, &bufenv) == -1) {
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
    return enif_make_tuple2(env,
			    enif_make_atom(env, "error"),
			    enif_make_string(env, dtrace_errmsg(NULL, handle->err), ERL_NIF_LATIN1));
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
  bufhandler_env_t bufenv;
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
  bufenv.env = env;
  bufenv.handle = handle;
  printf("2.1\n");
  dtrace_sleep(handle->handle);
  if(!dtrace_work(handle->handle, NULL, NULL, consume, &bufenv)) {
    printf("2.2\n");

    return enif_make_tuple2(env,
			    enif_make_atom(env, "error"),
			    enif_make_string(env, dtrace_errmsg(NULL, handle->err), ERL_NIF_LATIN1));

  }
  printf("2.3\n");
  return enif_make_atom(env, "ok");
}

static ErlNifFunc nif_funcs[] = {
  {"open", 1, open_nif},
  {"setopt", 3, setopt_nif},
  {"compile", 2, compile_nif},
  {"go", 1, go_nif},
  {"stop", 1, stop_nif},
  {"consume", 1, consume_nif},

};

ERL_NIF_INIT(erltrace, nif_funcs, *load, NULL, NULL, NULL)
