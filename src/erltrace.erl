-module(erltrace).

-export([open/0,
         script/1,
         setopt/3,
         compile/2,
         go/1,
         stop/1,
         consume/1,
         walk/1
        ]).

-on_load(init/0).

-type dtrace_handle() :: binary().

-type dtrace_error() :: {error, {dtrace, string()}}.

-type agr_type() :: count |
                    min | max |
                    sum | avg |
                    quantize | lquantize | llquantize.


-type walk_rec() :: {agr_type(), probe_rec(), number()}.

-type dtrace_walk_data() :: [walk_rec()].

-type probe_desc() :: [string()].

-type probe_rec() :: term().

-type probe() :: {probe, probe_desc()} |
                 {probe, probe_desc(), probe_rec()}.

-type dtrace_consume_data() :: [probe()].

init() ->
    PrivDir = case code:priv_dir(?MODULE) of
                  {error, _} ->
                      EbinDir = filename:dirname(code:which(?MODULE)),
                      AppPath = filename:dirname(EbinDir),
                      filename:join(AppPath, "priv");
                  Path ->
                      Path
              end,
    erlang:load_nif(filename:join(PrivDir, "erltrace_drv"), 0).

-spec script(Script::string()) ->
                    {ok, Handle::dtrace_handle()} |
                    dtrace_error().

script(Script) ->
    {ok, H} = open(),
    ok = compile(H, Script),
    {ok, H}.

-spec open() ->
                  {ok, Handle::dtrace_handle()} |
                  dtrace_error().
open() ->
    erlang:nif_error(nif_library_not_loaded).

-spec setopt(Handle::dtrace_handle(),
             Option::string(),
             Value::string()) ->
                    ok |
                    dtrace_error().

setopt(_Handle, _Opt, _Value) ->
    erlang:nif_error(nif_library_not_loaded).


-spec compile(Handle::dtrace_handle(),
              Script::string()) ->
                     ok |
                     {error, already_running} |
                     dtrace_error().

compile(_Handle, _Script) ->
    erlang:nif_error(nif_library_not_loaded).


-spec go(Handle::dtrace_handle()) ->
                ok |
                {error, no_prog}.

go(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).

-spec stop(Handle::dtrace_handle()) ->
                  ok |
                  {error, no_prog}.

stop(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).

-spec consume(Handle::dtrace_handle()) ->
                     ok |
                     {ok, dtrace_consume_data()} |
                     dtrace_error() |
                     {error, no_prog}.

consume(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).

-spec walk(Handle::dtrace_handle()) ->
                  ok |
                  {ok, dtrace_walk_data()} |
                  dtrace_error() |
                  {error, exit | filled | stopped | no_prog}.

walk(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).
