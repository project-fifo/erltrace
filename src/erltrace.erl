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
    ok = erlang:load_nif("priv/erltrace_drv", 0).

script(Script) ->
    {ok, H} = open(),
    ok = compile(H, Script),
    {ok, H}.

-spec open() -> {ok, Handle::dtrace_handle()} |
		dtrace_error().
open() ->
    exit(nif_library_not_loaded).

-spec setopt(Handle::dtrace_handle(),
	     Option::string(),
	     Value::string()) -> ok |
				 dtrace_error().

setopt(_Handle, _Opt, _Value) ->
    exit(nif_library_not_loaded).


-spec compile(Handle::dtrace_handle(),
	      Script::string()) -> ok |
				   {error, already_running} |
				   dtrace_error().

compile(_Handle, _Script) ->
    exit(nif_library_not_loaded).


-spec go(Handle::dtrace_handle()) -> ok |
				     {error, no_prog}.

go(_Handle) ->
    exit(nif_library_not_loaded).

-spec stop(Handle::dtrace_handle()) -> ok |
				       {error, no_prog}.

stop(_Handle) ->
    exit(nif_library_not_loaded).

-spec consume(Handle::dtrace_handle()) -> ok |
					  {ok, dtrace_consume_data()} |
					  dtrace_error() |
					  {error, no_prog}.

consume(_Handle) ->
    exit(nif_library_not_loaded).

-spec walk(Handle::dtrace_handle()) -> ok |
				       {ok, dtrace_walk_data()} |
				       dtrace_error() |
				       {error, exited | filled | stopped | no_prog}.

walk(_Handle) ->
    exit(nif_library_not_loaded).
