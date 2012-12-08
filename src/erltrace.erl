-module(erltrace).

-export([open/1,
	 setopt/3,
	 compile/2,
	 go/1,
	 stop/1,
	 consume/1
	]).
-on_load(init/0).


init() ->
    ok = erlang:load_nif("priv/erltrace_drv", 0).


open(_Pid) ->
    exit(nif_library_not_loaded).

setopt(_Handle, _Opt, _Value) ->
    exit(nif_library_not_loaded).

compile(_Handle, _Script) ->
    exit(nif_library_not_loaded).

go(_Handle) ->
    exit(nif_library_not_loaded).

stop(_Handle) ->
    exit(nif_library_not_loaded).

consume(_Handle) ->
    exit(nif_library_not_loaded).
