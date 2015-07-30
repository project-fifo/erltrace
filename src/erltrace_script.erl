-module(erltrace_script).

-export([compile/1]).


build_probe({A,B,C,D}) ->
    io_lib:format("~s:~s:~s:~s", [A, B, C, D]).


build_action(L) when is_list(L) ->
    string:join(
      lists:map(fun build_action/1, L),
      ";");

build_action({trace, V}) ->
    io_lib:format("trace(~s)", [V]).


build_predicate(L) when is_list(L) ->
    string:join(
      lists:map(fun build_predicate/1, L),
      "&&");


build_predicate({K,  V}) ->
    io_lib:format("(~s == ~s)", [K, V]);

build_predicate({E}) ->
    io_lib:format("(~s)", [E]).


build_program({Probe, Action}) ->
    io_lib:format("~s { ~s }",
		  [build_probe(Probe),
		   build_action(Action)]);

build_program({Probe, Predicate, Action}) ->
    io_lib:format("~s / ~s / { ~s }",
		  [build_probe(Probe),
		   build_predicate(Predicate),
		   build_action(Action)]).


compile([Code]) ->
    build_program(Code).
