REBAR=./rebar

.PHONY: all

all:
	$(REBAR) compile

shell: all
	erl -smp disable -pa ebin
