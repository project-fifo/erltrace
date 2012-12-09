erltrace
========
This is an Erlang dtrace consumer, it allows you to consume dtrace results directly from within Erlang.

implementation
--------------
erltrace is implemented as a NIF, currently it's working in a syncronouse blocking way - sorry for that. So call times are usually in the range of 200-400 microseconds so it shouldn't be that bad.

usage
-----

First is to create a handle:
```
{ok, Handle} = erltrace:open().
```
next is to compile a script:
```
erltrace:compile(
  Handle,
  "dtrace:::BEGIN {trace(\"Hello World\");} syscall:::entry { @num[execname] = count(); }"
).
```
and start the script
```
erltrace:go(Handle).
```


now you can walk or the results:
```
erltrace:consume(Handle).
erltrace:walk(Handle).
```

credits
-------
I borrowed heaviely from the code of [node-libdtrace](https://github.com/bcantrill/node-libdtrace) and [python-dtrace](https://github.com/tmetsch/python-dtrace).