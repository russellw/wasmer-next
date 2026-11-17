# Code generation flags that are part of the wasm32 (wasixv2) ABI rather than
# a build choice, for the build configuration WASIXV2_CONFIG names:
#
# - eh (the default): threads (atomics, bulk memory, wasm TLS), wasm exception
#   handling (exnref) and EH-based setjmp/longjmp (timer_create uses setjmp).
# - asyncify: threads, and no wasm exceptions, which binaryen's asyncify
#   cannot instrument. setjmp and longjmp are functions on the host's
#   stack_save and stack_restore, and fork works.
WASIXV2_CONFIG ?= eh

ifeq ($(WASIXV2_CONFIG),asyncify)
CFLAGS_ALL += -pthread -ftls-model=local-exec -fno-exceptions -mno-exception-handling
else
ifeq ($(WASIXV2_CONFIG),ehpic)
CFLAGS_ALL += -fPIC
endif
WASM_SJLJ = -mllvm -wasm-enable-sjlj
CFLAGS_ALL += -pthread -ftls-model=local-exec -fwasm-exceptions \
	-mllvm -wasm-use-legacy-eh=false $(WASM_SJLJ)

# The sjlj lowering pass declares __wasm_longjmp itself and would clash
# with the definition.
obj/src/setjmp/wasm32/longjmp.o obj/src/setjmp/wasm32/longjmp.lo: WASM_SJLJ =
endif
