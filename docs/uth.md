---
layout: default
title: Under the hoods
nav_order: 6
---

# Under the hoods
{: .no_toc }


Some of the features logic explained
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Breakpoints

```javascript
// there are several paths which the code can follow, mainly because of arguments provided to attach()
// let's take the simple case to begin the understanding
 
// hook is an object stored in dwarf to allow command execution inside the thread
// it also store information about the target address
// we use "wrappedInterceptor" which could be eventually used while scripting as a bridge to the real frida Interceptor
hook.interceptor = wrappedInterceptor.attach(hook.nativePtr, function(args) {
    // logic is the function provided as second argument in Interceptor.attach 
    // eventually dwarf manage if the object provided is the one with onEnter/onLeave
    var result = logic.call(this, args);
    // check if the return is an integer below 0. this will prevent the break.
    if (typeof result === 'undefined' || (typeof result === 'number' && result >= 0)) {
        // inside _onHook is where everything happens
        // the thread will be paused allowing code execution and api injection in the specific thread context
        getDwarf()._onHook(REASON_HOOK, hook.nativePtr, this.context, hook, null);
    }
});

/**
 * just a separator .P
**/

// relevant _onHook logic
this._onHook = function(reason, p, context, hook, java_handle) {
    ...
    
    while (hc.hold_context) {
        // next api hold a reference of the next api to be injected
        if (hc.next_api !== null) {
            // store the result of the api call
            hc.next_api_result = api[hc.next_api[0]].apply(that, hc.next_api[1]);
            // invalidate
            hc.next_api = null;
        }
        // sleep this thread
        Thread.sleep(1 / 100);
    }
    
    ...
}

// injection happens through the unique rpc.export to communicate with dwarf script
rpc.exports = {
    api: function(tid, api_funct, args) {
        // sanify args
        if (typeof args === 'undefined' || args === null) {
            args = [];
        }

        // check if the provided tid is actually hooked
        // otherwise fallback and execute the command to the main thread
        if (Object.keys(getDwarf().hook_contexts).length > 0) {
            // retrieve hc (hook context)
            var hc = getDwarf().hook_contexts[tid];
            if (typeof hc !== 'undefined') {
                // store data into hc that will be parsed from the sleeping thread
                hc.next_api = [api_funct, args];
                // wait for the result from the hooked thread
                while (hc.next_api_result === 'dwarf_handler') {
                    Thread.sleep(1 / 100);
                }
                // store the result
                var ret = hc.next_api_result;
                // invalidate hc stored result
                hc.next_api_result = 'dwarf_handler';
                // return
                return ret;
            }
        }

        // inject api in the main thread if tid is not provided/hooked
        return api[api_funct].apply(this, args)
    },
};

```

## Thread.new

----

```javascript
// attempt to retrieve pthread_create
var pthread_create_ptr = Module.findExportByName(null, 'pthread_create');
if (pthread_create_ptr != null && !pthread_create_ptr.isNull()) {
    this.pthread_create = new NativeFunction(pthread_create_ptr,
        'int', ['pointer', 'pointer', 'pointer', 'pointer']);
    this.handler = null;
    this.handler_fn = null;
}

// called at the right moment from the loading chain
this._init = function() {
    // check if pthread create has been declared
    if (typeof this.pthread_create !== 'undefined') {
        // allocate space for a fake handler which we intercept to run the callback
        this.handler = Memory.alloc(Process.pointerSize);
        // set permissions
        Memory.protect(this.handler, Process.pointerSize, 'rwx');
        if (Process.arch === 'arm64') {
            // arm64 require some fake code to get a trampoline from frida
            Memory.writeByteArray(this.handler, [0xE1, 0x03, 0x01, 0xAA, 0xC0, 0x03, 0x5F, 0xD6]);
        }
        // hook the fake handler
        wrappedInterceptor.replace(this.handler, new NativeCallback(function() {
            // null check for handler function
            if (Thread.handler_fn !== null) {
                // invoke callback
                return Thread.handler_fn.apply(this);
            }
            return 0;
        }, 'int', []));
    }
};

this.new = function(fn) {
    // check if pthread_create is defined
    if (typeof Thread.pthread_create === 'undefined') {
        return 1;
    }

    // check if fn is a valid function
    if (typeof fn !== 'function') {
        return 2;
    }
    
    // alocate space for struct pthread_t
    var pthread_t = Memory.alloc(Process.pointerSize);
    // set necessary permissions
    Memory.protect(pthread_t, Process.pointerSize, 'rwx');
    // store the function into thread object
    Thread.handler_fn = fn;
    // spawn the thread
    return Thread.pthread_create(pthread_t, ptr(0), Thread.handler, ptr(0));
};


// a simple test to see if it really works

console.log(Process.getCurrentThreadId());
Thread.new(function() {
    console.log('hello from -> ' + Process.getCurrentThreadId());    
});

```

