---
layout: default
title: Under the hoods
nav_order: 6
---

# Examples
{: .no_toc }


Some Dwarf usage cases
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Thread.new

##### prologue
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
```

##### core
```javascript
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
```

