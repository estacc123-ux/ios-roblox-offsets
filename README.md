> **Version:** 2.720.1164  
> **Binary:** Roblox iOS (ARM64)  
> **Tool:** Ghidra + Jython scripting console  
> **Download:** https://decrypt.day/app/id431946152  
>
> This took a while. What follows is a map of the Luau VM internals from the Roblox
> iOS binary - structs, offsets, functions, the works. This is **Luau** (Roblox's fork
> of Lua 5.1), not standard Lua, so don't go copying offsets from some random Lua 5.3
> repo and wondering why everything is on fire. Android offsets coming later, been busy.

---

## How This Was Done

If you want to verify anything here or pick up where this left off, here's the actual approach.

**1. String cross-references**  
Ghidra lets you find every piece of code that touches a string literal. Strings like `"attempt to call"`, `"__index"`, `"not enough memory"`, and `"13lua_exception"` are anchor points. Find the string, find the function that uses it, read what it does to nearby memory, and you've got struct offsets basically for free.

**2. Known-value anchors in global_State**  
The `tmname[]` and `ttname[]` arrays are a gift. They hold interned strings for every metamethod (`"__index"`, `"__call"`, etc.) and type name (`"nil"`, `"string"`, etc.) in a fixed order defined by the Luau source. Find any one entry and you've pinned the entire array - and by extension, the base address of `global_State`.

**3. luaE_newstate as a free layout map**  
The state initializer writes to basically every important field at startup: `L->gt`, `g->registry`, `g->strt`, the GC threshold, all of it. Just read the store sequence and you get a mostly-complete layout of both `lua_State` and `global_State` without breaking a sweat.

**4. Store-sequence analysis**  
When a known function allocates a struct and immediately fills it in (like `luaD_precall` pushing a new `CallInfo`), the stores happen in field order. Reading them gives you the layout directly. This is also how we caught that a lot of public references have `CallInfo` wrong - `func` is not at `ci+0x00` in this binary. More on that below.

**5. C++ exception type_info**  
Roblox's iOS build throws C++ exceptions for Lua errors instead of using `longjmp`. The `__cxa_throw` call passes a `std::type_info*`, which contains an Itanium-mangled class name string. Follow the pointer, read the string, and you get the class name and layout handed to you. That's how we confirmed `lua_exception`.

**Confidence levels - please read these:**
- `[HIGH]` - seen directly in the decompiler, no guessing involved
- `[MED]` - inferred from context, consistent with Luau source patterns
- `[LOW]` - the field exists, but what it actually means is a best guess

---

## lua_State (L)

The per-thread VM state. Every coroutine gets its own `lua_State`. They all share one `global_State` via `l_G`.

```cpp
L + 0x00 = unknown
L + 0x01 = tt / type       (byte)
L + 0x03 = status          (byte)
              0x00 = suspended / OK  - can be resumed
              0x01 = LUA_YIELD
              0x06 = LUA_BREAK      - Luau-specific, doesn't exist in standard Lua
              0x7f = running        - sentinel that blocks a thread from resuming itself
L + 0x08 = stacksize       (int - 0x2d on init; upper bytes still unknown)
L + 0x0c = size_ci         (int - 8 on init)
L + 0x18 = l_G             (global_State* - shared across all threads)
L + 0x20 = stack_last      (StkId - one past the last valid stack slot)
L + 0x28 = top             (StkId - current top of stack)
L + 0x30 = stack           (StkId - stack allocation base)
L + 0x38 = ci              (CallInfo* - current call frame)
L + 0x40 = base            (StkId - current frame base / first arg)
L + 0x58 = end_ci          (CallInfo* - one past the last CallInfo slot)
L + 0x60 = base_ci         (CallInfo* - first CallInfo / bottom of the call stack)
L + 0x70 = gt              (Table* - the _G global environment table)
```

---

## TValue (0x10 bytes)

Everything on the Lua stack is a `TValue`. The type tag at `+0x0c` tells you what the 8-byte value union at `+0x00` actually is - a pointer, a double, an int, whatever.

```cpp
TValue + 0x00 = value union  (8 bytes - interpret based on tt)
TValue + 0x08 = extra        (4 bytes - confirmed real field, purpose unresolved;
                               probably a hash cache or spare slot)
TValue + 0x0c = tt           (int - type tag, see Type Tags section)
```

**On `TValue+0x08`:** This is not padding. It shows up as a distinct field in the `LuaNode` layout, sitting between `key.value` and `key.tt`. No function analyzed so far explicitly reads or writes it for plain stack TValues, so what it does in that context is still open. It's there though.

---

## TString

Interned string object. The character data lives inline right after the header - no separate heap allocation for the string contents.

```cpp
TString + 0x00 = tt      (byte - always LUA_TSTRING = 0x06)
TString + 0x01 = memcat  (byte - memory category tag for the allocator)
TString + 0x02 = marked  (byte - GC flags; bit 3 = |0x08 = pinned, never collected)
TString + 0x03 = extra   (byte)
TString + 0x08 = next    (GCObject* - next string in the interning hash chain)
TString + 0x10 = hash    (uint - precomputed hash, used for table key lookup)
TString + 0x14 = len     (uint - byte length, not counting the null terminator)
TString + 0x18 = data[]  (inline chars - null terminated)
```

**Permanently pinned strings** (both get `marked |= 8` in `luaE_newstate`):
- `"not enough memory"` - for when the allocator gives up
- `"error in error handling"` - for when things go spectacularly wrong

---

## CallInfo (0x28 bytes)

One `CallInfo` per active call frame. Stored in a pre-allocated array between `base_ci` and `end_ci`, grown via `luaD_growCI` when needed.

> ⚠️ **A lot of public references get this wrong.** Many list `func` at `ci+0x00`. That is incorrect for this binary. The layout below was read directly from `luaD_precall`'s store sequence into a freshly allocated `CallInfo` - there's no inference here.

```cpp
ci + 0x00 = top      (StkId - frame ceiling: func + numparams * 0x10)   [HIGH]
ci + 0x08 = savedpc  (Instruction* - 0 on C call, Proto->code on Lua)   [HIGH]
ci + 0x10 = base     (StkId - first arg / frame base = func + 0x10)     [HIGH]
ci + 0x18 = func     (StkId - pointer to the function TValue on stack)  [HIGH]
ci + 0x20 = nresults (int - expected result count; -1 = LUA_MULTRET)    [HIGH]
ci + 0x24 = flags    (int - bit 0: CIST_YIELDABLE set on resume,
                             bit 2: has upvalues set by precall)         [MED]
```

---

## Closure (partial)

Lua closures and C closures share the same header. `isC` at `+0x05` is the dividing line.

```cpp
Closure + 0x00 = tt         (byte - 0x08 = LUA_TFUNCTION)
Closure + 0x01 = memcat     (byte)
Closure + 0x02 = marked     (byte - GC flags)
Closure + 0x03 = numparams  (byte - used by precall for stack sizing)   [MED - could be nupvalues]
Closure + 0x04 = unknown    (byte)
Closure + 0x05 = isC        (byte - 0 = Lua closure, nonzero = C)      [HIGH]
Closure + 0x18 = Proto*     (Lua) / lua_CFunction (C)                   [HIGH]
Closure + 0x28 = cont*      (C closures only - continuation fn pointer,
                              NULL = this function cannot yield)         [HIGH]
```

The `cont` field at `+0x28` is how coroutine-aware C functions like `pcall` hand control back after a yield. If it's null, the function is not yield-safe and the VM knows it.

---

## Proto (partial)

The compiled function prototype. All closures from the same function body share one `Proto`. It holds the bytecode, constants, upvalue descriptors, and debug info.

```cpp
Proto + 0x04 = byte         - is_vararg or numparams (if 0: L->top = ci->top)  [MED]
Proto + 0x05 = byte         - maxstacksize, used for the nil-fill loop in precall  [HIGH]
Proto + 0x08 = ptr          - upvalue-related (0 = skip upvalue init)  [LOW]
Proto + 0x10 = ptr          - upvalue-related (0 = skip upvalue init)  [LOW]
Proto + 0x40 = Instruction* - code array, copied into ci->savedpc on call  [HIGH]
```

`luaV_execute` is the next target for the rest of Proto - constants array, nested protos, line info, all of it.

---

## Table (partial)

Luau tables are a hybrid array/hash structure. Small integer keys (1..n) go into a flat array part for speed; everything else lands in the hash part.

```cpp
Table + 0x04 = lsizenode  (byte - log2 of the hash node array size)  [HIGH]
Table + 0x20 = node       (LuaNode* - hash part)                      [HIGH]
Table + 0x28 = metatable  (Table* - NULL if none)                     [HIGH]
```

Still missing: the array part pointer, `sizearray`, flags, and the GCObject common header. `luaH_new` (0x03f736b8) is the next stop for those.

---

## LuaNode (0x20 bytes)

Each slot in the table hash part is a `LuaNode` - a value TValue and a key TValue packed into 32 bytes. The key's type tag and the next-chain offset are packed together into a single `uint32` at the end to save space.

```cpp
// Value:
node + 0x00 = val.value  (8 bytes)
node + 0x08 = val.extra  (4 bytes - TValue+0x08 field)
node + 0x0c = val.tt     (int - value type tag)

// Key (packed):
node + 0x10 = key.value  (8 bytes - for strings, this is the TString*)
node + 0x18 = key.extra  (4 bytes - TValue+0x08 field)
node + 0x1c = packed     (uint32:
                           bits  [3:0] = key type tag
                           bits [31:4] = next-node offset, signed, in LuaNode units)
```

**Hash lookup** (from `luaH_getstr`):
```
bucket = TString->hash & ((1 << Table->lsizenode) - 1)
node   = Table->node + bucket
```
Chain ends when `node+0x1c < 0x10` - next is 0 and the key is nil, meaning you've hit an empty slot or the end of the chain.

---

## Userdata (partial)

```cpp
Userdata + 0x08 = metatable*  (Table* - NULL if none)  [HIGH]
```

---

## global_State (g)

Shared across all threads. Access it via `L->l_G`.

```cpp
g + 0x00  = nextgc      (size_t - GC threshold; set to totalbytes * 4 on init)
g + 0x08  = totalbytes  (size_t - total bytes currently allocated)

// Written by the outer lua_newstate before luaE_newstate runs.
// lua_newstate itself hasn't been found yet so this gap is still dark.
g + 0x10  → g + 0x37   = UNKNOWN  (mainthread*, frealloc fn*, userdata ptr, panic fn*)

g + 0x38  = strt.size   (uint - string interning table bucket count)
g + 0x40  = strt.hash   (TString** - string interning bucket array)

// GC gray lists, weak tables, etc. Needs GC function analysis to fill in.
g + 0x48  → g + 0x31f  = UNKNOWN  (rootgc, gray, grayagain, weak, and friends)

// Metamethod name strings - 21 entries, 8 bytes each:
g + 0x320 = tmname[0]   "__index"
g + 0x328 = tmname[1]   "__newindex"
g + 0x330 = tmname[2]   "__mode"
g + 0x338 = tmname[3]   "__namecall"
g + 0x340 = tmname[4]   "__call"
g + 0x348 = tmname[5]   "__iter"
g + 0x350 = tmname[6]   "__len"
g + 0x358 = tmname[7]   "__eq"
g + 0x360 = tmname[8]   "__add"
g + 0x368 = tmname[9]   "__sub"
g + 0x370 = tmname[10]  "__mul"
g + 0x378 = tmname[11]  "__div"
g + 0x380 = tmname[12]  "__idiv"
g + 0x388 = tmname[13]  "__mod"
g + 0x390 = tmname[14]  "__pow"
g + 0x398 = tmname[15]  "__unm"
g + 0x3a0 = tmname[16]  "__lt"
g + 0x3a8 = tmname[17]  "__le"
g + 0x3b0 = tmname[18]  "__concat"
g + 0x3b8 = tmname[19]  "__type"
g + 0x3c0 = tmname[20]  "__metatable"

// Type name strings - 12 entries, 8 bytes each:
g + 0x3c8 = ttname[0]   "nil"
g + 0x3d0 = ttname[1]   "boolean"
g + 0x3d8 = ttname[2]   "userdata"   (light)
g + 0x3e0 = ttname[3]   "number"
g + 0x3e8 = ttname[4]   "integer"
g + 0x3f0 = ttname[5]   "vector"
g + 0x3f8 = ttname[6]   "string"
g + 0x400 = ttname[7]   "table"
g + 0x408 = ttname[8]   "function"
g + 0x410 = ttname[9]   "userdata"   (heavy)
g + 0x418 = ttname[10]  "thread"
g + 0x420 = ttname[11]  "buffer"

// Per-type metatables - 12 entries, 8 bytes each (NULL = not set):
g + 0x428 = mt[0]   LUA_TNIL
g + 0x430 = mt[1]   LUA_TBOOLEAN
g + 0x438 = mt[2]   LUA_TLIGHTUSERDATA
g + 0x440 = mt[3]   LUA_TNUMBER
g + 0x448 = mt[4]   LUA_TINTEGER
g + 0x450 = mt[5]   LUA_TVECTOR
g + 0x458 = mt[6]   LUA_TSTRING      // almost always non-null in Roblox (string library)
g + 0x460 = mt[7]   LUA_TTABLE       // fallback only - tables have their own mt field
g + 0x468 = mt[8]   LUA_TFUNCTION
g + 0x470 = mt[9]   LUA_TUSERDATA    // fallback only - userdata has its own mt field
g + 0x478 = mt[10]  LUA_TTHREAD
g + 0x480 = mt[11]  LUA_TBUFFER
// mt[] ends at g+0x488

g + 0x488 → g + 0x497 = UNKNOWN  (16 bytes between mt[] and the registry, still unclear)

// The Lua registry, stored inline as a TValue:
g + 0x498 = registry.value  (Table*)
g + 0x4a4 = registry.tt     (int - always 7 = LUA_TTABLE)
```

**How `luaT_gettmbyobj` uses `mt[]`:** For TABLE and USERDATA it checks the per-object metatable directly (Table+0x28, Userdata+0x08). For everything else it falls back to `g->mt[tt]`. So `g->mt[7]` and `g->mt[9]` only get hit if an object has no metatable of its own.

---

## Error / Exception Mechanism

Standard Lua uses `setjmp`/`longjmp` for error handling. Roblox's iOS build does not - it uses **C++ exceptions** instead, which play nicer with Objective-C and Swift frames on ARM64.

```cpp
// class lua_exception : public std::exception
// ABI: __cxxabiv1::__si_class_type_info (single inheritance, global namespace)

exception_object + 0x00 = vtable*     → DAT_05dadd88
exception_object + 0x08 = lua_State*  (the thread that threw)
exception_object + 0x10 = int         (LUA_ERR* error code)

05dadd60   = lua_exception typeinfo object
04ebd59c   = "13lua_exception"  (Itanium-mangled; demangles to just: lua_exception)
DAT_05dadd88 = lua_exception vtable
```

`luaD_throw` (0x03f66e08) allocates via `__cxa_allocate_exception(0x18)`, fills the three fields, and calls `__cxa_throw`. Catch sites in `lua_resume` and `luaD_pcall` use normal `try/catch` blocks. There are no `setjmp` error jump buffers anywhere in `lua_State` - if you're looking for one, stop looking.

---

## Type Tags

```cpp
0x00 = LUA_TNIL
0x01 = LUA_TBOOLEAN
0x02 = LUA_TLIGHTUSERDATA
0x03 = LUA_TNUMBER
0x04 = LUA_TINTEGER    (Luau-specific - a distinct integer type, not just a float)
0x05 = LUA_TVECTOR     (Luau-specific - 3-component float vector)
0x06 = LUA_TSTRING
0x07 = LUA_TTABLE
0x08 = LUA_TFUNCTION
0x09 = LUA_TUSERDATA
0x0a = LUA_TTHREAD
0x0b = LUA_TBUFFER     (Luau-specific - typed byte buffer)
```

---

## Error Codes

```cpp
0x02 = LUA_ERRRUN   runtime error
0x04 = LUA_ERRMEM   memory allocation failure
0x05 = LUA_ERRERR   error while handling an error (yes, that's a thing)
```

Thread status values (`L+0x03`):
```cpp
0x00 = OK / suspended
0x01 = LUA_YIELD
0x06 = LUA_BREAK    (Luau-specific)
0x7f = running      (if you see this, the thread is already going - don't resume it)
```

---

## Functions

### VM Core

```
0x03f7e9f8 = luaD_precall         (lua_State*, StkId func, int nresults)
                                   Sets up a new call frame. Pushes a CallInfo,
                                   initializes the frame, then either runs the C
                                   function directly (returns 1) or returns 0 so the
                                   caller knows to run luaV_execute.

0x03f7ebcc = luaD_poscall         (lua_State*, StkId firstResult)
                                   Tears down a call frame. Copies results back,
                                   pops the CallInfo, restores L->base and L->top.

0x03f7747c = luaV_execute         (lua_State*)
                                   The bytecode interpreter. The big one.

0x03f67d40 = resume_execute_loop  (lua_State*)
                                   Post-resume execution driver. Runs luaV_execute
                                   for Lua frames, calls C continuations for C frames,
                                   until the coroutine yields or finishes.
                                   (Internal name - actual symbol unknown.)
```

### Thread / State

```
0x03f675c8 = lua_resume           (lua_State* L, StkId func)
0x03f6523c = lua_closethread
0x03f6f478 = luaD_initstack       (lua_State* L, lua_State* mainthread)
0x03f6fac4 = luaE_newstate        (lua_State*)
                                   Initializes a freshly allocated state: creates _G
                                   and the registry, interns metamethod strings, pins
                                   the two permanent error strings, sets GC threshold.
                                   The outer lua_newstate that allocates global_State
                                   and writes frealloc/ud/panic hasn't been found yet.
```

### Call Stack

```
0x03f670a8 = luaD_growCI
0x03f67010 = luaD_reallocCI
0x03f66e4c = luaD_growstack        [MED - called in precall on stack overflow]
0x03f67454 = luaD_seterrorobj
0x03f66e08 = luaD_throw            C++ exception throw, not longjmp - see above
```

### Strings

```
0x03f6ff1c = luaS_newlstr         (lua_State*, const char* s, size_t len)
0x03f6fcc0 = luaS_resize          (lua_State*, int newsize)
```

### Tables

```
0x03f736b8 = luaH_new             (lua_State*, int narray, int nhash) -> Table*
                                   Next analysis target - will fill in the rest
                                   of the Table layout.

0x03f73a8c = luaH_getstr          (Table*, TString*) -> TValue*
                                   Raw hash lookup by string key. Returns a pointer
                                   to the static nil sentinel on a miss -
                                   do not write through that pointer.
```

### Metamethods / Type System

```
0x03f75e60 = luaT_init            Interns all metamethod names into g->tmname[] at startup.

0x03f75f6c = luaT_gettmbyobj      (lua_State*, TValue* obj, uint event) -> TValue*
                                   Metamethod lookup. Checks the object's own metatable
                                   for TABLE and USERDATA; uses g->mt[tt] for everything else.
```

### Error Reporting

```
0x03f660f0 = luaG_runerror        (lua_State*, const char* fmt, ...) - does not return
0x03f660c0 = luaG_typeerror       Calls luaO_tostring to get the type name, then hits
                                   luaG_runerror with "attempt to %s a %s value".
0x03f662b4 = luaG_indexerror
0x03f81e98 = tryfuncTM            The __call metamethod handler inside luaD_precall.
                                   When a value isn't a function, this runs first -
                                   looks up __call (event 4) via luaT_gettmbyobj,
                                   shuffles the stack to insert the metamethod if found,
                                   and throws a type error if not.
```

### Misc

```
0x03f7607c = luaO_tostring
0x03f76a08 = luaopen_vector       The vector library initializer.
                                   NOTE: early on this looked promising because it showed
                                   up in __index xrefs. It's not a metamethod lookup -
                                   it just registers an __index handler. Don't chase
                                   xref counts blindly without checking what the function
                                   actually does with the string.
0x03f77254 = vector __index handler
```

### C API (recovered from luaopen_vector)

```
0x03f5e5fc = luaL_register        (lua_State*, name, luaL_Reg[])
0x03f5bae4 = lua_pushvector       (float x, float y, float z, lua_State*)
                                   L is the last argument here - the three floats
                                   consume the first float registers on ARM64.
0x03f5c724 = lua_setfield         (lua_State*, int idx, const char* name)
0x03f5c300 = lua_createtable / luaL_newlib
0x03f5bcc4 = lua_pushcfunction / lua_pushcclosure
0x03f5c38c = lua_rawseti or lua_setfield variant
0x03f5aa94 = stack op (settop/pop variant)
0x03f5cbac = stack op (settop/pop variant)
0x03f5a728 = stack op (settop/pop variant)
```

---

## Static Data

```
DAT_04ebdbc0 = Static nil TValue sentinel. Returned by luaH_getstr and luaT_gettmbyobj
               on a miss. Don't write to this address.

DAT_05dae828 = Vector library luaL_Reg[] function table.

DAT_05fabec8 = Global feature flag byte. Checked at the top of lua_resume and in the
               resume loop. When it's 0x01, coroutine-extended behavior is enabled.
               Exactly what it gates is still being looked into.
```

---

## What's Left

The map is solid but there are still gaps worth filling.

| Target | Why it matters |
|---|---|
| `luaH_new` (0x03f736b8) | Rest of Table layout: array*, sizearray, flags, GCObject header |
| Outer `lua_newstate` (xref callers of 0x03f6fac4) | Closes `g+0x10`→`g+0x37`: mainthread, frealloc, ud, panic |
| `luaV_execute` (0x03f7747c) | Full Proto layout + all opcode handlers - big function, worth it |
| `luaS_newlstr` (0x03f6ff1c) | Might finally explain what `TValue+0x08` is for |
| GC functions (`luaC_step` etc.) | Closes `g+0x48`→`g+0x31f` - the whole GC list block |
| `g+0x488`→`g+0x497` | 16 mystery bytes between `mt[]` and the registry |
| Closure+0x03 | Confirm numparams vs nupvalues |
| Proto+0x04 | Confirm is_vararg vs numparams |

---

*Offsets are specific to version 2.720.1164. Verify before putting these into anything. Corrections welcome.*
