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

**1. String cross-references**  
Ghidra lets you find every piece of code that touches a string literal. Strings like `"attempt to call"`, `"__index"`, `"not enough memory"`, and `"13lua_exception"` are anchor points. Find the string, find the function that uses it, read what it does to nearby memory, and you've got struct offsets basically for free.

**2. Known-value anchors in global_State**  
The `tmname[]` and `ttname[]` arrays are a gift. They hold interned strings for every metamethod (`"__index"`, `"__call"`, etc.) and type name (`"nil"`, `"string"`, etc.) in a fixed order defined by the Luau source. Find any one entry and you've pinned the entire array - and by extension, the base address of `global_State`.

**3. lua_newstate / luaE_newstate as free layout maps**  
The state initializers write to basically every important field at startup. `lua_newstate` gives you the allocator, userdata, panic handler, mainthread pointer, GC parameters, and the combined allocation size. `luaE_newstate` fills in `_G`, the registry, metamethod strings, and the pinned error strings. Just read the store sequences.

**4. Store-sequence analysis**  
When a known function allocates a struct and immediately fills it in (like `luaD_precall` pushing a new `CallInfo`), the stores happen in field order. Reading them gives you the layout directly. This is also how we caught that a lot of public references have `CallInfo` wrong - `func` is not at `ci+0x00` in this binary.

**5. C++ exception type_info**  
Roblox's iOS build throws C++ exceptions for Lua errors instead of using `longjmp`. The `__cxa_throw` call passes a `std::type_info*`, which contains an Itanium-mangled class name string. Follow the pointer, read the string, and you get the class name and layout handed to you.

**Confidence levels:**
- `[HIGH]` - seen directly in the decompiler, no guessing involved
- `[MED]` - inferred from context, consistent with Luau source patterns
- `[LOW]` - the field exists, but what it actually means is a best guess

---

## Combined Allocation Layout

`lua_newstate` allocates **one contiguous block of 0x4710 bytes** for both the main thread state and the global state. They are not separate heap allocations.

```
[base + 0x0000] = lua_State    (main thread)
[base + 0x0080] = global_State
[base + 0x4710] = end of allocation
```

`L->l_G` (at L+0x18) is set to `base + 0x80`, confirming the split. Coroutines have their own separately allocated `lua_State` but share the same `global_State` via their own `l_G` pointer.

---

## lua_State (L)

```cpp
L + 0x00 = tt          (byte - 0x0a = LUA_TTHREAD; lua_State is a GC object)
L + 0x01 = memcat      (byte - GC object memory category, 0 for main thread)
L + 0x02 = marked      (byte - GC flags; 9 = 0b00001001 on main thread:
                                bit 0 = current GC color,
                                bit 3 = fixed/pinned, not in GC sweep list)
L + 0x03 = status      (byte)
              0x00 = suspended / OK
              0x01 = LUA_YIELD
              0x06 = LUA_BREAK      (Luau-specific)
              0x7f = running
L + 0x04 = active_memcat  (byte - memcat used for new objects allocated on
                            behalf of this thread; distinct from L+0x01)
L + 0x08 = stacksize   (int)
L + 0x0c = size_ci     (int - 8 on init)
L + 0x18 = l_G         (global_State*)
L + 0x20 = stack_last  (StkId)
L + 0x28 = top         (StkId)
L + 0x30 = stack       (StkId - allocation base)
L + 0x38 = ci          (CallInfo*)
L + 0x40 = base        (StkId - current frame base)
L + 0x58 = end_ci      (CallInfo*)
L + 0x60 = base_ci     (CallInfo*)
L + 0x70 = gt          (Table* - _G)
L + 0x78 = ???         (pointer - NULL on init)
```

**Note:** Earlier notes listed L+0x01 as "tt/type". That was wrong. Like all Luau GC objects, `tt` is at +0x00. L+0x01 is `memcat` (the GC object's own memory category). L+0x04 is the *active* memcat used when allocating new objects on this thread's behalf — they are different things.

---

## TValue (0x10 bytes)

```cpp
TValue + 0x00 = value union  (8 bytes)
TValue + 0x08 = extra        (4 bytes - confirmed real field, purpose still unknown)
TValue + 0x0c = tt           (int - type tag)
```

`TValue+0x08` is not padding — it appears as a distinct field in `LuaNode` key layout. No analyzed function reads or writes it for plain stack TValues yet.

---

## TString

```cpp
TString + 0x00 = tt      (byte - 0x06 = LUA_TSTRING)
TString + 0x01 = memcat  (byte)
TString + 0x02 = marked  (byte - bit 3 = pinned)
TString + 0x03 = extra   (byte)
TString + 0x04 = atom    (int16 - fast-comparison ID; -1 = not yet assigned)
TString + 0x06 = ???     (int16 - initialized to 0x8000)
TString + 0x08 = next    (TString* - next in interning hash chain)
TString + 0x10 = hash    (uint)
TString + 0x14 = len     (uint)
TString + 0x18 = data[]  (inline chars, null terminated)

sizeof(TString) = 0x18 + len + 1
```

Permanently pinned strings (marked |= 8 in luaE_newstate):
- `"not enough memory"`
- `"error in error handling"`

---

## CallInfo (0x28 bytes)

> ⚠️ Many public references list `func` at `ci+0x00`. That is wrong for this binary. Layout read directly from `luaD_precall`'s store sequence.

```cpp
ci + 0x00 = top      (StkId)                                             [HIGH]
ci + 0x08 = savedpc  (Instruction* - 0 on C call, Proto->code on Lua)   [HIGH]
ci + 0x10 = base     (StkId)                                             [HIGH]
ci + 0x18 = func     (StkId - ptr to function TValue on stack)           [HIGH]
ci + 0x20 = nresults (int - -1 = LUA_MULTRET)                            [HIGH]
ci + 0x24 = flags    (int - bit 0: CIST_YIELDABLE, bit 2: has upvalues)  [MED]
```

---

## Closure (partial)

```cpp
Closure + 0x00 = tt         (byte - 0x08 = LUA_TFUNCTION)
Closure + 0x01 = memcat     (byte)
Closure + 0x02 = marked     (byte)
Closure + 0x03 = numparams  (byte)                    [MED - could be nupvalues]
Closure + 0x04 = unknown    (byte)
Closure + 0x05 = isC        (byte - 0 = Lua, nonzero = C)               [HIGH]
Closure + 0x18 = Proto* / lua_CFunction                                  [HIGH]
Closure + 0x28 = cont*      (C only - continuation fn; NULL = not yieldable) [HIGH]
```

---

## Proto (partial)

```cpp
Proto + 0x04 = byte  - is_vararg or numparams (if 0: L->top = ci->top)  [MED]
Proto + 0x05 = byte  - maxstacksize                                       [HIGH]
Proto + 0x08 = ptr   - upvalue-related (0 = skip)                        [LOW]
Proto + 0x10 = ptr   - upvalue-related (0 = skip)                        [LOW]
Proto + 0x40 = Instruction* - code array                                  [HIGH]
```

---

## Table (complete)

```cpp
sizeof(Table) = 0x30

Table + 0x00 = tt         (byte - 0x07 = LUA_TTABLE)
Table + 0x01 = memcat     (byte)
Table + 0x02 = marked     (byte - GC color = g->gccolor & 3 on creation)
Table + 0x03 = ???        (byte - zeroed on init)
Table + 0x04 = lsizenode  (byte - log2 hash node count; 0 = 1 dummy slot) [HIGH]
Table + 0x05 = flags      (byte - 0xff on init; 1<<p = metamethod p absent) [HIGH]
Table + 0x06 = ???        (8 bytes zeroed - likely sizearray + padding)
Table + 0x0e = ???        (2 bytes zeroed)
Table + 0x10 = array*     (TValue* - array part; NULL on empty table)     [MED]
Table + 0x18 = lastfree   (LuaNode* - NULL on empty table)
Table + 0x20 = node       (LuaNode* - &DAT_04ebdcd0 dummy on empty table) [HIGH]
Table + 0x28 = metatable  (Table* - NULL if none)                          [HIGH]
```

---

## LuaNode (0x20 bytes)

```cpp
node + 0x00 = val.value  (8 bytes)
node + 0x08 = val.extra  (4 bytes)
node + 0x0c = val.tt     (int)
node + 0x10 = key.value  (8 bytes)
node + 0x18 = key.extra  (4 bytes)
node + 0x1c = packed uint32:
                bits  [3:0] = key.tt
                bits [31:4] = next offset (signed, in LuaNode units)
```

Hash lookup: `bucket = TString->hash & ((1 << lsizenode) - 1)`.  
Chain end: `node+0x1c < 0x10` (next=0 and key=nil).

---

## Userdata (partial)

```cpp
Userdata + 0x08 = metatable*  (Table*)  [HIGH]
```

---

## global_State (g)

Access via `L->l_G`. Starts at `L+0x80` in the main-thread allocation block.

```cpp
g + 0x00  = nextgc      (size_t - GC threshold; set to totalbytes*4 by luaE_newstate)
g + 0x08  = totalbytes  (size_t - 0x4710 on init = size of combined LG block)

// Written by lua_newstate:
g + 0x10  = frealloc    (lua_Alloc - allocator function pointer)
g + 0x18  = ud          (void* - allocator userdata)
g + 0x20  = panic       (lua_CFunction - unprotected error handler; NULL on init)
g + 0x28  = ???         (8 bytes, zeroed)
g + 0x30  = ???         (8 bytes, zeroed)

g + 0x38  = strt.size   (uint - bucket count; 0 on init, 0x20 after luaS_resize)
g + 0x3c  = strt.nuse   (uint - interned string count)
g + 0x40  = strt.hash   (TString**)

// GC parameters (written by lua_newstate):
g + 0x48  = gcpause     (uint32 - 200 on init)
g + 0x4c  = gcstepmul   (uint32 - 200 on init)
g + 0x50  = ???         (uint32 - 0x400 on init; possibly gcstepsize)
g + 0x54  = gccolor     (byte - 9 on init; bits[1:0] = mark color, bit[3] = GC flag)
g + 0x55  = ???         (byte - zeroed)

// GC lists (partially mapped from lua_newstate init):
g + 0x58  = ???         (GC list anchor - g+0x68 and g+0x70 both point here on init)
g + 0x68  = ???         (pointer - initialized to &g+0x58)
g + 0x70  = ???         (pointer - initialized to &g+0x58)

// g+0x48 through g+0x31f still partially unknown
// (rootgc, gray, grayagain, weak tables etc. - needs luaC_step analysis)

g + 0x310 = mainthread  (lua_State*)
g + 0x318 = ???         (8 bytes between mainthread and tmname[0])

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

// Per-type metatables - 12 entries, 8 bytes each:
g + 0x428 = mt[0]   LUA_TNIL
g + 0x430 = mt[1]   LUA_TBOOLEAN
g + 0x438 = mt[2]   LUA_TLIGHTUSERDATA
g + 0x440 = mt[3]   LUA_TNUMBER
g + 0x448 = mt[4]   LUA_TINTEGER
g + 0x450 = mt[5]   LUA_TVECTOR
g + 0x458 = mt[6]   LUA_TSTRING      (almost always non-null in Roblox)
g + 0x460 = mt[7]   LUA_TTABLE       (fallback - tables use own metatable field)
g + 0x468 = mt[8]   LUA_TFUNCTION
g + 0x470 = mt[9]   LUA_TUSERDATA    (fallback - userdata uses own metatable field)
g + 0x478 = mt[10]  LUA_TTHREAD
g + 0x480 = mt[11]  LUA_TBUFFER

g + 0x488 = ???     (4 bytes, zeroed)
g + 0x490 = ???     (8 bytes, zeroed)
g + 0x494 = ???     (4 bytes, zeroed)

// Registry (inline TValue):
g + 0x498 = registry.value  (Table*)
g + 0x4a4 = registry.tt     (int - 7 = LUA_TTABLE)

g + 0x4a8 = ???     (uint32 - 0x70000000 on init; possibly a memory cap or
                     Roblox-specific sandbox limit)
```

---

## Error / Exception Mechanism

Roblox's iOS build uses **C++ exceptions**, not `setjmp`/`longjmp`.

```cpp
// class lua_exception : public std::exception

exception_object + 0x00 = vtable*     → DAT_05dadd88
exception_object + 0x08 = lua_State*
exception_object + 0x10 = int         (LUA_ERR* code)

05dadd60     = lua_exception typeinfo
04ebd59c     = "13lua_exception" (Itanium mangled)
DAT_05dadd88 = lua_exception vtable
```

`luaD_throw` allocates via `__cxa_allocate_exception(0x18)` and calls `__cxa_throw`. No `setjmp` buffers exist in `lua_State`.

---

## Type Tags

```cpp
0x00 = LUA_TNIL
0x01 = LUA_TBOOLEAN
0x02 = LUA_TLIGHTUSERDATA
0x03 = LUA_TNUMBER
0x04 = LUA_TINTEGER    (Luau-specific)
0x05 = LUA_TVECTOR     (Luau-specific)
0x06 = LUA_TSTRING
0x07 = LUA_TTABLE
0x08 = LUA_TFUNCTION
0x09 = LUA_TUSERDATA
0x0a = LUA_TTHREAD
0x0b = LUA_TBUFFER     (Luau-specific)
```

---

## Error Codes

```cpp
0x02 = LUA_ERRRUN
0x04 = LUA_ERRMEM
0x05 = LUA_ERRERR
```

Thread status (`L+0x03`):
```cpp
0x00 = OK / suspended
0x01 = LUA_YIELD
0x06 = LUA_BREAK    (Luau-specific)
0x7f = running
```

---

## Functions

### VM Core
```
0x03f7e9f8 = luaD_precall
0x03f7ebcc = luaD_poscall
0x03f67d40 = resume_execute_loop  (internal name unknown)
```

### Thread / State
```
0x03f6f7c8 = lua_newstate         (lua_Alloc f, void* ud) -> lua_State*
                                   Allocates 0x4710 byte combined block.
                                   Writes frealloc/ud/panic/gcpause(200)/
                                   gcstepmul(200)/mainthread into global_State.
                                   Calls luaD_rawrunprotected(L, luaE_newstate).
                                   Returns NULL on failure.

0x03f675c8 = lua_resume
0x03f6523c = lua_closethread
0x03f6f478 = luaD_initstack
0x03f6fac4 = luaE_newstate        (called under protection by lua_newstate)
0x03f66d48 = luaD_rawrunprotected (lua_State*, lua_CFunction, void*)
0x03f6fb88 = lua_freestate        (cleanup on init failure)
```

### Call Stack
```
0x03f670a8 = luaD_growCI
0x03f67010 = luaD_reallocCI
0x03f66e4c = luaD_growstack        [MED]
0x03f67454 = luaD_seterrorobj
0x03f66e08 = luaD_throw
```

### Memory
```
0x03f6d7e4 = luaM_newobject       (lua_State*, size_t, memcat) -> void*
0x03f6d648 = luaG_toobig          (no return - string > 0x40000000 bytes)
```

### Strings
```
0x03f6fc34 = luaS_hash            (const char*, size_t) -> uint
0x03f6ff1c = luaS_newlstr         (lua_State*, const char*, size_t) -> TString*
0x03f6fcc0 = luaS_resize
```

### Tables
```
0x03f736b8 = luaH_new             (lua_State*, int narray, int nhash) -> Table*
0x03f7376c = luaH_resizearray
0x03f7387c = luaH_resizehash
0x03f73a8c = luaH_getstr          (Table*, TString*) -> TValue*
                                   Returns &DAT_04ebdbc0 (nil sentinel) on miss.
```

### Metamethods / Type System
```
0x03f75e60 = luaT_init
0x03f75f6c = luaT_gettmbyobj      (lua_State*, TValue*, uint event) -> TValue*
```

### Error Reporting
```
0x03f660f0 = luaG_runerror        (no return)
0x03f660c0 = luaG_typeerror
0x03f662b4 = luaG_indexerror
0x03f81e98 = tryfuncTM            (__call metamethod handler in luaD_precall)
```

### Misc
```
0x03f7607c = luaO_tostring
0x03f76a08 = luaopen_vector
0x03f77254 = vector __index handler
```

### C API
```
0x03f5e5fc = luaL_register
0x03f5bae4 = lua_pushvector       (float x, float y, float z, lua_State*)
                                   NOTE: L is last arg - floats consume ARM64
                                   float registers first.
0x03f5c724 = lua_setfield
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
DAT_04ebdbc0 = nil TValue sentinel  (luaH_getstr / luaT_gettmbyobj miss - do not write)
DAT_04ebdcd0 = dummy LuaNode        (Table->node for empty tables - do not write)
DAT_05dae828 = vector lib luaL_Reg[]
DAT_05dadd88 = lua_exception vtable
DAT_05fabec8 = global feature flag byte (0x01 = coroutine-extended behavior enabled)
```

---

## What's Left

| Target | Why it matters |
|---|---|
| `luaV_execute` (0x03f7747c) | Full Proto layout + opcode handlers |
| GC functions (`luaC_step` etc.) | Closes `g+0x48`→`g+0x31f`; pins `g+0x58/0x68/0x70` |
| `TValue+0x08` | Still unknown - try a table set path or luaV_execute |
| `g+0x488`→`g+0x497` | 12 bytes between `mt[]` and registry |
| `g+0x4a8` | 0x70000000 - memory cap? Roblox sandbox limit? |
| `g+0x28`, `g+0x30`, `g+0x318` | Zeroed unknowns from lua_newstate |
| `Closure+0x03` | numparams vs nupvalues |
| `Proto+0x04` | is_vararg vs numparams |
| `Table+0x06`→`+0x17` | sizearray, array* |
| `TString+0x06` | 0x8000 sentinel meaning |
| `L+0x78` | NULL on init, unknown purpose |

---

*Offsets are specific to version 2.720.1164. Verify before use. Corrections welcome.*
