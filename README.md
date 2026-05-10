> **Version:** 2.720.1164  
> **Binary:** Roblox iOS (ARM64)  
> **Tool:** Ghidra + Jython scripting console  
> **Download:** https://decrypt.day/app/id431946152  
> Also Forgot Credit me estacc123-ux and 60ve(aka love)
> 
> This took a while. What follows is a map of the Luau VM internals from the Roblox
> iOS binary - structs, offsets, functions, the works. This is **Luau** (Roblox's fork
> of Lua 5.1), not standard Lua, so don't go copying offsets from some random Lua 5.3
> repo and wondering why everything is on fire. Android offsets coming later, been busy.


also check out he funny: https://github.com/60ve/roblox-ios-offsets


### **NOTE: iOS AC is disabled, and only luau and other dtcs that no one knows of are enabled**

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

**5. Jython scripting for bulk extraction**  
For things like the opcode dispatch table (256 entries) or scanning all interpreter instructions for a specific access pattern, Ghidra's Jython console is faster than clicking. Scripts in this doc can be re-run against updated binaries to spot changes quickly.

**6. C++ exception type_info**  
Roblox's iOS build throws C++ exceptions for Lua errors instead of using `longjmp`. The `__cxa_throw` call passes a `std::type_info*`, which contains an Itanium-mangled class name string. Follow the pointer, read the string, and you get the class name and layout handed to you.

**Confidence levels:**
- `[HIGH]` - seen directly in the decompiler or disassembly, no guessing involved
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
L + 0x00 = tt           (byte - 0x0a = LUA_TTHREAD; lua_State is a GC object)  [HIGH]
L + 0x01 = memcat       (byte - GC object memory category, 0 for main thread)   [HIGH]
L + 0x02 = marked       (byte - GC flags; 9 = 0b00001001 on main thread:
                                 bit 0 = current GC color,
                                 bit 3 = fixed/pinned, not in GC sweep list)     [HIGH]
L + 0x03 = status       (byte)                                                   [HIGH]
              0x00 = suspended / OK
              0x01 = LUA_YIELD
              0x06 = LUA_BREAK      (Luau-specific)
              0x7f = running
L + 0x04 = active_memcat (byte - memcat used for new objects allocated on
                           behalf of this thread; distinct from L+0x01)          [HIGH]
L + 0x06 = native_exec  (byte - 0x01 = NCG/native code path active)             [MED]
L + 0x08 = stacksize    (int)                                                    [HIGH]
L + 0x0c = size_ci      (int - 8 on init)                                       [HIGH]
L + 0x18 = l_G          (global_State*)                                         [HIGH]
L + 0x20 = stack_last   (StkId)                                                  [HIGH]
L + 0x28 = top          (StkId)                                                  [HIGH]
L + 0x30 = stack        (StkId - allocation base)                                [HIGH]
L + 0x38 = ci           (CallInfo*)                                              [HIGH]
L + 0x40 = base         (StkId - current frame base)                            [HIGH]
L + 0x58 = end_ci       (CallInfo*)                                              [HIGH]
L + 0x60 = base_ci      (CallInfo*)                                              [HIGH]
L + 0x70 = gt           (Table* - _G global environment)                        [HIGH]
L + 0x78 = ???          (pointer - NULL on init, purpose unknown)                [LOW]

sizeof(lua_State) = 0x80
```

> **Note on L+0x01 vs L+0x04:** Earlier public notes label L+0x01 as "tt/type". That is wrong.
> Like all Luau GC objects, `tt` is at +0x00. L+0x01 is `memcat` (the GC object's own memory
> category, used by the GC itself). L+0x04 is `active_memcat` - the category used when this
> thread allocates new objects. They are different fields with different purposes.

---

## TValue (0x10 bytes)

```cpp
TValue + 0x00 = value union  (8 bytes - pointer, double, or int depending on tt)   [HIGH]
                               For LUA_TVECTOR: +0x00=X (float), +0x04=Y (float)
TValue + 0x08 = vec_z        (float - vector Z component for LUA_TVECTOR;
                               confirmed via lua_pushvector store sequence;
                               unused/zero for all other types)                     [HIGH]
TValue + 0x0c = tt           (int - type tag, see Type Tags section)                [HIGH]
```

> **vec_z confirmed:** `lua_pushvector` (`FUN_03f5bae4`) stores X at `+0x00`, Y at `+0x04`,
> Z at `+0x08`, then `tt = 5` (LUA_TVECTOR) at `+0x0c`. The field was previously listed as
> `extra` with purpose unknown. It is the Z component, zero / ignored for non-vector TValues.

---

## TString

```cpp
TString + 0x00 = tt      (byte - 0x06 = LUA_TSTRING)    [HIGH]
TString + 0x01 = memcat  (byte)                          [HIGH]
TString + 0x02 = marked  (byte - bit 3 = pinned/fixed)  [HIGH]
TString + 0x03 = extra   (byte)                          [MED]
TString + 0x04 = atom    (int16 - fast-comparison ID; -1 / 0xFFFF = not yet assigned)  [HIGH]
TString + 0x06 = atom2   (int16 - second intern index; 0x8000 = not yet assigned)      [MED]
TString + 0x08 = next    (TString* - next in interning hash chain)                     [HIGH]
TString + 0x10 = hash    (uint)                                                        [HIGH]
TString + 0x14 = len     (uint)                                                        [HIGH]
TString + 0x18 = data[]  (inline chars, null terminated)                               [HIGH]

sizeof(TString) = 0x18 + len + 1
```

> **TString+0x04 / +0x06:** `luaS_newlstr` writes both fields in a single 4-byte store:
> `*(uint32*)(s + 4) = 0x8000FFFF` (little-endian: `0xFFFF` at +0x04, `0x8000` at +0x06).
> `atom = -1` (0xFFFF as int16) is the standard "not yet assigned" sentinel. `atom2 = 0x8000`
> (INT16_MIN) mirrors the same pattern - almost certainly a second intern index, possibly for
> `__namecall` or another Roblox-specific string table.

Permanently pinned strings (marked |= 8 in `luaE_newstate`):
- `"not enough memory"`
- `"error in error handling"`

---

## CallInfo (0x28 bytes)

> ⚠️ Many public references list `func` at `ci+0x00`. That is wrong for this binary.
> Layout read directly from `luaD_precall`'s store sequence into a freshly allocated `CallInfo`.

```cpp
ci + 0x00 = top      (StkId - frame ceiling: func + numparams*0x10)          [HIGH]
ci + 0x08 = savedpc  (Instruction* - 0 on C call, Proto->code on Lua call)   [HIGH]
ci + 0x10 = base     (StkId - first arg / frame base)                        [HIGH]
ci + 0x18 = func     (StkId - ptr to function TValue on stack)               [HIGH]
ci + 0x20 = nresults (int - expected return count; -1 = LUA_MULTRET)         [HIGH]
ci + 0x24 = flags    (int)                                                    [MED]
              bit 0 = CIST_YIELDABLE  (set during lua_resume)
              bit 2 = interrupt pending (checked at luaV_execute entry;
                      triggers g->cb.interrupt call before dispatch)
```

---

## Closure (partial)

```cpp
Closure + 0x00 = tt         (byte - 0x08 = LUA_TFUNCTION)                  [HIGH]
Closure + 0x01 = memcat     (byte)                                          [HIGH]
Closure + 0x02 = marked     (byte - GC flags)                               [HIGH]
Closure + 0x03 = numparams  (byte - parameter slot count; cached from Proto
                              for fast frame sizing in luaD_precall)        [HIGH]
Closure + 0x04 = unknown    (byte)                                          [LOW]
Closure + 0x05 = isC        (byte - 0 = Lua closure, nonzero = C closure)  [HIGH]
Closure + 0x08 = next       (GCObject* - GC linkage, inferred from TString pattern) [MED]
Closure + 0x10 = gclist     (GCObject* - GC gray list chain pointer;
                              confirmed via luaC_barrier prepend pattern)   [HIGH]
Closure + 0x18 = Proto*     (Lua closures) / lua_CFunction (C closures)    [HIGH]
Closure + 0x28 = cont*      (C closures only - continuation fn ptr;
                              NULL = not yieldable across this call)        [HIGH]
```

> **Closure+0x03 correction:** Earlier notes listed this as possibly `nupvalues`. It is
> `numparams`. `luaD_precall` reads it directly as the parameter slot count for frame
> sizing: `ci->top = base + numparams * sizeof(TValue)`. The binary caches numparams in
> the Closure instead of reading it from Proto at every call.
>
> **Closure+0x10:** Confirmed `gclist` via `luaC_barrier` - the barrier prepends GC objects
> to the gray list by writing `obj->gclist = g->gray` then `g->gray = obj`, with the gclist
> pointer at `obj+0x10` for all heap-allocated GC objects.

---

## Proto (partial)

```cpp
Proto + 0x04 = byte  - is_vararg    (if 0: L->top = ci->top on call,
                        capping the stack at numparams slots)            [HIGH]
Proto + 0x05 = byte  - maxstacksize (nil-fill loop bound in precall,
                        confirmed in multiple opcode handlers)           [HIGH]
Proto + 0x08 = ptr   - upvalue-related (0 = skip upvalue init)         [LOW]
Proto + 0x10 = ptr   - upvalue-related (0 = skip upvalue init)         [LOW]
Proto + 0x18 = ???   - passed to g->cb.interrupt as 2nd argument       [MED]
Proto + 0x38 = k     (TValue* - constants array)                       [HIGH]
Proto + 0x40 = code  (Instruction* - bytecode array, stored into
                      ci->savedpc at call time)                         [HIGH]

// Gap Proto+0x20 through +0x37 still unknown:
// likely contains: sizek, sizecode, sizelineinfo, nups, p (nested protos ptr), etc.
```

> **Proto+0x04 confirmed:** `luaD_precall` branches on `pcVar9[4] == 0` (byte at Proto+0x04).
> When zero (non-vararg), it executes `L->top = ci->top`, capping the stack to exactly
> `numparams` slots. This is precisely the `is_vararg` branch documented in the Luau source.
>
> **Proto+0x05 conflict resolved:** An earlier session labeled Proto+0x05 as `numparams`. It is
> `maxstacksize`. Confirmed by two separate paths: the nil-fill loop in `luaD_precall`
> (which uses it as a slot count) and direct reads in multiple opcode handlers immediately
> after loading Proto*.

---

## Table (0x30 bytes)

```cpp
Table + 0x00 = tt         (byte - 0x07 = LUA_TTABLE)                      [HIGH]
Table + 0x01 = memcat     (byte)                                           [HIGH]
Table + 0x02 = marked     (byte - GC color = g->gccolor & 3 on creation)  [HIGH]
Table + 0x03 = nodemask   (byte - (1<<lsizenode)-1; precomputed hash bucket
                            mask; 0 before first hash use, written on every
                            resize: ~(-1 << lsizenode))                    [HIGH]
Table + 0x04 = lsizenode  (byte - log2 hash node count; 0 = 1 dummy slot) [HIGH]
Table + 0x05 = flags      (byte - 0xff on init; bit p=1 means metamethod
                            p is absent, skipping lookup overhead)         [HIGH]
Table + 0x06 = ???        (byte - zeroed on init; checked == 0 in
                            table-set fast path)                           [LOW]
Table + 0x07 = ???        (byte - zeroed)                                  [LOW]
Table + 0x08 = sizearray  (uint - array part capacity)                    [HIGH]
Table + 0x0c = lastfree   (uint - free node index, integer not pointer;
                            init = 1<<lsizenode, decremented during
                            collision resolution to find free slots)       [HIGH]
Table + 0x10 = gclist     (GCObject* - GC gray list chain pointer)        [HIGH]
Table + 0x18 = array*     (TValue* - array part base; NULL on empty table) [HIGH]
Table + 0x20 = node       (LuaNode* - hash part; &DAT_04ebdcd0 dummy
                            on empty table)                                [HIGH]
Table + 0x28 = metatable  (Table* - NULL if none)                          [HIGH]

sizeof(Table) = 0x30
```

> **Table+0x03 (nodemask):** Previously `[LOW]` unknown, zeroed on init. Confirmed via
> `luaH_resizehash`: written as `~(-1 << lsizenode)` = `(1<<lsizenode)-1` on every resize.
> Used as `hash & nodemask` to compute bucket index directly without division.
>
> **Table+0x0c (lastfree):** Previously `[LOW]` unknown. Roblox stores this as an **integer
> index** (not a pointer as in standard Lua). Initialized to the full node count
> (`1 << lsizenode`) and decremented to find free slots during collision resolution.
> This is why it fits in a `uint` (4 bytes) rather than a full 8-byte pointer.
>
> **Table+0x10 (gclist):** Resolved by elimination once `lastfree` was confirmed at +0x0c.
> Consistent with all other GC objects (`gclist` at the same relative position after the
> GC header). The `array*` pointer at +0x18 confirmed separately by `luaH_resizearray`'s
> realloc call sequence.

---

## LuaNode (0x20 bytes)

Each slot in the Table hash part. Key type tag and next-chain offset are packed into a single `uint32` to save space.

```cpp
node + 0x00 = val.value  (8 bytes - value union)              [HIGH]
node + 0x08 = val.vec_z  (float - vector Z if val is LUA_TVECTOR, else 0) [HIGH]
node + 0x0c = val.tt     (int - value type tag)               [HIGH]
node + 0x10 = key.value  (8 bytes - key union; TString* for string keys) [HIGH]
node + 0x18 = key.vec_z  (float - vector Z if key is LUA_TVECTOR, else 0) [HIGH]
node + 0x1c = packed uint32:                                   [HIGH]
                bits  [3:0]  = key.tt  (type tag)
                bits [31:4]  = next offset (signed, in LuaNode units of 0x20 bytes)
```

Hash lookup: `bucket = TString->hash & nodemask` (Table+0x03).  
Chain end: `node+0x1c < 0x10` - means next==0 and key==nil (empty or end of chain).

---

## Userdata (partial)

```cpp
Userdata + 0x08 = metatable*  (Table* - NULL if none)  [HIGH]
```

---

## global_State (g)

Access via `L->l_G`. Starts at `L+0x80` in the main-thread combined allocation.

```cpp
g + 0x00  = nextgc      (size_t - GC threshold; init = totalbytes * 4)  [HIGH]
g + 0x08  = totalbytes  (size_t - 0x4710 on init = combined LG block)   [HIGH]

// Written by lua_newstate:
g + 0x10  = frealloc    (lua_Alloc - allocator function pointer)         [HIGH]
g + 0x18  = ud          (void* - allocator userdata)                     [HIGH]
g + 0x20  = panic       (lua_CFunction - unprotected error handler;
                          NULL on init)                                   [HIGH]
g + 0x28  = gray        (GCObject* - active gray list head; zeroed at
                          init, populated during GC operation; confirmed
                          via luaC_barrier prepend pattern)               [HIGH]
g + 0x30  = ???         (8 bytes - zeroed by lua_newstate)               [LOW]

g + 0x38  = strt.size   (uint - bucket count; 0x20 after luaS_resize)   [HIGH]
g + 0x3c  = strt.nuse   (uint - interned string count)                   [HIGH]
g + 0x40  = strt.hash   (TString** - bucket array)                       [HIGH]

// GC parameters:
g + 0x48  = gcpause     (uint32 - 200 on init)                           [HIGH]
g + 0x4c  = gcstepmul   (uint32 - 200 on init)                           [HIGH]
g + 0x50  = ???         (uint32 - 0x400 on init; possibly gcstepsize)    [MED]
g + 0x54  = gccolor     (byte - 9 on init; bits[1:0]=mark color,
                          bit[3]=GC phase flag)                           [MED]
g + 0x55  = gcstate     (byte - GC phase; value 2 = sweep phase, triggers
                          different barrier behavior in luaC_barrier)     [HIGH]

// GC lists (partially mapped):
g + 0x58  = gc_sentinel (16-byte dummy anchor; both g+0x68 and g+0x70 are
                          initialized to point here - it serves as the
                          list-end sentinel for GC traversal lists)       [MED]
g + 0x60  = ???         (8 bytes - part of sentinel object above)        [LOW]
g + 0x68  = ???         (GCObject* - GC traversal list head #1;
                          init → &g+0x58 sentinel; NOT the active gray
                          list - that is g+0x28; likely grayagain or weak,
                          confirmed by lua_newstate store sequence but
                          distinction requires luaC_step)                 [MED]
g + 0x70  = ???         (GCObject* - GC traversal list head #2;
                          init → &g+0x58 sentinel; same caveat as g+0x68) [MED]

// g+0x78 through g+0x30f: GC list block (rootgc, weak, allweak, etc.) - needs luaC_step

// Extended Roblox-specific region (all zeroed on init except g+0x510):
g + 0x500 = ???         (8 bytes - zeroed)                               [LOW]
g + 0x508 = ???         (8 bytes - zeroed)                               [LOW]
g + 0x510 = ???         (size_t or uint - set to 1 by lua_newstate;
                          unique non-zero init in this region; purpose
                          unknown - possibly a version flag or ref count) [LOW]
g + 0x518 = ???         (zeroed; further fields continue to ~g+0x768)   [LOW]

g + 0x310 = mainthread  (lua_State*)                                      [HIGH]
g + 0x318 = ???         (8 bytes - between mainthread and tmname[0])      [LOW]

// Metamethod name strings - 21 entries, 8 bytes (TString*) each:
g + 0x320 = tmname[0]   "__index"       [HIGH]
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

// Type name strings - 12 entries, 8 bytes (TString*) each:
g + 0x3c8 = ttname[0]   "nil"           [HIGH]
g + 0x3d0 = ttname[1]   "boolean"
g + 0x3d8 = ttname[2]   "userdata"      (light)
g + 0x3e0 = ttname[3]   "number"
g + 0x3e8 = ttname[4]   "integer"
g + 0x3f0 = ttname[5]   "vector"
g + 0x3f8 = ttname[6]   "string"
g + 0x400 = ttname[7]   "table"
g + 0x408 = ttname[8]   "function"
g + 0x410 = ttname[9]   "userdata"      (heavy)
g + 0x418 = ttname[10]  "thread"
g + 0x420 = ttname[11]  "buffer"

// Per-type metatables - 12 entries, 8 bytes (Table*) each:
g + 0x428 = mt[0]   LUA_TNIL            [HIGH]
g + 0x430 = mt[1]   LUA_TBOOLEAN
g + 0x438 = mt[2]   LUA_TLIGHTUSERDATA
g + 0x440 = mt[3]   LUA_TNUMBER
g + 0x448 = mt[4]   LUA_TINTEGER
g + 0x450 = mt[5]   LUA_TVECTOR
g + 0x458 = mt[6]   LUA_TSTRING         (almost always non-null in Roblox)
g + 0x460 = mt[7]   LUA_TTABLE          (fallback - tables use own metatable field)
g + 0x468 = mt[8]   LUA_TFUNCTION
g + 0x470 = mt[9]   LUA_TUSERDATA       (fallback - userdata uses own metatable field)
g + 0x478 = mt[10]  LUA_TTHREAD
g + 0x480 = mt[11]  LUA_TBUFFER

g + 0x488 = ???     (4 bytes - zeroed)   [LOW]
g + 0x48c = ???     (4 bytes - zeroed)   [LOW]
g + 0x490 = ???     (8 bytes - zeroed)   [LOW]

// Registry (inline TValue at g+0x498):
g + 0x498 = registry.value  (Table*)       [HIGH]
g + 0x4a4 = registry.tt     (int - 7 = LUA_TTABLE)  [HIGH]

g + 0x4a8 = ???     (uint32 - 0x70000000 on init; confirmed via lua_newstate
                     store at puVar3+0x294 * 2 = g+0x4a8; likely a Roblox-specific
                     memory cap or sandbox memory limit)                   [MED]

// Roblox sandbox / callback hooks:
g + 0x4b8 = global_set_hook  (fn ptr - Roblox sandbox interceptor)       [MED]
g + 0x540 = cb.userdata      (void*)                                      [MED]
g + 0x548 = cb.interrupt     (fn ptr - called at luaV_execute entry when
                               ci->flags bit 2 is set; receives (L, Proto*)) [HIGH]
g + 0x550 = cb.panic         (fn ptr)                                     [MED]
g + 0x558 = cb.userthread    (fn ptr)                                     [MED]

// Per-memory-category size tracking (confirmed from lua_newstate bzero pattern):
g + 0x2c00 = memsize[256]  (size_t[256] - per-memcat byte totals; init:
                             memsize[0] = 0x4710 (the combined LG block),
                             all other entries = 0;
                             lua_newstate: bzero(g+0x2c08, 0x7f8) then
                             *(size_t*)(g+0x2c00) = 0x4710)              [MED]

// Roblox-specific large data blocks (extents from lua_newstate _bzero calls):
g + 0x3400 = ???  (0x800 bytes zeroed - purpose unknown)                 [LOW]
g + 0x3c00 = ???  (0x400 bytes zeroed - purpose unknown)                 [LOW]
g + 0x4000 = ???  (0x410 bytes zeroed if DAT_05fabf10 flag is set)       [LOW]

// sizeof(global_State) ≈ 0x4690 (allocation is 0x4710; lua_State is 0x80)
```

> **g+0x28 correction:** Previously listed as unknown `[LOW]`. Confirmed `gray` (active gray
> list head) via `luaC_barrier`: the barrier writes `obj->gclist = g->gray` then
> `g->gray = obj`, with `g->gray` at `g+0x28`. Earlier `[MED]` guess of `uvhead` was wrong.
>
> **g+0x55 correction:** Previously `[LOW]`. Confirmed `gcstate` (GC phase byte) via
> `luaC_barrier`: `if (*(char*)(g + 0x55) == 2)` branches to the sweep-phase barrier path.
>
> **g+0x58 / g+0x68 / g+0x70:** Full `lua_newstate` decompile confirms both g+0x68 and g+0x70
> are initialized to `puVar3+0x6c` = `&g+0x58`. This means g+0x58 is a sentinel object (not
> a real GCObject) used as the list-end marker. Since `gray = g+0x28` (confirmed), g+0x68 and
> g+0x70 must be other traversal lists. The previous label `grayagain` on g+0x68 was an
> unconfirmed guess and has been removed. Pull `luaC_step` to distinguish them.
>
> **g+0x510 = 1:** Set explicitly by `lua_newstate` as the only non-zero value in the g+0x500
> block. Unique among this region; exact purpose unknown.
>
> **g+0x2c00 (memsize[]):** `lua_newstate` uses `_bzero(puVar3+0x1644, 0x7f8)` then
> `*(size_t*)(puVar3+0x1640) = 0x4710` to initialize 256 × 8-byte per-memcat size entries.
> Entry 0 = 0x4710 (the initial combined allocation), all others = 0.
>
> **g+0x4a8:** Confirmed present in `lua_newstate` via offset arithmetic
> (`puVar3+0x294`, with `undefined2*` pointer arithmetic: `0x294 * 2 = 0x528` from base,
> `g = base+0x80`, so `g+0x4a8`). Purpose still unknown - likely a memory cap or sandbox
> limit given the round value `0x70000000`.

---

## Error / Exception Mechanism

Roblox's iOS build uses **C++ exceptions**, not `setjmp`/`longjmp`. There are no `setjmp`
buffers anywhere in `lua_State`. Stop looking.

```cpp
// class lua_exception : public std::exception  (single inheritance, global namespace)
// ABI: __cxxabiv1::__si_class_type_info

exception_object + 0x00 = vtable*     → DAT_05dadd88
exception_object + 0x08 = lua_State*  (the throwing thread)
exception_object + 0x10 = int         (LUA_ERR* error code)

05dadd60     = lua_exception typeinfo object
04ebd59c     = "13lua_exception"  (Itanium mangled; demangles to: lua_exception)
DAT_05dadd88 = lua_exception vtable
```

`luaD_throw` allocates via `__cxa_allocate_exception(0x18)` and calls `__cxa_throw`.
Catch sites in `lua_resume` / `luaD_pcall` use `try/catch` blocks - not `setjmp`.

---

## Opcode Dispatch

> ⚠️ **Roblox shuffles opcode byte values per build.** The first byte of each Luau
> instruction is NOT the raw opcode enum from the open-source Luau repo. Roblox
> randomizes the mapping each release as an anti-tamper measure. Any table that claims
> "opcode 5 = LOP_LOADK" is giving you a shuffled byte value specific to one build,
> not a portable constant. Do not cross-reference these numbers with Luau source.

The dispatch table lives at `DAT_05daf138`. Each entry is an 8-byte pointer.
~76 of 256 slots are non-null (out-of-line handlers). The rest are handled inline
in the main interpreter loop at `0x03f7b00c`.

Jython to dump the full table for your build:
```python
base = toAddr(0x05daf138)
for i in range(256):
    try:
        ptr = getLong(base.add(i * 8))
        if ptr != 0:
            print("opcode 0x%02x -> 0x%08x" % (i, ptr))
    except: pass
```

**Confirmed handler addresses for 2.720.1164** (shuffled byte → handler):
```
0x00 -> 0x03f7b090      0x03 -> 0x03f7bc60      0x05 -> 0x03f7ba34
0x06 -> 0x03f7bb2c      0x08 -> 0x03f7b9b4      0x10 -> 0x03f7e9f4
0x16 -> 0x03f7bae4      0x1a -> 0x03f7b5e0      0x1d -> 0x03f7b688
0x21 -> 0x03f7bbd4      0x22 -> 0x03f7ba18      0x25 -> 0x03f7beb8
0x2b -> 0x03f7bb80      0x2d -> 0x03f7be74      0x2f -> 0x03f7b5c8
0x30 -> 0x03f7bcd0      0x33 -> 0x03f7b4c4      0x37 -> 0x03f7be28
0x38 -> 0x03f7b794      0x3a -> 0x03f7b9d0      0x3f -> 0x03f7bdf8
0x42 -> 0x03f7b8b4      0x47 -> 0x03f7b8f4      0x4a -> 0x03f7bc8c
0x4e -> 0x03f7d318      0x55 -> 0x03f7b4a4      0x57 -> 0x03f7d388
0x58 -> 0x03f7c23c      0x5d -> 0x03f7bf74      0x5e -> 0x03f7d2fc
0x62 -> 0x03f7d418      0x66 -> 0x03f7d1a0      0x69 -> 0x03f7d2cc
0x6a -> 0x03f7d4d8      0x6b -> 0x03f7b3ac      0x6d -> 0x03f7c254
0x70 -> 0x03f7ced8      0x77 -> 0x03f7ce64      0x7c -> 0x03f7d598
0x7f -> 0x03f7c0b0      0x80 -> 0x03f7d504      0x81 -> 0x03f7bab8
0x82 -> 0x03f7d1ec      0x84 -> 0x03f7ce28      0x89 -> 0x03f7b3d8
0x8c -> 0x03f7bd7c      0x8e -> 0x03f7d164      0x90 -> 0x03f7b20c
0x92 -> 0x03f7d0dc      0xa0 -> 0x03f7b50c      0xa2 -> 0x03f7d670
0xa4 -> 0x03f7d458      0xa5 -> 0x03f7d3d0      0xa6 -> 0x03f7b350
0xa7 -> 0x03f7c1b4      0xa9 -> 0x03f7d024      0xab -> 0x03f7b35c
0xb1 -> 0x03f7c110      0xb2 -> 0x03f7d550      0xb3 -> 0x03f7e824
0xb5 -> 0x03f7b71c      0xb8 -> 0x03f7bad8      0xc1 -> 0x03f7d48c
0xc7 -> 0x03f7e93c      0xc9 -> 0x03f7d7a0      0xd5 -> 0x03f7d624
0xd6 -> 0x03f7d098      0xd9 -> 0x03f7cea0      0xdb -> 0x03f7cfe4
0xdf -> 0x03f7b0b8      0xe0 -> 0x03f7d804      0xe4 -> 0x03f7b3bc
0xe6 -> 0x03f7b1e4      0xe7 -> 0x03f7cdcc      0xe8 -> 0x03f7cf9c
0xea -> 0x03f7c294      0xeb -> 0x03f7d118      0xed -> 0x03f7d840
0xee -> 0x03f7bd1c      0xf0 -> 0x03f7d5e0      0xf2 -> 0x03f7bf00
0xf3 -> 0x03f7b57c      0xf4 -> 0x03f7cf54      0xf5 -> 0x03f7cdfc
0xf6 -> 0x03f7d7d0      0xf9 -> 0x03f7cf04
```

**luaV_execute internals:**
```
0x03f7747c = luaV_execute_dispatch  (trampoline - checks L+0x06 for NCG path)
0x03f7490  = luaV_execute_native    (NCG / native code path)
0x03f7b00c = luaV_execute           (main bytecode interpreter loop)
```

The interpreter caches `Proto->k` (constants array) into a register early in the
function body (`03f7b078`: `ldr x8,[x8,#0x38]`). Common opcodes like LOADK are handled
**inline** in the main loop and do not appear in the dispatch table.

**ARM64 register convention inside luaV_execute:**
```
x19 = L           (lua_State*)
x25 = dispatch table base (DAT_05daf138)
x26 = Closure*    (current function's closure object)
x27 = savedpc     (Instruction* - current bytecode position)
x28 = frame base  (L->base, &reg[0])
```

---

## Type Tags

```cpp
0x00 = LUA_TNIL
0x01 = LUA_TBOOLEAN
0x02 = LUA_TLIGHTUSERDATA
0x03 = LUA_TNUMBER
0x04 = LUA_TINTEGER    (Luau-specific - distinct from float)
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
0x02 = LUA_ERRRUN
0x04 = LUA_ERRMEM
0x05 = LUA_ERRERR
```

Thread status (`L+0x03`):
```cpp
0x00 = OK / suspended
0x01 = LUA_YIELD
0x06 = LUA_BREAK    (Luau-specific)
0x7f = running sentinel (prevents self-resume)
```

---

## Functions

### VM Core
```
0x03f7747c = luaV_execute_dispatch   trampoline; checks L+0x06 for NCG
0x03f77490 = luaV_execute_native     NCG/native execution path
0x03f7b00c = luaV_execute            main bytecode interpreter loop
0x03f7e9f8 = luaD_precall            (lua_State*, StkId func, int nresults)
0x03f7ebcc = luaD_poscall            (lua_State*, StkId firstResult)
0x03f67d40 = resume_execute_loop     post-resume driver (internal name unknown)
0x03f81e98 = tryfuncTM               __call metamethod handler inside luaD_precall
```

### Thread / State
```
0x03f6f7c8 = lua_newstate            (lua_Alloc f, void* ud) -> lua_State*
                                      Allocates 0x4710 byte combined block.
                                      Writes frealloc/ud/panic/gcparams/mainthread.
                                      Calls luaD_rawrunprotected(L, luaE_newstate).
                                      Returns NULL on failure.
0x03f675c8 = lua_resume
0x03f6523c = lua_closethread
0x03f6f478 = luaD_initstack          (lua_State* L, lua_State* mainthread)
0x03f6fac4 = luaE_newstate           called under protection by lua_newstate
0x03f66d48 = luaD_rawrunprotected    (lua_State*, lua_CFunction, void*)
0x03f6fb88 = lua_freestate           cleanup on init failure
```

### Call Stack
```
0x03f670a8 = luaD_growCI
0x03f67010 = luaD_reallocCI
0x03f66e4c = luaD_growstack          [MED]
0x03f67454 = luaD_seterrorobj
0x03f66e08 = luaD_throw              C++ __cxa_throw wrapper, NOT longjmp
```

### Memory
```
0x03f6d7e4 = luaM_newobject          (lua_State*, size_t, memcat) -> void*
0x03f6d648 = luaG_toobig             no return - string > 0x40000000 bytes
```

### Strings
```
0x03f6fc34 = luaS_hash               (const char*, size_t) -> uint
0x03f6ff1c = luaS_newlstr            (lua_State*, const char*, size_t) -> TString*
0x03f6fcc0 = luaS_resize
```

### Tables
```
0x03f736b8 = luaH_new                (lua_State*, int narray, int nhash) -> Table*
0x03f7376c = luaH_resizearray
0x03f7387c = luaH_resizehash
0x03f73a8c = luaH_getstr             (Table*, TString*) -> TValue*
                                      Returns &DAT_04ebdbc0 (nil sentinel) on miss.
```

### Metamethods / Type System
```
0x03f75e60 = luaT_init
0x03f75f6c = luaT_gettmbyobj         (lua_State*, TValue*, uint event) -> TValue*
```

### Error Reporting
```
0x03f660f0 = luaG_runerror           no return
0x03f660c0 = luaG_typeerror          "attempt to %s a %s value"
0x03f66184 = luaG_concaterror
0x03f661c8 = luaG_aritherror
0x03f66240 = luaG_ordererror
0x03f662b4 = luaG_indexerror
```

### GC (partial - needs luaC_step analysis)
```
0x03f6938c = luaC_barrier            GC write barrier (called on heap-obj store
                                      into black table)                     [MED]
```

### Misc
```
0x03f7607c = luaO_tostring
0x03f76a08 = luaopen_vector          NOTE: not luaT_gettmbyobj - false lead
0x03f77254 = vector __index handler
```

### C API
```
0x03f5e5fc = luaL_register
0x03f5bae4 = lua_pushvector          (float x, float y, float z, lua_State*)
                                      NOTE: L is last arg - ARM64 float registers
                                      consume x/y/z first.
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
DAT_04ebdbc0 = nil TValue sentinel    luaH_getstr / luaT_gettmbyobj miss - DO NOT WRITE
DAT_04ebdcd0 = dummy LuaNode          Table->node for empty tables - DO NOT WRITE
DAT_05dae828 = vector lib luaL_Reg[]
DAT_05dadd88 = lua_exception vtable
DAT_05daf138 = opcode dispatch table  ptr[256], 8 bytes per entry
DAT_05fabec8 = feature flag           0x01 = coroutine-extended behavior
DAT_05fabf10 = feature flag           checked in lua_newstate
```

---

## What's Left

| Target | What it unlocks | Priority |
|---|---|---|
| GC functions (`luaC_step` etc.) | Distinguishes g+0x68 vs g+0x70 (grayagain/weak/allweak); closes g+0x78→g+0x30f GC list block | High |
| `Proto+0x20`→`+0x37` gap | sizek, sizecode, nups, nested proto array | High |
| `g+0x30`, `g+0x318` | Zeroed unknowns; need `lua_resume` full body or upvalue fns | Med |
| `L+0x78` | NULL on init; need CLOSE opcode handler or `luaF_close` | Med |
| `g+0x510` | = 1 on init; purpose unknown - could be a version flag or memcat ref count | Med |
| `g+0x500`→`g+0x768` gap | Extended Roblox-specific region; callback struct boundaries unclear | Med |
| `g+0x3400`, `g+0x3c00`, `g+0x4000` | Large _bzero'd blocks; likely Roblox sandbox data | Low |
| `Closure+0x04` | Unknown byte between numparams and isC | Low |
| `Table+0x06`, `+0x07` | Zeroed on init; likely padding | Low |
| `g+0x488`→`g+0x497` | 12 bytes between `mt[]` end and registry | Low |
| `g+0x4a8` | 0x70000000 confirmed present; purpose (memory cap?) still unknown | Low |

---

*Offsets are specific to version 2.720.1164. Verify before use. Corrections welcome.*
