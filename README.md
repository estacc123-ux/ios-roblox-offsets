### lua_State (L)
```cpp
L + 0x00 = unknown
L + 0x01 = tt / type (byte)
L + 0x03 = status (byte)
            0x00 = suspended / OK
            0x01 = LUA_YIELD
            0x06 = LUA_BREAK  (Luau-specific)
            0x7f = running
L + 0x08 = stacksize (int, upper bytes unknown)
L + 0x0c = size_ci (int)
L + 0x18 = l_G (global_State*)
L + 0x20 = stack_last (StkId)
L + 0x28 = top (StkId)
L + 0x30 = stack (StkId - alloc base)
L + 0x38 = ci (CallInfo*)
L + 0x40 = base (StkId - current frame base)
L + 0x58 = end_ci (CallInfo*)
L + 0x60 = base_ci (CallInfo*)
L + 0x70 = gt (Table* - _G)
```

---

### TValue (0x10 bytes)
```cpp
TValue + 0x00 = value union (8 bytes)
TValue + 0x08 = unknown (4 bytes)  // unresolved - likely extra/hash cache
TValue + 0x0c = type tag (int)
```

---

### TString
```cpp
TString + 0x00 = tt (byte)
TString + 0x01 = memcat (byte)
TString + 0x02 = marked (byte, GC flags - |8 = pinned)
TString + 0x03 = extra (byte)
TString + 0x08 = next (GCObject* - hash chain)
TString + 0x10 = hash (uint)
TString + 0x14 = len (uint)
TString + 0x18 = data[] (inline chars)
```

---

### CallInfo (0x28 bytes) - **CORRECTED this session**
```cpp
ci + 0x00 = top     (StkId - frame ceiling: func + numparams slots)    // HIGH confidence
ci + 0x08 = savedpc (Instruction* - 0 on C call, Proto->code on Lua)   // HIGH confidence
ci + 0x10 = base    (StkId - first arg / frame base = func + 0x10)     // HIGH confidence
ci + 0x18 = func    (StkId - ptr to func TValue on stack)              // HIGH confidence
ci + 0x20 = nresults (int - -1 = LUA_MULTRET)                          // HIGH confidence
ci + 0x24 = flags   (int - bit 0: CIST_YIELDABLE, bit 2: has upvalues) // MED confidence on bit meanings
```

---

### Closure (partial)
```cpp
Closure + 0x00 = tt      (byte)
Closure + 0x01 = memcat  (byte)
Closure + 0x02 = marked  (byte)
Closure + 0x03 = numparams (byte)  // MED - could be nupvalues, derived from precall stack sizing
Closure + 0x04 = unknown (byte)
Closure + 0x05 = isC     (byte - 0 = Lua closure, nonzero = C closure)  // HIGH confidence
Closure + 0x18 = Proto*  (Lua) / lua_CFunction (C)                       // HIGH confidence
Closure + 0x28 = continuation fn* (C closures only - 0 = none)           // HIGH confidence
```

---

### Proto (partial)
```cpp
Proto + 0x04 = byte  (is_vararg or numparams - if 0: L->top = ci->top)  // MED - branch seen, meaning uncertain
Proto + 0x05 = byte  (maxstacksize - used for nil-fill loop)             // HIGH confidence
Proto + 0x08 = ptr   (upvalue-related - if 0: skip upvalue flag)         // LOW - ptr confirmed, semantics guessed
Proto + 0x10 = ptr   (upvalue-related - if 0: skip upvalue flag)         // LOW - same
Proto + 0x40 = Instruction* (code array - stored into ci->savedpc)       // HIGH confidence
```

---

### global_State (g)
```cpp
g + 0x00  = nextgc / GCthreshold (size_t)
g + 0x08  = totalbytes (size_t)
g + 0x38  = strt.size (uint - string table bucket count)
g + 0x40  = strt.hash (TString** - bucket array)
g + 0x320 = tmname[0]  "__index"      (TString*)  // through g+0x3c0
g + 0x3c8 = ttname[0]  "nil"          (TString*)  // through g+0x420
g + 0x498 = registry TValue.value (Table*)
g + 0x4a4 = registry TValue.tt = 7
// Gap g+0x10 → g+0x31f still unresolved (mainthread, panic, frealloc, GC lists, mt[12])
```

---

### lua_exception (C++ exception class)
```cpp
// class lua_exception : public std::exception
// __si_class_type_info - single inheritance, no namespace
exception_object + 0x00 = vtable*     (→ DAT_05dadd88)
exception_object + 0x08 = lua_State*  (the throwing thread)
exception_object + 0x10 = int         (LUA_ERR* errcode)

05dadd60 = lua_exception_typeinfo
04ebd59c = "13lua_exception" (mangled name string)
DAT_05dadd88 = lua_exception_vtable
```

---

### Type Tags (full - your partial list had errors)
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

### Error Codes
```cpp
0x02 = LUA_ERRRUN
0x04 = LUA_ERRMEM
0x05 = LUA_ERRERR
```

---

### Functions
```cpp
// HIGH confidence
0x03f660f0 = luaG_runerror
0x03f662b4 = luaG_indexerror
0x03f66e08 = luaD_throw          // C++ exception wrapper confirmed
0x03f670a8 = luaD_growCI
0x03f67010 = luaD_reallocCI
0x03f67454 = luaD_seterrorobj
0x03f675c8 = lua_resume
0x03f6523c = lua_closethread
0x03f6f478 = luaD_initstack
0x03f6fac4 = luaE_newstate
0x03f6fcc0 = luaS_resize
0x03f6ff1c = luaS_newlstr
0x03f736b8 = luaH_new
0x03f75e60 = luaT_init
0x03f7607c = luaO_tostring
0x03f7e9f8 = luaD_precall        // signature confirmed: (L, func, nresults)
0x03f7ebcc = luaD_poscall        // HIGH confidence - matches standard impl exactly
0x03f7747c = luaV_execute        // HIGH confidence - called for every Lua closure dispatch

// MED confidence - named from behavior, not symbol
0x03f67d40 = resume_execute_loop // drives post-resume execution; name uncertain
0x03f81e98 = luaG_typeerror      // called on TValue.tt != 8 in precall; not yet verified
0x03f66e4c = luaD_growstack      // called on stack overflow in precall; not yet verified
```
