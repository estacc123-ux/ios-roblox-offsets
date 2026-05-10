#pragma once

#include <cstdint>

// Roblox iOS (ARM64) - Luau VM offsets
// Version: 2.720.1164
// Confidence: HIGH = verified directly, MED = inferred/consistent, LOW = best guess

namespace offsets
{
        // Error reporting
    
    constexpr std::uintptr_t luaG_runerror        = 0x03f660f0; // [HIGH] vsnprintf + luaD_throw(2) pattern
    constexpr std::uintptr_t luaG_typeerror        = 0x03f660c0; // [HIGH] calls luaO_tostring + "attempt to %s a %s value"
    constexpr std::uintptr_t luaG_concaterror      = 0x03f66184; // [HIGH] "attempt to concatenate %s with %s"
    constexpr std::uintptr_t luaG_aritherror       = 0x03f661c8; // [HIGH] "attempt to perform arithmetic"
    constexpr std::uintptr_t luaG_indexerror       = 0x03f662b4; // [HIGH] "attempt to index %s with %s"
    constexpr std::uintptr_t luaG_ordererror       = 0x03f66240; // [HIGH] "attempt to compare %s %s %s"
    constexpr std::uintptr_t luaG_toobig           = 0x03f6d648; // [MED]  string > 0x40000000 bytes, no return

        // Execution / call stack
    
    constexpr std::uintptr_t luaD_precall          = 0x03f7e9f8; // [HIGH] sets up CallInfo; func at ci+0x18 not ci+0x00
    constexpr std::uintptr_t luaD_poscall          = 0x03f7ebcc; // [HIGH] tears down CallInfo, copies results
    constexpr std::uintptr_t tryfuncTM             = 0x03f81e98; // [HIGH] __call metamethod handler inside luaD_precall
    constexpr std::uintptr_t luaD_throw            = 0x03f66e08; // [HIGH] C++ __cxa_throw wrapper, NOT longjmp
    constexpr std::uintptr_t luaD_growstack        = 0x03f66e4c; // [MED]  grows lua stack
    constexpr std::uintptr_t luaD_growCI           = 0x03f670a8; // [MED]  grows CallInfo array when ci >= end_ci
    constexpr std::uintptr_t luaD_reallocCI        = 0x03f67010; // [MED]  reallocs CallInfo array
    constexpr std::uintptr_t luaD_seterrorobj      = 0x03f67454; // [MED]  sets error TValue on stack
    constexpr std::uintptr_t luaD_rawrunprotected  = 0x03f66d48; // [MED]  calls fn under C++ try/catch
    constexpr std::uintptr_t luaD_initstack        = 0x03f6f478; // [MED]  (L, mainthread)
    constexpr std::uintptr_t resume_execute_loop   = 0x03f67d40; // [MED]  post-resume execution driver (internal name unknown)

        // VM interpreter
    
    constexpr std::uintptr_t luaV_execute_dispatch = 0x03f7747c; // [HIGH] trampoline: checks L+0x06 for NCG path
    constexpr std::uintptr_t luaV_execute_native   = 0x03f77490; // [MED]  NCG / native code execution path
    constexpr std::uintptr_t luaV_execute          = 0x03f7b00c; // [HIGH] real bytecode interpreter (jump table, Ghidra can't recover it)

        // Thread / coroutine
    
    constexpr std::uintptr_t lua_resume            = 0x03f675c8; // [HIGH] checks status, calls luaD_precall, sets CIST_YIELDABLE
    constexpr std::uintptr_t lua_yield             = 0x03f67950; // [HIGH] sets status=YIELD, base=top-nresults
    constexpr std::uintptr_t lua_closethread       = 0x03f6523c; // [HIGH] coroutine.close
    constexpr std::uintptr_t lua_newstate          = 0x03f6f7c8; // [HIGH] allocs 0x4710 bytes: lua_State@+0, global_State@+0x80
    constexpr std::uintptr_t luaE_newstate         = 0x03f6fac4; // [HIGH] inits _G, registry, tmname[], pins error strings
    constexpr std::uintptr_t lua_freestate         = 0x03f6fb88; // [MED]  cleanup on init failure

        // Memory
    
    constexpr std::uintptr_t luaM_newobject        = 0x03f6d7e4; // [MED]  (L, size_t, memcat) -> void*

        // Strings
    
    constexpr std::uintptr_t luaS_hash             = 0x03f6fc34; // [HIGH] (const char*, size_t) -> uint
    constexpr std::uintptr_t luaS_newlstr          = 0x03f6ff1c; // [HIGH] interns string, returns TString*; new strings get atom=-1
    constexpr std::uintptr_t luaS_resize           = 0x03f6fcc0; // [MED]  rehashes string interning table

        // Tables
    
    constexpr std::uintptr_t luaH_new              = 0x03f736b8; // [HIGH] (L, narray, nhash) -> Table*; lsizenode=0, flags=0xFF
    constexpr std::uintptr_t luaH_resizearray      = 0x03f7376c; // [MED]  (L, Table*, narray)
    constexpr std::uintptr_t luaH_resizehash       = 0x03f7387c; // [MED]  (L, Table*, nhash)
    constexpr std::uintptr_t luaH_getstr           = 0x03f73a8c; // [HIGH] (Table*, TString*) -> TValue*; returns nil sentinel on miss

        // Metamethods / type system
    
    constexpr std::uintptr_t luaT_init             = 0x03f75e60; // [HIGH] interns all tmname[] and ttname[] at startup
    constexpr std::uintptr_t luaT_gettmbyobj       = 0x03f75f6c; // [HIGH] (L, TValue*, event) -> TValue*; checks obj->mt then g->mt[tt]

        // Misc
    
    constexpr std::uintptr_t luaO_tostring         = 0x03f7607c; // [MED]  converts Lua value to type name string for error messages
    constexpr std::uintptr_t luaopen_vector        = 0x03f76a08; // [HIGH] vector library initializer

        // Static data (do NOT write to these)
    
    constexpr std::uintptr_t nil_tvalue_sentinel   = 0x04ebdbc0; // [HIGH] returned by luaH_getstr on miss; do not write
    constexpr std::uintptr_t dummy_luanode         = 0x04ebdcd0; // [HIGH] Table->node for empty tables; do not write
    constexpr std::uintptr_t opcode_dispatch_table = 0x05daf138; // [HIGH] ptr[256] x 8 bytes; byte values are shuffled per build

} // namespace offsets


// lua_State field offsets  (L = lua_State*)
namespace L
{
    constexpr std::uintptr_t tt            = 0x00; // [HIGH] byte  0x0a = LUA_TTHREAD
    constexpr std::uintptr_t memcat        = 0x01; // [HIGH] byte  GC object category
    constexpr std::uintptr_t marked        = 0x02; // [HIGH] byte  GC flags; bit3=pinned
    constexpr std::uintptr_t status        = 0x03; // [HIGH] byte  0=OK 1=YIELD 6=BREAK 0x7f=running
    constexpr std::uintptr_t active_memcat = 0x04; // [HIGH] byte  memcat for new allocs on this thread
    constexpr std::uintptr_t native_exec   = 0x06; // [MED]  byte  1=NCG path active
    constexpr std::uintptr_t stacksize     = 0x08; // [HIGH] int
    constexpr std::uintptr_t size_ci       = 0x0c; // [HIGH] int
    constexpr std::uintptr_t l_G           = 0x18; // [HIGH] global_State*
    constexpr std::uintptr_t stack_last    = 0x20; // [HIGH] StkId
    constexpr std::uintptr_t top           = 0x28; // [HIGH] StkId  current top of stack
    constexpr std::uintptr_t stack         = 0x30; // [HIGH] StkId  allocation base
    constexpr std::uintptr_t ci            = 0x38; // [HIGH] CallInfo*  current frame
    constexpr std::uintptr_t base          = 0x40; // [HIGH] StkId  current frame base = &reg[0]
    constexpr std::uintptr_t end_ci        = 0x58; // [HIGH] CallInfo*
    constexpr std::uintptr_t base_ci       = 0x60; // [HIGH] CallInfo*
    constexpr std::uintptr_t nCcalls       = 0x68; // [HIGH] ushort  current C call nesting depth
    constexpr std::uintptr_t baseCcalls    = 0x6a; // [HIGH] ushort  C depth at coroutine entry
    constexpr std::uintptr_t gt            = 0x70; // [HIGH] Table*  _G global environment
} // namespace L


// CallInfo field offsets  (ci = CallInfo*)
// WARNING: many public references put func at +0x00 — that is WRONG
namespace CI
{
    constexpr std::uintptr_t top      = 0x00; // [HIGH] StkId  frame ceiling
    constexpr std::uintptr_t savedpc  = 0x08; // [HIGH] Instruction*  0 on C call
    constexpr std::uintptr_t base     = 0x10; // [HIGH] StkId  first arg / frame base
    constexpr std::uintptr_t func     = 0x18; // [HIGH] StkId  ptr to function TValue on stack
    constexpr std::uintptr_t nresults = 0x20; // [HIGH] int    -1 = LUA_MULTRET
    constexpr std::uintptr_t flags    = 0x24; // [MED]  int    bit0=YIELDABLE bit2=interrupt check
} // namespace CI


// TValue field offsets
namespace TV
{
    constexpr std::uintptr_t value = 0x00; // [HIGH] 8 bytes  union: ptr / double / int
    constexpr std::uintptr_t extra = 0x08; // [LOW]  4 bytes  real field, purpose unknown
    constexpr std::uintptr_t tt    = 0x0c; // [HIGH] int      type tag
} // namespace TV


// TString field offsets
namespace TS
{
    constexpr std::uintptr_t tt      = 0x00; // [HIGH] byte  0x06 = LUA_TSTRING
    constexpr std::uintptr_t memcat  = 0x01; // [HIGH] byte
    constexpr std::uintptr_t marked  = 0x02; // [HIGH] byte  bit3=pinned
    constexpr std::uintptr_t atom    = 0x04; // [MED]  int16 -1=unassigned
    constexpr std::uintptr_t next    = 0x08; // [HIGH] TString*  interning hash chain
    constexpr std::uintptr_t hash    = 0x10; // [HIGH] uint
    constexpr std::uintptr_t len     = 0x14; // [HIGH] uint  byte length
    constexpr std::uintptr_t data    = 0x18; // [HIGH] char[]  inline, null terminated
} // namespace TS


// Table field offsets  (sizeof = 0x30)
namespace TBL
{
    constexpr std::uintptr_t tt        = 0x00; // [HIGH] byte  0x07 = LUA_TTABLE
    constexpr std::uintptr_t memcat    = 0x01; // [HIGH] byte
    constexpr std::uintptr_t marked    = 0x02; // [HIGH] byte  GC color
    constexpr std::uintptr_t lsizenode = 0x04; // [HIGH] byte  log2 hash node count; 0=1 dummy slot
    constexpr std::uintptr_t flags     = 0x05; // [HIGH] byte  0xFF=no metamethods; bit p=TM p absent
    constexpr std::uintptr_t sizearray = 0x08; // [HIGH] uint  array part capacity
    constexpr std::uintptr_t array     = 0x18; // [HIGH] TValue*  array part; NULL on empty
    constexpr std::uintptr_t node      = 0x20; // [HIGH] LuaNode*  hash part
    constexpr std::uintptr_t metatable = 0x28; // [HIGH] Table*  NULL if none
} // namespace TBL


// Closure field offsets
namespace CL
{
    constexpr std::uintptr_t tt         = 0x00; // [HIGH] byte  0x08 = LUA_TFUNCTION
    constexpr std::uintptr_t memcat     = 0x01; // [HIGH] byte
    constexpr std::uintptr_t marked     = 0x02; // [HIGH] byte
    constexpr std::uintptr_t numparams  = 0x03; // [MED]  byte  (could be nupvalues)
    constexpr std::uintptr_t isC        = 0x05; // [HIGH] byte  0=Lua nonzero=C
    constexpr std::uintptr_t proto_or_fn= 0x18; // [HIGH] Proto* (Lua) / lua_CFunction (C)
    constexpr std::uintptr_t cont       = 0x28; // [HIGH] cont* (C only; NULL=not yieldable)
} // namespace CL


// Proto field offsets  (partial)
namespace PT
{
    constexpr std::uintptr_t maxstacksize = 0x05; // [HIGH] byte
    constexpr std::uintptr_t k           = 0x38; // [HIGH] TValue*  constants array
    constexpr std::uintptr_t code        = 0x40; // [HIGH] Instruction*  bytecode
} // namespace PT


// global_State field offsets  (g = *(global_State**)(L + L::l_G))
// In main-thread combined alloc: g = main_thread_ptr + 0x80
namespace G
{
    constexpr std::uintptr_t nextgc         = 0x00;  // [HIGH] size_t  GC threshold
    constexpr std::uintptr_t totalbytes     = 0x08;  // [HIGH] size_t  total allocated bytes
    constexpr std::uintptr_t frealloc       = 0x10;  // [HIGH] lua_Alloc fn ptr
    constexpr std::uintptr_t ud             = 0x18;  // [HIGH] void*  allocator userdata
    constexpr std::uintptr_t panic          = 0x20;  // [HIGH] lua_CFunction; NULL on init
    constexpr std::uintptr_t strt_size      = 0x38;  // [HIGH] uint  string table bucket count
    constexpr std::uintptr_t strt_nuse      = 0x3c;  // [HIGH] uint  interned string count
    constexpr std::uintptr_t strt_hash      = 0x40;  // [HIGH] TString**  bucket array
    constexpr std::uintptr_t gcpause        = 0x48;  // [HIGH] uint32  200 on init
    constexpr std::uintptr_t gcstepmul      = 0x4c;  // [HIGH] uint32  200 on init
    constexpr std::uintptr_t gccolor        = 0x54;  // [MED]  byte  GC phase color bits
    constexpr std::uintptr_t gray           = 0x68;  // [MED]  GCObject*  gray list
    constexpr std::uintptr_t grayagain      = 0x70;  // [MED]  GCObject*  grayagain list
    constexpr std::uintptr_t mainthread     = 0x310; // [HIGH] lua_State*
    constexpr std::uintptr_t tmname         = 0x320; // [HIGH] TString*[21]  metamethod name strings
    constexpr std::uintptr_t ttname         = 0x3c8; // [HIGH] TString*[12]  type name strings
    constexpr std::uintptr_t mt             = 0x428; // [HIGH] Table*[12]  per-type metatables
    constexpr std::uintptr_t registry_val   = 0x498; // [HIGH] Table*  Lua registry
    constexpr std::uintptr_t registry_tt    = 0x4a4; // [HIGH] int  = 7 = LUA_TTABLE
    constexpr std::uintptr_t cb_interrupt   = 0x548; // [HIGH] fn(L,Proto*)  debug interrupt callback
} // namespace G


// Type tags
namespace types
{
    constexpr int Nil           = 0x00;
    constexpr int Boolean       = 0x01;
    constexpr int LightUserdata = 0x02;
    constexpr int Number        = 0x03;
    constexpr int Integer       = 0x04; // Luau-specific
    constexpr int Vector        = 0x05; // Luau-specific
    constexpr int String        = 0x06;
    constexpr int Table         = 0x07;
    constexpr int Function      = 0x08;
    constexpr int Userdata      = 0x09;
    constexpr int Thread        = 0x0a;
    constexpr int Buffer        = 0x0b; // Luau-specific
} // namespace types


// Error codes
namespace errcodes
{
    constexpr int ERRRUN = 0x02;
    constexpr int ERRMEM = 0x04;
    constexpr int ERRERR = 0x05;
} // namespace errcodes


// Thread status values  (L::status)
namespace status
{
    constexpr int OK      = 0x00; // suspended / resumable
    constexpr int Yield   = 0x01;
    constexpr int Break   = 0x06; // Luau-specific
    constexpr int Running = 0x7f; // sentinel — do NOT resume
} // namespace status
