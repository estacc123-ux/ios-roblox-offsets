#pragma once

#include <cstdint>

namespace lua_offsets
{
    constexpr std::uintptr_t luaG_runerror        = 0x03f660f0; // Confident
    constexpr std::uintptr_t luaG_indexerror      = 0x03f662b4;// Less confident

    constexpr std::uintptr_t luaD_throw           = 0x03f66e08; // Confident
    constexpr std::uintptr_t luaD_reallocCI       = 0x03f67010; // Less confident
    constexpr std::uintptr_t luaD_growCI          = 0x03f670a8; // Less confident
    constexpr std::uintptr_t luaD_seterrorobj     = 0x03f67454;
    constexpr std::uintptr_t lua_resume           = 0x03f675c8; // Confident
    constexpr std::uintptr_t luaD_precall         = 0x03f7e9f8; // Confident

    constexpr std::uintptr_t lua_closethread      = 0x03f6523c; // Not useful but added it

    constexpr std::uintptr_t luaE_newstate        = 0x03f6fac4; // init
    constexpr std::uintptr_t luaS_newlstr         = 0x03f6ff1c; // creates TString

    constexpr std::uintptr_t luaH_new             = 0x03f736b8; // creates Table, probably

    constexpr std::uintptr_t luaO_tostring        = 0x03f7607c; // More less confident
}
