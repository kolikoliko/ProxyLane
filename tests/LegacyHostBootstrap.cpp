// Exercise the real 32-bit UI on an x64 test machine. Only skip the bootstrap
// that normally launches ProxyLane64.exe; production sources/binaries are unchanged.
#include "../src/ProxyLane/stdafx.h"
#include "../src/ProxyLane/ProxyLane.h"
#include "../src/ProxyLane/Page3.h"
#define IsWow64(handle) FALSE
#include "../src/ProxyLane/ProxyLane.cpp"
#undef IsWow64
