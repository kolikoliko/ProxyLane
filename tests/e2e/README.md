# ProxyLane end-to-end test tools

## Desktop startup regression

After building both Release platforms, run on an unlocked desktop:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests/run-startup-smoke.ps1
```

This launches the real main dialog twice through each entry executable and
checks that it remains responsive for 10 seconds. On 64-bit Windows the Win32
launcher is verified through its exact x64 child. Use `-BinaryDirectory` with
an isolated copy of the release and sample INI to avoid using personal profiles.
The test starts no proxy and changes no certificate trust.

This catches initialization recursion such as calling an MFC `OnSize` handler
directly from `OnInitDialog`: its default handler redispatches the current
`WM_INITDIALOG`, causing stack overflow before the main window appears.
Initialization and resize must call a shared layout helper instead.

For monitor page activation, resizing and CA dialog layout (Python + Pillow):

```powershell
python tests/MonitorLayoutE2ETests.py
python tests/MonitorLayoutE2ETests.py --language en-US
python tests/MonitorLayoutE2ETests.py --ca-guidance
```

This uses an isolated release copy and CA directory, checks actual control
rectangles after navigation, a parameterless `WM_SIZE`, resize and reactivation,
and opens the CA status dialog without changing trust. Screenshots and results
are retained in `build/qa/monitor-layout-*`. A running process alone does not
count as passing this check: controls must be visible and inside the page.

The optional `--ca-guidance` case installs a unique temporary CA through the GUI
and removes that exact CA in `finally`. It checks missing CA guidance,
cancel without installation, direct installation without an initialization button,
and automatic decryption after installation
and closing the dialog. Adding `--ca-read-error` deliberately opens an error popup
for a corrupt test CA file, which is restored before cleanup.

## HTTPS MITM validation

Build both solution Release platforms (x64 Release also builds both MITM DLLs),
or run `scripts/build-mitm.ps1` to build only the optional TLS components.
Core tests (no trust-store changes):

```powershell
cargo test --manifest-path src/ProxyLaneMitm/Cargo.toml --locked
cargo clippy --manifest-path src/ProxyLaneMitm/Cargo.toml --locked --all-targets -- -D warnings
```

Compile `mitm_host.cpp` in an x64 Visual Studio developer prompt:

```bat
cl /nologo /EHsc /O2 /DUNICODE /D_UNICODE tests\e2e\mitm_host.cpp /Fo:build\qa\mitm_host64.obj /Fe:bin\mitm_host64.exe /link /LIBPATH:bin\x64\Release ProxyLaneHook.lib ws2_32.lib user32.lib
```

For Win32 use an x86 developer prompt, output `mitm_host32.exe` and link
`bin\Win32\Release\ProxyLaneHook.lib` (also use a different `/Fo` path).
Then run with Python 3 and `cryptography` installed:

```powershell
python tests/e2e/mitm_e2e.py --arch 64
python tests/e2e/mitm_e2e.py --arch 32
```

The test creates a unique CA in `build/qa/mitm-<id>/pki`, installs that exact
CA in CurrentUser ROOT, and removes it in `finally`. It does not change existing
proxy profiles, other certificates, or revocation caches. If the test is forcibly
killed, set `PROXYLANE_MITM_HOME` to the printed test directory's `pki` subdirectory
and run `bin/ProxyLaneMitm64.exe remove` to remove that test CA.

The test controller removes any inherited ProxyLane hooks **inside its own
process** before creating threads and children, so an already-running developer
proxy does not redirect the test. It leaves that developer proxy running.
The test host explicitly injects the matching Hook DLL into Windows curl.
By default all origins and proxy relays are local; TEST-NET addresses are mapped
to them. Optional `--external-ifconfig` reproduces a live HTTPS request to
ifconfig.io through the test relay and records shutdown diagnostics.

Cases cover certificate persistence and idempotent installation/removal,
Schannel TLS 1.2 with normal revocation checking through SOCKS5 and HTTP CONNECT,
plain TCP, 2 MiB bidirectional payload integrity, rejection of a mismatched
upstream identity, and process-associated plaintext records. The x64 run also
injects a Python/OpenSSL TLS 1.3 client for systems without Schannel TLS 1.3.
Rust tests additionally exercise byte-at-a-time ClientHello and short writes,
ALPN agreement, bounded buffers, malformed TLS, and half-close behavior.
Tests also check that TLS ciphertext/handshake JSON never enters the simple
monitor, plain TCP remains visible, clean shutdown has no error, and missing
close_notify reports its endpoint once. Abrupt close after a complete response
is distinguished from a truncated HTTP response, which must fail at the client.
CA tests verify the new name and identity-preserving directory migration.

The host uses the same object interfaces as the GUI: CA status/init/install/remove,
enable preflight and live event polling through `IGlobalProxy`. The environment enable flag is off.
Tests reject enabling before CA trust, verify request/response plaintext with
the injected PID, creation time and connection ID, disable decryption during an
established TLS stream without interrupting it, and verify new connections pass
through after disabling. Both TLS versions also check observer byte integrity
in the Rust tests, including an unusable capture path. End-to-end tests assert
that default sessions never create a `captures` directory while still delivering
process-associated plaintext to the memory observer. Temporary CA removal is
checked after every run.

Manual GUI check: open Data monitoring, enable HTTPS decryption, install the CA
when prompted, and reconnect an injected application. Verify plaintext-only
TLS records, raw records for ordinary connections, HEX view, pause, clear, and CA removal. These interactive
checks are separate from the backend API tests.

These small Go and Python programs provide controlled endpoints for testing the
real injected Windows binaries. They intentionally use TEST-NET-3 addresses
(`203.0.113.0/24`) and `.test` names; the local proxy servers map those targets
to loopback test services.

## Programs

- `socks5_udp_server.go`: SOCKS5 CONNECT and UDP ASSOCIATE server, optional
  username/password authentication and byte-at-a-time handshake replies.
- `socks5_udp_server.py`: UDP ASSOCIATE reference server with malformed-packet
  and forged-relay-source fault injection.
- `udp_soak.go`: concurrent UDP load, latency, loss, socket and association
  lifecycle test.
- `udp_echo.go`: IPv4/IPv6 UDP echo endpoint used by the soak and QUIC route
  tests.
- `ipv6_egress_probe.go`: TCP/TLS and UDP/DNS probes for validating IPv6
  targets through a SOCKS5 server on an IPv4-only local network.
- `udp_writemsg_probe.go`: Windows `WriteToUDP` / `WriteMsgUDP` compatibility
  probe, including IPv4-mapped destinations on dual-stack sockets.
- `udp_connect_probe.go`: connected UDP lifecycle probe. By default it only
  connects and closes without sending; `-write` activates one datagram per
  socket. This verifies that route reservation does not eagerly open SOCKS5
  UDP associations.
- `quic/`: quic-go stream and unreliable-datagram echo test.
- `tcp_e2e.go`: TCP server/client whose response is sent only after the server
  observes EOF. This makes successful completion proof of end-to-end
  half-close propagation.
- `connectex_initial_data.cpp`: native Windows probe that submits the first
  application payload in `ConnectEx`. It covers data queued while the PRC is
  still negotiating SOCKS5/HTTP, including the Windows XP notification path.
- `child_guard_watchdog.cpp`: native watchdog probe that creates a marked,
  single-threaded suspended child, exits its parent, and verifies that PRC
  terminates it only after the production age threshold and two stable checks;
  a second suspended child registered as normally released must remain intact.
- `http_connect_server.go`: HTTP CONNECT proxy that deliberately writes its
  final response header and initial tunnel bytes together to verify surplus
  preservation.

## Build examples

```powershell
go build -o build/qa/go/socks5_e2e_server.exe tests/e2e/socks5_udp_server.go
go build -o build/qa/go/udp_soak.exe tests/e2e/udp_soak.go
go build -o build/qa/go/udp_echo.exe tests/e2e/udp_echo.go
go build -o build/qa/go/ipv6_egress_probe.exe tests/e2e/ipv6_egress_probe.go
go build -o build/qa/go/udp_connect_probe.exe tests/e2e/udp_connect_probe.go
go build -o build/qa/go/tcp_e2e.exe tests/e2e/tcp_e2e.go
go build -o build/qa/go/http_connect_server.exe tests/e2e/http_connect_server.go
Push-Location tests/e2e/quic
go build -o ../../../build/qa/go/quic_e2e.exe .
Pop-Location
```

Build the native Win32 probe from a Visual Studio developer prompt:

```bat
cl /nologo /EHsc /O2 tests\e2e\connectex_initial_data.cpp /Fe:build\qa\connectex_initial_data32.exe
```

Build the x64 child-guard probe after building ProxyLane x64 Release:

```bat
cl /nologo /EHsc /O2 /DUNICODE /D_UNICODE /I src\ProxyLaneHook ^
  tests\e2e\child_guard_watchdog.cpp /Fe:build\qa\child_guard_watchdog.exe ^
  /link /LIBPATH:bin\x64\Release ProxyLaneHook.lib user32.lib
set PATH=%CD%\bin;%PATH%
build\qa\child_guard_watchdog.exe
```

The watchdog test intentionally takes about two minutes; it uses the same
60-second minimum age and two 30-second observations as production.

Verify profile-scoped command reuse after building both Release platforms:

```powershell
python tests/ProfileCommandReuseE2ETests.py --bin bin
```

This test covers reuse of a running manual instance, repeated automation
launches, Win32-to-x64 forwarding, a later manual instance that must not steal
ownership, and two simultaneous first launches.

Launch the client through ProxyLane's automation interface after creating a
temporary profile that points at the corresponding local proxy:

```powershell
bin/ProxyLane64.exe --auto --profile E2E --run `
  build/qa/go/tcp_e2e.exe -- -mode client `
  -target 203.0.113.10:39003 -connections 8 -iterations 10
```

The servers, temporary profiles and ports are test-owned resources. Do not run
these mappings against production proxy settings.

## Traffic statistics

`traffic_statistics.cpp` checks exact upstream/downstream payload byte counts
through the real Hook DLL, including TCP, initial queued UDP datagrams, and
reset after stopping and restarting the proxy. The Python runner starts local
TCP/UDP endpoints that reply with twice the request payload, so swapped
directions, duplicate counting, and inclusion of SOCKS framing fail the test.

After building x64 Release, compile in an x64 Visual Studio developer prompt:

```bat
cl /nologo /EHsc /O2 /DUNICODE /D_UNICODE tests\e2e\traffic_statistics.cpp /Fo:build\qa\traffic_statistics.obj /Fe:bin\traffic_statistics.exe /link /LIBPATH:bin\x64\Release ProxyLaneHook.lib ws2_32.lib user32.lib
python tests\TrafficStatisticsE2ETests.py --probe bin\traffic_statistics.exe --socks-server build\qa\go\socks5_e2e_server.exe
```

For Win32, use an x86 developer prompt and `bin\Win32\Release` as the library
directory. The probe must reside beside the matching Hook DLL. All proxy and
echo server ports are temporary loopback ports; no saved profiles are changed.

## Managed process startup

After building both Release platforms, use 64-bit Python with `psutil` and
the .NET Framework 4 C# compiler installed:

```powershell
python tests/ManagedStartupE2ETests.py --bin bin
```

Optionally add `--msbuild-dir` with the Visual Studio 2019
`MSBuild/Current/Bin` directory to also run both MSBuild executables with
`-nologo -version` through the hooked shells.

The runner compiles `managed_startup_probe.cs` for x86 and x64 and tests all
four shell/managed-child architecture combinations. Each managed child
starts a managed grandchild of the other bitness. Both must load the test
Hook DLL and exchange PING/PONG through a local SOCKS5 server, for eight
proxied connections in total. Reports and isolated binaries are retained
under `build/qa/managed-startup-*`; only test-owned processes are stopped.
An inherited Hook is disabled only in the disposable Python runner.

This covers the startup-context regression where a newly created x86 CLR
process receives `_CorExeMain` in EAX during loader initialization, but the
injection trampoline used to overwrite it with the pre-initialization
snapshot on return from `remoteCode`.

## Simple data monitoring under load

After building Release for both platforms, run:

```powershell
python tests/MonitorLayoutE2ETests.py --binary-directory bin
python tests/MonitorLayoutE2ETests.py --binary-directory bin --language en-US
python tests/MonitorTrafficE2ETests.py --binary-directory bin
```

The traffic test launches a disposable GUI with a unique profile and transfers
128 MiB through an injected child and a local SOCKS5 relay. It verifies complete
delivery by SHA-256 while HEX logging stays below 128 Ki characters, private
memory growth stays below 48 MiB, and window message latency stays below one
second. It also checks tail following, hidden-page replay, HEX switching and
clearing. Screenshots and measurements remain in `build/qa/monitor-traffic-*`.
No user profiles or CA trust are changed. `mitm_host32.exe monitor-queue` and
`mitm_host64.exe monitor-queue` test queue overflow order, clear, and pause.
The queue checks also cover capture through the existing data-handler interface
without GUI callbacks, and service lifetime across proxy owner recreation.
The ordinary native tests cover HEX byte formatting and text budget boundaries.

## Alternate-user process creation

Build `logon_child_probe.cpp` from both x64 and x86 Visual Studio developer
prompts (use the corresponding output name):

```bat
cl /nologo /EHsc /MT /O2 /DUNICODE /D_UNICODE tests\e2e\logon_child_probe.cpp /Fe:build\qa\logon_probe64.exe
cl /nologo /EHsc /MT /O2 /DUNICODE /D_UNICODE tests\e2e\logon_child_probe.cpp /Fe:build\qa\logon_probe32.exe
```

After building both ProxyLane Release platforms, run:

```powershell
python tests/LogonChildE2ETests.py --user <local-test-account>
```

The runner prompts for the password, or accepts `PROXYLANE_TEST_PASSWORD` from
its transient environment. Credentials are never stored in sources, reports,
profiles or command-line arguments. A disposable directory under `build/qa`
is granted Modify access to the supplied test account so both users can write
reports and read the test binaries. Only the runner's own inherited Hook, if
any, is disabled to isolate the test from an already-proxied developer shell.

The 24 cases cover all four x86/x64 parent/child combinations, NULL and
explicit ANSI/Unicode environments, caller-owned suspension, invalid creation
flags and a missing executable. Successful cases verify the actual child
identity, Hook loading, environment semantics and both child/grandchild
SOCKS5 traffic through the PRC. Only a local test proxy can answer the
TEST-NET target. Separate ACL checks use the test user's regular and lowered
integrity tokens: message I/O is allowed; DACL modification and creating a
competing named-pipe server are denied.

For the actual Windows `runas.exe`, run this in an interactive terminal:

```powershell
python tests/LogonChildE2ETests.py --user <local-test-account> --interactive-runas
```

Enter the password at the initial test prompt and at each of the four Windows
`runas` prompts. The script injects the selected x86/x64 `runas.exe` while
suspended, then validates the alternate-user child and grandchild against the
same local SOCKS5 endpoint. This deliberately leaves runas password entry to
the operator. Each prompt has a 60-second timeout.

Implementation notes: NULL environments retain Windows' target-user profile
semantics. Consequently that initial child does not carry the caller's
environment-based orphan-watchdog marker; once its Hook is initialized, its
normal descendants use the existing marker mechanism. The explicit handle
inheritance path requires Vista or later; XP retains the existing PID-based
cross-bitness helper and is not covered by this test matrix. The installation
directory must be readable/executable by the target account; production file
ACLs and account privileges are not modified.
