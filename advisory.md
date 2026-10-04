# NoxPlayer YSDrv: unrestricted SUP session available to a local user

## Summary

NoxPlayer 7.0.6.2 ships a Windows support driver derived from the
VirtualBox 5.2.36 SUP driver. Its main device, `\Device\YSDrv`, gives a
caller an unrestricted SUP session without verifying that the caller is a
trusted VM process. A local standard user can therefore reach operations
that assume a trusted VM client.

The PoC uses the installed, signed `YSR0.sys` module and the
unrestricted session to execute kernel code and replace its process token.
On the tested physical Windows 11 system, a medium-integrity user ran the
PoC and its final `whoami` was `nt authority\system`.

## Tested product and environment

| Property | Value |
| --- | --- |
| Product | NoxPlayer 7.0.6.2 for Windows |
| Installer name | `nox_setup_v7.0.6.2_full_intl.exe` |
| Installer SHA-256 | `f76637ba2680feb8d30a413cdbf6335ded749bbedcd2da08f3791db46ea99cc1` |
| Installer signature | Valid Authenticode signature, Nox Limited |
| On-disk `BigNoxVM\RT\YSDrv.sys` SHA-256 | `043f69b539670af5b4db8c2b2a7e05a2d5634bb281dc49ea4e827cbf1c7fea3d` |
| On-disk `BigNoxVM\RT\YSR0.sys` SHA-256 | `27831ac079cb6bfb813ff434274f7b73918848767dfdc885acc61e8e30a0343e` |
| PoC executable SHA-256 | `87b038908405196d9442071055b0f0e5209f381136816d3f8d678a580643507a` |
| OS | Windows 11, build 26200, x64 |
| Protection state | Secure Boot enabled; VBS=0; HVCI off |
| Starting account | Non-admin, medium-integrity local user |

NoxPlayer was installed through its GUI using administrator
credentials. The PoC ran later from the non-admin user's PowerShell
session and ended with `nt authority\system`.

The signed installer's embedded `newver\YSDrv-single` package contains
the exact `YSDrv.sys` and `YSR0.sys` files installed under `BigNoxVM\RT`.

## Security boundary

The SUP interface serves VirtualBox-derived VM processes.
Some of its requests load a ring-0 module, create VM state, allocate pages
visible to the kernel, and invoke ring-0 VM operations. Those requests
belong to an unrestricted session.

Local users can open the device. Access to privileged IOCTLs depends on
whether the driver admits the caller to an unrestricted session.

The installed Nox driver exposes two kernel devices:

| Device | Session selected by the analyzed create path |
| --- | --- |
| `\Device\YSDrv` | Unrestricted |
| `\Device\YSDrvU` | Restricted |

The issue concerns `\Device\YSDrv`. The `YSDrvU` path does not expose
the same privileged dispatcher in the analyzed binary.

## Root cause

Static analysis of the tested `YSDrv.sys` variant shows that the file
create handler calls the session constructor with the unrestricted flag
derived from which device object was opened:

```text
on file create from user mode:
    main = (device == \Device\YSDrv)
    session = create_session(user_mode=true, unrestricted=main)
    attach session to file object
```

The create path sets `unrestricted=true` without checking whether the
caller is a trusted VM process. The common IOCTL path
then selects the privileged handler using the session's unrestricted
flag. Thus a session obtained by opening the main device can submit the
loader, memory, and VMM requests used in the PoC.

In VirtualBox 5.2.36, the hardening-enabled Windows create path checks
a candidate VM process through
`supdrvNtProtectVerifyProcess` before `supdrvCreateSession` creates an
unrestricted session. Its separate non-hardening path directly creates
the session based on the device object. YSDrv follows that create path.

The unrestricted/restricted split is retained elsewhere in Nox's SUP
dispatcher. The missing decision is at the admission point, before
untrusted callers gain the unrestricted session.

## Reachability

The PoC ran from a token that listed `BUILTIN\Users` and `S-1-16-8192`
(medium integrity), with no Administrators group. The
PoC's path opens the main device through
`\\?\GLOBALROOT\Device\YSDrv`; it does not require a DOS device alias.

The main device's security descriptor grants Everyone access. The
privileged behavior follows from the unrestricted session assignment,
not from the ACL alone.

The IOCTL header carries a device cookie, session cookie, input/output
sizes, flags, and a driver return code. These cookies carry session state;
they do not authenticate the client.

## Exploit path

The PoC uses NoxPlayer's installed driver and signed module from a
standard-user process.

1. Open `\Device\YSDrv` from the standard-user process. The create
   path attaches an unrestricted session to the file object.
2. Send `SUP_IOCTL_COOKIE` and `SUP_IOCTL_QUERY_FUNCS` to initialize the
   SUP protocol and obtain the function table used to resolve module
   imports.
3. Read the installed `YSR0.sys`, map its PE sections into image layout,
   apply base relocations for the address assigned by the driver, and
   resolve the VirtualBox/SUP import slots.
4. Submit `SUP_IOCTL_LDR_OPEN` and `SUP_IOCTL_LDR_LOAD`. The loader
   accepts the installed signed module and makes its VMM entry points
   available to the session.
5. Use the unrestricted VMM and page-allocation operations to create
   VM state and obtain pages mapped into user and kernel address space.
6. Reach the VM callback path with attacker-controlled VM data. The PoC
   checks a kernel execution marker before attempting token replacement.
7. Replace the calling process's token with a SYSTEM token and run
   `whoami` in that process context.

The main device admits an ordinary caller to a session whose later
operations assume a trusted VM process. The exploit uses that session
to reach VirtualBox-derived callback operations.

### Relevant requests

| Request | Code | Purpose in this PoC |
| --- | --- | --- |
| `SUP_IOCTL_COOKIE` | `0x228204` | Session handshake |
| `SUP_IOCTL_QUERY_FUNCS` | `0x228208` | Resolve SUP imports |
| `SUP_IOCTL_LDR_OPEN` | `0x22820c` | Open the signed module image |
| `SUP_IOCTL_LDR_LOAD` | `0x228210` | Load the relocated image |
| `SUP_IOCTL_PAGE_ALLOC_EX` | `0x228228` | Obtain shared page mappings |
| `SUP_IOCTL_CALL_VMMR0_BIG` | `0x22826c` | Request VM and callback operations |

The request numbers match the analyzed dispatcher and PoC source.

### Signed module requirement

`LDR_OPEN` uses the Windows kernel image-loading path. The PoC loads
`YSR0.sys` installed with NoxPlayer. Module signing does not restrict
the caller to a trusted VM process.

### Kernel execution path

The page-allocation request returns both user and kernel addresses for
pages associated with the session. The PoC prepares the VM structure
and uses a VMM callback operation to write a marker, then invokes a
second callback that performs the token replacement. The PoC checks
the execution marker before replacing its process token.

The token-replacement payload in `poc/poc.c` uses offsets for Windows
build 26200. The PoC is therefore tied to the stated test environment;
the admission flaw is in `YSDrv.sys`, while the final payload depends on
Windows kernel structure layout.

## Physical-system reproduction

Reproduction steps:

1. Perform a normal GUI installation of NoxPlayer 7.0.6.2 on a physical
   Windows system, entering administrator credentials for installation.
2. Sign in as a user outside Administrators and open a normal PowerShell
   session.
3. Confirm that the token is medium integrity and that the installed
   `YSDrv.sys` and `YSR0.sys` match the tested hashes.
4. Run the PoC from that PowerShell session.

The successful run is recorded in [`evidence/reproduction.txt`](evidence/reproduction.txt):

```text
Build=26200
VBS=0
YSDrv=043f69b539670af5b4db8c2b2a7e05a2d5634bb281dc49ea4e827cbf1c7fea3d
YSR0=27831ac079cb6bfb813ff434274f7b73918848767dfdc885acc61e8e30a0343e
BUILTIN\Users ... S-1-5-32-545
Mandatory Label\Medium Mandatory Level ... S-1-16-8192
--- POC (final whoami) ---
nt authority\system
```

## Impact

A standard user who can open the main YSDrv device can obtain a
privileged SUP session. In the tested configuration, that access was
used to execute code in the kernel and elevate the calling process to
`NT AUTHORITY\SYSTEM`.

The PoC loads a ring-0 module and can crash the machine. Use a
disposable test system.

## Remediation

Before creating an unrestricted session, verify that the requesting
process is an authorized, intact VM process. Reject or restrict other
local callers even when they can open the support device. Keep loader,
memory, and VMM requests behind that trusted-session decision.

The separate restricted device path can remain available for the
limited requests intended for ordinary clients. A device ACL change
alone does not express the trusted-process rule used by the upstream
hardening design.

## References

- [Reproduction log](evidence/reproduction.txt)
- [PoC source](poc/poc.c)
- [VirtualBox 5.2.36 upstream source archive](https://download.virtualbox.org/virtualbox/5.2.36/VirtualBox-5.2.36.tar.bz2): `src/VBox/HostDrivers/Support/win/SUPDrv-win.cpp`, `src/VBox/HostDrivers/Support/SUPDrv.cpp`
