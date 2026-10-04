# NoxPlayer YSDrv local privilege escalation

NoxPlayer 7.0.6.2 installs a Windows support driver, `YSDrv.sys`, whose main
device grants an unrestricted VirtualBox SUP session to a local caller without
verifying that the caller is a trusted VM process. A standard user can reach
privileged driver operations through that session.

NoxPlayer was installed through its GUI on a physical Windows 11
system using administrator credentials. The PoC ran from a non-admin,
medium-integrity PowerShell session and ended with `whoami` reporting
`nt authority\system`.

## Tested artifacts

| Item | Value |
| --- | --- |
| Product | NoxPlayer 7.0.6.2 |
| Installer SHA-256 | `f76637ba2680feb8d30a413cdbf6335ded749bbedcd2da08f3791db46ea99cc1` |
| On-disk `BigNoxVM\RT\YSDrv.sys` SHA-256 | `043f69b539670af5b4db8c2b2a7e05a2d5634bb281dc49ea4e827cbf1c7fea3d` |
| On-disk `BigNoxVM\RT\YSR0.sys` SHA-256 | `27831ac079cb6bfb813ff434274f7b73918848767dfdc885acc61e8e30a0343e` |
| PoC executable SHA-256 | `87b038908405196d9442071055b0f0e5209f381136816d3f8d678a580643507a` |
| Windows build | 26200 |
| Test configuration | Secure Boot enabled; VBS=0; HVCI off |

The installer has a valid Nox Limited Authenticode signature and contains
the same `YSDrv.sys` and `YSR0.sys` files installed under `BigNoxVM\RT`.

## Result

1. Before the PoC, the user was a member of `BUILTIN\Users` and had
   medium integrity. Its token did not list `BUILTIN\Administrators`.
2. The same run ended with `whoami` reporting `nt authority\system`.
3. Static analysis of the installed `YSDrv.sys` variant found that opening
   `\Device\YSDrv` creates an unrestricted SUP session without an equivalent
   trusted-process check in its create path.

The main `\Device\YSDrv` device creates unrestricted sessions. The
separate `\Device\YSDrvU` device creates restricted sessions.

## Reproduction

Use an isolated x64 Windows test system with the tested driver/module pair.
Install NoxPlayer, then sign in as a non-admin user with a medium-integrity
token. The PoC reads the installed `YSR0.sys` from
`C:\Program Files (x86)\Bignox\BigNoxVM\RT\YSR0.sys`.

Build `poc/poc.c` as an x64 console application, for example from an x64
Visual Studio developer prompt:

```bat
cl /nologo /W4 /O2 poc\poc.c /Fe:poc.exe
```

Run `poc.exe` from the non-admin account. A successful run ends with:

```text
nt authority\system
```

The PoC uses the installed signed module and is specific to the tested driver
pair and Windows build. It can crash the test system.

## Contents

- [`advisory.md`](advisory.md): technical analysis, impact, and remediation.
- [`poc/poc.c`](poc/poc.c): source for the local SYSTEM elevation path.
- [`evidence/reproduction.txt`](evidence/reproduction.txt): successful run
  log from the physical Windows system.

## Remediation

Require trusted VM-process verification before creating an unrestricted SUP
session. Keep ordinary local clients on the restricted session path.
