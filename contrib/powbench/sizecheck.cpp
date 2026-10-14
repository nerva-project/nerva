// Replicates the allocation/lws sizing in nerva-gpubench for every machine we
// have, so the paths that cannot be tested locally are still checked.
#include <cstdio>
#include <cstddef>
#include <cstdint>

struct Dev { const char *name; unsigned long long gmem, maxalloc; };
static Dev DEVS[] = {
  { "RTX 3050",  8589934592ull,  2147483648ull },
  { "Vega FE",  17179869184ull, 14384267264ull },
  { "GTX1050Ti", 4294967296ull,  1073741824ull },
  { "gfx1036",  13099287552ull, 10629247795ull },
  { "tiny 1G",   1073741824ull,   268435456ull },   // stress: very small card
};
static size_t KB[] = { 1024, 1536, 2048, 4096, 8192, 8192, 24576 };
static const char *NM[] = { "v5 1MB","v5 1.5MB","v5 2MB","v5 4MB","v5 8MB","v6","v7" };

int main() {
  int bad = 0;
  for (const Dev &d : DEVS) {
    printf("== %s  gmem %.1fG  maxalloc %.1fG ==\n", d.name,
           d.gmem/1073741824.0, d.maxalloc/1073741824.0);
    for (int i = 0; i < 7; i++) {
      const size_t bytes_per = KB[i] * 1024ull;
      size_t budget = (size_t)(d.gmem * 0.70);

      const size_t MAXBUF = 4;
      size_t nbuf = 1;
      while (nbuf < MAXBUF && budget / nbuf > (size_t)d.maxalloc) nbuf++;
      size_t chunk = budget / nbuf;
      if (chunk > (size_t)d.maxalloc) chunk = (size_t)d.maxalloc;
      size_t per_buf = chunk / bytes_per;
      if (per_buf < 1) { printf("  %-9s SKIPPED (pad exceeds a buffer)\n", NM[i]); continue; }

      size_t nonces = nbuf * per_buf;
      size_t lws = 64;
      while (lws > 1 && nonces < lws * 4) lws /= 2;
      nonces = (nonces / lws) * lws;
      if (nonces < 1) { printf("  %-9s SKIPPED (no work)\n", NM[i]); continue; }

      size_t step = lws * ((nonces / lws + 7) / 8);
      if (step < lws) step = lws;

      // the invariants that matter
      const bool ok_mult  = (nonces % lws) == 0;              // else CL_INVALID_WORK_GROUP_SIZE
      const bool ok_step  = (step % lws) == 0 && step >= lws;
      const bool ok_range = nonces <= nbuf * per_buf;         // else PICK_BUF reads past bl[]
      size_t launches = (nonces + step - 1) / step;
      const bool ok_launch = launches <= 8;
      // every launch offset+size must stay a multiple of lws and within range
      bool ok_off = true;
      for (size_t off = 0; off < nonces; off += step) {
        size_t n = nonces - off; if (n > step) n = step;
        if ((off % lws) != 0) ok_off = false;
        if ((n % lws) != 0 && (off + n) != nonces) ok_off = false;
        if (off + n > nonces) ok_off = false;
      }
      const bool all = ok_mult && ok_step && ok_range && ok_launch && ok_off;
      if (!all) bad++;
      printf("  %-9s nbuf=%zu per_buf=%-6zu nonces=%-7zu lws=%-3zu step=%-6zu launches=%zu  %s%s%s%s%s\n",
             NM[i], nbuf, per_buf, nonces, lws, step, launches,
             all ? "OK" : "FAIL",
             ok_mult ? "" : " [nonces%lws]", ok_range ? "" : " [overrun]",
             ok_step ? "" : " [step]", ok_off ? "" : " [offset]");
    }
    printf("\n");
  }
  printf(bad ? "*** %d FAILURES ***\n" : "all configurations valid\n", bad);
  return bad != 0;
}
