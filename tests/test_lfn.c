/* Throwaway unit test for the Phase-1 server-side LFN logic in fs.c.
 * Links fs.c directly (no networking): exercises findfile(out_lfn),
 * sfn_for_name_in_dir(), and createfile() against a fixture directory. */
#include <stdio.h>
#include <string.h>
#include "fs.h"

/* symbols normally provided by ethersrv.c */
int lowercase_mode = 0;
int debug_level = 0;

int main(int argc, char **argv) {
  const char *dir;
  unsigned short dss, nth = 0;
  struct fileprops fp, cf;
  char lfn[256], sfn[14], alias_check[14];
  int rc;

  if (argc < 2) {
    fprintf(stderr, "usage: %s <dir>\n", argv[0]);
    return (1);
  }
  dir = argv[1];

  dss = getitemss((char *)dir);
  printf("== FindFirst/FindNext enumeration of '%s' (dss=%u) ==\n", dir, dss);
  printf("  %-13s %-5s %-12s  consistency\n", "LONG NAME", "ATTR", "SFN(FCB)");
  while (findfile(&fp, dss, "???????????", 0x37, &nth, 0, "", lfn) == 0) {
    /* re-derive the SFN alias independently and confirm it matches */
    const char *cmp = "n/a";
    if (lfn[0] != 0 && strcmp(lfn, ".") != 0 && strcmp(lfn, "..") != 0) {
      char fcb[12];
      sfn_for_name_in_dir(dir, lfn, alias_check);
      filename2fcb(fcb, alias_check);
      cmp = (memcmp(fcb, fp.fcbname, 11) == 0) ? "OK (matches)" : "**MISMATCH**";
    }
    printf("  %-13s 0x%02X  '%.11s'  %s\n", lfn[0] ? lfn : "(vol/empty)",
           fp.fattr, fp.fcbname, cmp);
  }

  printf("\n== sfn_for_name_in_dir() direct ==\n");
  sfn_for_name_in_dir(dir, "file_id_long.diz", sfn);
  printf("  file_id_long.diz  -> %s\n", sfn);
  sfn_for_name_in_dir(dir, "file_id_other.diz", sfn);
  printf("  file_id_other.diz -> %s\n", sfn);
  sfn_for_name_in_dir(dir, "file_id.diz", sfn);
  printf("  file_id.diz       -> %s\n", sfn);

  printf("\n== create-gap regression: create a 9-char-base long file ==\n");
  rc = createfile(&cf, (char *)dir, "file_id_created.diz", 0x20, 0);
  sfn_for_name_in_dir(dir, "file_id_created.diz", sfn);
  printf("  createfile(file_id_created.diz) rc=%d ; SFN alias=%s\n", rc, sfn);

  return (0);
}
