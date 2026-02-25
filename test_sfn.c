#include <stdio.h>
#include <string.h>

char upchar(char c) {
  if ((c >= 'a') && (c <= 'z'))
    c -= ('a' - 'A');
  return (c);
}

void lfn2sfn(char *sfn, const char *lfn, int collision_idx) {
  int i, j = 0, ext_idx = -1;
  char basen[9] = {0};
  char extn[4] = {0};

  if (strcmp(lfn, ".") == 0 || strcmp(lfn, "..") == 0) {
    strcpy(sfn, lfn);
    return;
  }

  for (i = 0; lfn[i] != 0; i++) {
    if (lfn[i] == '.')
      ext_idx = i;
  }

  for (i = 0; lfn[i] != 0 && i != ext_idx && j < 8; i++) {
    char c = lfn[i];
    if (c == ' ' || c == '.' || c == '+' || c == ',' || c == ';' || c == '=' ||
        c == '[' || c == ']')
      continue;
    basen[j++] = upchar(c);
  }

  if (ext_idx >= 0) {
    j = 0;
    for (i = ext_idx + 1; lfn[i] != 0 && j < 3; i++) {
      char c = lfn[i];
      if (c == ' ' || c == '.' || c == '+' || c == ',' || c == ';' ||
          c == '=' || c == '[' || c == ']')
        continue;
      extn[j++] = upchar(c);
    }
  }

  if (collision_idx > 0) {
    char suffix[6];
    int suflen = sprintf(suffix, "~%d", collision_idx);
    int baselen = strlen(basen);
    if (baselen + suflen > 8) {
      baselen = 8 - suflen;
    }
    sprintf(basen + baselen, "%s", suffix);
  }

  if (extn[0] != 0) {
    sprintf(sfn, "%s.%s", basen, extn);
  } else {
    sprintf(sfn, "%s", basen);
  }
}

int main() {
  char sfn[13];
  lfn2sfn(sfn, "MS-DOS 7.10.iso", 0);
  printf("0: %s\n", sfn);
  lfn2sfn(sfn, "MS-DOS 7.10.iso", 1);
  printf("1: %s\n", sfn);
  lfn2sfn(sfn, "MS-DOS 7.1R2 Supplemental.img", 0);
  printf("0: %s\n", sfn);
  lfn2sfn(sfn, "MS-DOS 7.1R2 Supplemental.img", 2);
  printf("2: %s\n", sfn);
  return 0;
}
