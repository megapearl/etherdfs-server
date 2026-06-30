#!/bin/sh
# Build the EtherDFS DOS client (ETHERDFS.EXE) with OpenWatcom v2 on Linux.
#
# The upstream client is DOS-targeted (Open Watcom 1.9, see src/MAKEFILE). This
# script reproduces that build on a modern Linux host inside a throwaway debian
# container, downloading the Open Watcom v2 snapshot on first run (cached in a
# named docker volume). It produces a valid DOS MZ executable (~8.6 KB UPX'd).
#
# Run it (from a host with docker; the OW volume must be exec-capable, i.e. NOT
# a noexec /tmp bind-mount -- use a named volume):
#
#   sudo docker run --rm \
#     -v <repo>/client/src:/src:ro \
#     -v <dir-with-this-script>:/host \
#     -v owcache:/opt/ow \
#     debian:stable-slim sh /host/build-linux.sh
#
# Two Linux adaptations (the program logic is unchanged):
#  - the DOS-uppercase source filenames are lowercased to match the lowercase
#    #include directives on the case-sensitive Linux FS;
#  - the DOS "msg\foo.c" backslash include/output paths are rewritten to
#    "msg/foo.c". genmsg is built/run natively with gcc (it is portable C).
set -e

echo "### installing deps ###"
apt-get update >/dev/null 2>&1
apt-get install -y curl xz-utils gcc upx-ucl >/dev/null 2>&1 || apt-get install -y curl xz-utils gcc >/dev/null 2>&1

OW=/opt/ow
if [ ! -x "$OW/binl64/wcl" ]; then
  echo "### downloading OpenWatcom v2 snapshot (once) ###"
  curl -fsSL -o /tmp/ow.tar.xz \
    "https://github.com/open-watcom/open-watcom-v2/releases/download/Current-build/ow-snapshot.tar.xz"
  ls -la /tmp/ow.tar.xz
  mkdir -p "$OW"
  tar -xJf /tmp/ow.tar.xz -C "$OW"
fi

# Linux x86-64 host binaries live in binl64 (NOT armo64 = ARM).
export WATCOM="$OW"
export PATH="$OW/binl64:$PATH"
export INCLUDE="$OW/h"
export EDPATH="$OW/eddat"
echo "### OW toolchain ###"
ls "$OW/binl64/wcl" "$OW/binl64/wcc" "$OW/binl64/wasm" "$OW/binl64/wlink" 2>&1
ls "$OW/h/i86.h" >/dev/null 2>&1 && echo "i86.h present" || echo "WARN: i86.h missing"

echo "### staging build copy + lowercasing DOS-uppercase filenames ###"
rm -rf /build && cp -r /src /build && cd /build
for f in *; do
  lc=$(echo "$f" | tr 'A-Z' 'a-z')
  [ "$f" != "$lc" ] && mv "$f" "$lc"
done
echo "files:"; ls

echo "### genmsg (native gcc) -> msg/*.c (forward-slash paths) ###"
mkdir -p msg
# genmsg.c source has "msg\\foo.c" (two backslash chars). Replace the 2-char
# C escape with "/" (the lone-backslash rule is a safety net).
sed 's#msg\\\\#msg/#g; s#msg\\#msg/#g' genmsg.c > genmsg_native.c
gcc genmsg_native.c -o genmsg_native
./genmsg_native
echo "generated:"; ls msg

echo "### normalize backslash includes -> forward slash in build copy ###"
sed 's#msg\\\\#msg/#g; s#msg\\#msg/#g' etherdfs.c > etherdfs_b.c
echo "include lines:"; grep -n 'include "msg' etherdfs_b.c | head

echo "### wasm chint086.asm ###"
wasm -0 chint086.asm -fo=chint.obj -ms 2>&1 | tail -5

echo "### wcl etherdfs (8086, small model, real-mode, size-opt) ###"
wcl -y -0 -s -d0 -lr -ms -wx -k1024 -fm=etherdfs.map -os chint.obj etherdfs_b.c -fe=etherdfs.exe 2>&1 | tail -45

echo "### RESULT ###"
if [ -f etherdfs.exe ]; then
  echo "BUILD OK (pre-UPX):"
  ls -la etherdfs.exe
  head -c 2 etherdfs.exe | od -An -c
  echo "(MZ above = valid DOS MZ executable)"
  cp etherdfs.exe etherdfs_raw.exe
  if command -v upx >/dev/null 2>&1; then
    upx -9 --8086 etherdfs.exe 2>&1 | tail -3 || echo "(upx failed, keeping raw)"
  else
    echo "(upx not available; raw exe kept)"
  fi
  echo "final:"; ls -la etherdfs.exe etherdfs_raw.exe
  echo "--- committed reference ETHERDFS.EXE ---"
  ls -la /src/bin/ETHERDFS.EXE 2>/dev/null || echo "(ref bin not mounted)"
else
  echo "BUILD FAILED - no etherdfs.exe produced"
  exit 1
fi
