#!/bin/sh
# Phase-1 LFN regression tests for the EtherDFS server.
# Runs in an ephemeral Alpine container (no host toolchain install needed):
#   sudo docker run --rm -v "$(git rev-parse --show-toplevel)":/src -w /src/tests \
#        alpine:latest sh tests/run.sh        # (from repo root, adjust -w as needed)
# Or simply, from the repo root on a TrueNAS host:
#   sudo docker run --rm -v "$PWD":/src -w /src alpine:latest sh tests/run.sh
set -e
cd "$(dirname "$0")/.."   # repo root (server sources live here)
ROOT="$(pwd)"             # absolute repo root; the tests chdir into /tmp fixtures
apk add --no-cache gcc musl-dev linux-headers libpcap-dev >/dev/null 2>&1 || true

echo "=== compiling test_lfn (fs.c unit test) ==="
gcc tests/test_lfn.c fs.c -o /tmp/test_lfn -O2 -Wall -std=gnu89 -Wno-long-long -I.

echo "=== compiling test_proto (process() wire test; includes ethersrv.c) ==="
# net_linux.c supplies net_open/recv/send/close: ethersrv.c's (renamed) main
# references them, so they must be linked even though the wire test never calls
# the network layer.
gcc tests/test_proto.c fs.c lock.c net_linux.c -o /tmp/test_proto -O2 -std=gnu89 -Wno-long-long -lpcap -I.

# build a fixture directory with the regression name set
FIX=/tmp/lfn_fixture
rm -rf "$FIX" && mkdir -p "$FIX" && cd "$FIX"
printf X    > file_id.diz
printf XX   > file_id_long.diz
printf XXX  > file_id_other.diz
printf XXXX > readme.txt
printf YY   > a_long_document_name.txt
printf Z    > mixedcase.txt
printf W    > "my long file.txt"

echo; echo "########## UNIT TEST (fs.c) ##########"
/tmp/test_lfn "$FIX"

# fresh fixture for the wire test (create-gap test writes a file)
rm -rf "$FIX" && mkdir -p "$FIX" && cd "$FIX"
printf X>file_id.diz; printf XX>file_id_long.diz; printf XXX>file_id_other.diz
printf XXXX>readme.txt; printf YY>a_long_document_name.txt; printf Z>mixedcase.txt
printf W>"my long file.txt"
mkdir -p "Long Dir Name"
printf N>"Long Dir Name/nested long file.txt"
mkdir -p emptydir   # empty first-level subdir (isroot . / .. regression)
printf Q > "$(printf 'caf\303\251.txt')"   # UTF-8 'café.txt' (increment 6 codepage)

echo; echo "########## WIRE / process() TEST (ethersrv.c) ##########"
/tmp/test_proto "$FIX"
# increment 6: the CP437 create ("ni\xA4o6.txt") must exist on disk as UTF-8 nino
if [ -f "$FIX/$(printf 'ni\303\261o6.txt')" ]; then
  echo "  OK: CP437 create stored as UTF-8 on disk (ni\xc3\xb1o6.txt)"
else
  echo "  FAIL: CP437 create did not produce the UTF-8 disk name"; exit 1
fi

cd "$ROOT"  # back to repo root (absolute; we are currently inside the fixture dir)

echo; echo "########## FTCONV TEST (client 71A7h date math, host build) ##########"
gcc tests/test_ftconv.c -o /tmp/test_ftconv -O2 -Wall -Iclient/src
/tmp/test_ftconv

echo; echo "########## MASK-IDENTITY FUZZ (client lfn_leaf2fcb == server lfn_mask2fcb) ##########"
# extract the REAL implementations from both trees so drift fails the build
awk '/^static unsigned char lfn_upc/,/^}/'   client/src/ETHERDFS.C  > /tmp/maskcmp_gen.c
awk '/^static void lfn_leaf2fcb/,/^}/'       client/src/ETHERDFS.C >> /tmp/maskcmp_gen.c
awk '/^void filename2fcb/,/^}/'              fs.c                   > /tmp/maskcmp_srv.c
awk '/^static void lfn_mask2fcb/,/^}/'       ethersrv.c            >> /tmp/maskcmp_srv.c
cp tests/test_maskcmp.c /tmp/
gcc /tmp/test_maskcmp.c -o /tmp/test_maskcmp -O2 -I/tmp
/tmp/test_maskcmp
