#!/bin/sh
# Phase-1 LFN regression tests for the EtherDFS server.
# Runs in an ephemeral Alpine container (no host toolchain install needed):
#   sudo docker run --rm -v "$(git rev-parse --show-toplevel)":/src -w /src/tests \
#        alpine:latest sh tests/run.sh        # (from repo root, adjust -w as needed)
# Or simply, from the repo root on a TrueNAS host:
#   sudo docker run --rm -v "$PWD":/src -w /src alpine:latest sh tests/run.sh
set -e
cd "$(dirname "$0")/.."   # repo root (server sources live here)
apk add --no-cache gcc musl-dev linux-headers libpcap-dev >/dev/null 2>&1 || true

echo "=== compiling test_lfn (fs.c unit test) ==="
gcc tests/test_lfn.c fs.c -o /tmp/test_lfn -O2 -Wall -std=gnu89 -Wno-long-long -I.

echo "=== compiling test_proto (process() wire test; includes ethersrv.c) ==="
gcc tests/test_proto.c fs.c lock.c -o /tmp/test_proto -O2 -std=gnu89 -Wno-long-long -lpcap -I.

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

echo; echo "########## WIRE / process() TEST (ethersrv.c) ##########"
/tmp/test_proto "$FIX"

cd "$(dirname "$0")/.."  # back to repo root

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
