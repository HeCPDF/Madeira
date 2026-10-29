#!/usr/bin/env bash
# .github/ci/fetch-vcruntime.sh -- fetch Microsoft's 14 x64 VC++ runtime DLLs.
#
# Why this exists next to tools/fetch-vcruntime.sh: upstream's helper expects
# the redistributable to carry *.cab files in its resource section
# (`find ... -iname '*.cab'`). The current vc_redist.x64.exe is a WiX Burn
# bundle whose payload sits in an attached cabinet container, so that find
# matches nothing and the helper stops with "no cab files found in installer".
# Everything below still ends with the same guarantee: 14 files, byte-identical
# to Microsoft's, into app/Madeira/x86_64-vcruntime/, then upstream's own
# tests/host/check-vcruntime.py --strict must pass.
#
#   bash .github/ci/fetch-vcruntime.sh
#
# The redistributable ships every architecture side by side, and the ARM64
# copies of these DLLs are ARM64X hybrids whose PE machine field is 0x8664 (the
# same as x64), so a machine check alone happily accepts one. Selection below
# is therefore by name first: `_amd64` wins, exact name next, and any
# `_arm64`/`_arm64x`/`_arm64ec`/`_x86` sibling is rejected outright. Among
# equals, the directory that holds the most of the 14 wins -- the payload cab
# holds twelve, the MFC cab two, and stray copies from other packages hold one.
#
# Environment:
#   VC_REDIST_URL     override the download URL (default aka.ms x64)
#   VC_REDIST_SHA256  if set, the downloaded installer must match this digest
#   VC_RUNTIME_DEST   override the output directory
#
# Requires: curl, cabextract (brew install cabextract), python3.
# Does not modify the DLLs and never writes them into git's index.
set -euo pipefail

R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="${VC_RUNTIME_DEST:-$R/app/Madeira/x86_64-vcruntime}"
URL="${VC_REDIST_URL:-https://aka.ms/vs/17/release/vc_redist.x64.exe}"

WANT="concrt140.dll msvcp140.dll msvcp140_1.dll msvcp140_2.dll msvcp140_atomic_wait.dll
msvcp140_codecvt_ids.dll vcamp140.dll vccorlib140.dll vcomp140.dll vcruntime140.dll
vcruntime140_1.dll vcruntime140_threads.dll mfc140.dll mfc140u.dll"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/madeira-vcrt.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

note() { echo "fetch-vcruntime: $*"; }
die() { echo "fetch-vcruntime: error: $*" >&2; exit 1; }

command -v cabextract >/dev/null 2>&1 || die "cabextract not found (brew install cabextract)"
command -v python3 >/dev/null 2>&1 || die "python3 not found"

note "downloading $URL"
curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "$WORK/vc_redist.x64.exe" "$URL"
if [ -n "${VC_REDIST_SHA256:-}" ]; then
    echo "$VC_REDIST_SHA256  $WORK/vc_redist.x64.exe" | shasum -a 256 -c - || die "installer digest mismatch"
fi
note "installer sha256 $(shasum -a 256 "$WORK/vc_redist.x64.exe" | awk '{print $1}')"

# 1. The attached container itself: cabextract finds the MSCF cabinet that
#    7-Zip's resource view does not surface as a .cab.
mkdir -p "$WORK/x1"
cabextract -q -d "$WORK/x1" "$WORK/vc_redist.x64.exe" || note "note: outer cabinet extraction returned non-zero"

# 2. Burn's payload is a cabinet of cabinets; unwrap anything that is not a DLL
#    until a pass adds nothing new (cabinets and MSIs, up to 4 levels).
for pass in 1 2 3 4; do
    before=$(find "$WORK" -type f \( -iname '*_amd64' -o -iname '*_arm64' -o -iname '*.dll*' \) | wc -l | tr -d ' ')
    find "$WORK" -type f -size +20k \
        ! -iname '*.dll' ! -iname '*.dll_*' ! -iname '*.exe' ! -name '*.log' \
        | while IFS= read -r f; do
            d="$f.d"
            [ -d "$d" ] && continue
            mkdir -p "$d"
            if cabextract -q -d "$d" "$f" >/dev/null 2>&1; then :
            elif command -v msiextract >/dev/null 2>&1 && msiextract -C "$d" "$f" >/dev/null 2>&1; then :
            else rmdir "$d" 2>/dev/null || true
            fi
        done
    after=$(find "$WORK" -type f \( -iname '*_amd64' -o -iname '*_arm64' -o -iname '*.dll*' \) | wc -l | tr -d ' ')
    note "pass $pass: $after candidate file(s) (was $before)"
    [ "$after" -gt "$before" ] || break
done

# 3. Verify and copy. Each wanted DLL must be the x64 build: `_amd64` naming
#    preferred, ARM siblings rejected, PE machine 0x8664 and PE32+, and the
#    version resource must still name the file itself.
mkdir -p "$DEST"
python3 - "$WORK" "$DEST" $WANT <<'PY'
import hashlib
import os
import shutil
import struct
import sys

work, dest = sys.argv[1], sys.argv[2]
want = sys.argv[3:]
other_arch = ("_arm64", "_arm64x", "_arm64ec", "_x86", "_arm64ec64")


def pe_facts(path):
    try:
        with open(path, "rb") as f:
            d = f.read()
    except OSError:
        return None
    if len(d) < 0x40 or d[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    if pe + 0x100 > len(d) or d[pe:pe + 4] != b"PE\0\0":
        return None
    machine = struct.unpack_from("<H", d, pe + 4)[0]
    magic = struct.unpack_from("<H", d, pe + 24)[0]
    off, size = struct.unpack_from("<II", d, pe + 24 + 112 + 4 * 8)
    signed = bool(size and off and off + size <= len(d))
    return {"data": d, "machine": machine, "magic": magic, "signed": signed}


def version_name(d):
    """OriginalFilename from the VS_VERSIONINFO resource, lower-cased, or None."""
    key = "OriginalFilename".encode("utf-16-le")
    i = d.find(key)
    if i < 0:
        return None
    seg = d[i:i + 512].decode("utf-16-le", "replace")
    for token in seg.split("\x00"):
        token = token.strip()
        if token.lower().endswith(".dll"):
            return token.lower()
    return None


def name_rank(fn, name):
    """0 = the x64 build's own file, 1 = the exact name, 2 = other spelling, None = reject."""
    if fn == name + "_amd64":
        return 0
    if fn == name:
        return 1
    # any other suffix naming the same DLL, but never another architecture
    if fn.startswith(name + "_"):
        suffix = fn[len(name):].split("_", 1)[1]
        if any(suffix == a[1:] for a in other_arch):
            return None
        return 2
    if fn.startswith("f_central_" + name[:-4] + "_"):
        if any(fn.endswith(a) for a in other_arch):
            return None
        return 2
    return None


candidates = []
for root, _dirs, files in os.walk(work):
    for fn in files:
        path = os.path.join(root, fn)
        facts = pe_facts(path)
        if facts is None or facts["machine"] != 0x8664 or facts["magic"] != 0x20B:
            continue
        candidates.append((path, fn.lower(), facts))

# Directory completeness: the main payload cab carries most of the 14.
dir_score = {}
for path, fn, _facts in candidates:
    d = os.path.dirname(path)
    dir_score.setdefault(d, set())
    for name in want:
        if name_rank(fn, name) is not None:
            dir_score[d].add(name)
scores = {d: len(names) for d, names in dir_score.items()}

missing, bad, rows = [], [], []
for name in want:
    ranked = []
    for path, fn, facts in candidates:
        rank = name_rank(fn, name)
        if rank is None:
            continue
        vname = version_name(facts["data"])
        if vname is not None and vname != name:
            bad.append((os.path.basename(path), name, "version resource names %s" % vname))
            continue
        ranked.append((rank, -scores.get(os.path.dirname(path), 0), len(facts["data"]), path, facts))
    if not ranked:
        missing.append(name)
        continue
    ranked.sort(key=lambda r: (r[0], r[1], r[2]))
    rank, _neg, _size, path, facts = ranked[0]
    shutil.copyfile(path, os.path.join(dest, name))
    rows.append((name, len(facts["data"]), facts["signed"],
                 hashlib.sha256(facts["data"]).hexdigest(), os.path.basename(path), rank))

for name, size, signed, digest, src, rank in rows:
    print("  %-30s %9d bytes  signed=%-5s from=%-34s sha256=%s"
          % (name, size, signed, src, digest))

if bad:
    print("", file=sys.stderr)
    for fn, wantname, why in bad:
        print("  rejected %s for %s: %s" % (fn, wantname, why), file=sys.stderr)
if missing:
    print("", file=sys.stderr)
    for name in missing:
        print("  missing %s" % name, file=sys.stderr)
    sys.exit(1)
unsigned = [r[0] for r in rows if not r[2]]
if unsigned:
    print("  missing Authenticode payload: %s" % ", ".join(unsigned), file=sys.stderr)
    sys.exit(1)
print("fetch-vcruntime: %d/%d files staged in %s" % (len(rows), len(want), dest))
PY

# 4. The project's own gate: signature payload, PE32+, all 14 present.
python3 "$R/tests/host/check-vcruntime.py" --strict
