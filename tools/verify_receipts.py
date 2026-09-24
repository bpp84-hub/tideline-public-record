#!/usr/bin/env python3
"""Verify Tideline's RFC 3161 timestamp receipts against their ledger fingerprints.

Standard library + the `openssl` command line tool. For every fingerprint in
data/fingerprints.json it downloads each .tsr receipt from tideline.jbpscapital.com
and runs:  openssl ts -verify -digest <manifest_sha256> -in <receipt> -CAfile <roots>
A receipt proves the fingerprint existed no later than its signed time.
"""
import argparse, json, shutil, subprocess, sys, tempfile, urllib.request
from pathlib import Path

ORIGIN = "https://tideline.jbpscapital.com"
ROOT = Path(__file__).resolve().parents[1]
CAFILES = ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--offline", action="store_true", help="only check the local fingerprint file; download nothing")
    ap.add_argument("--cafile", help="trusted root bundle (default: the system bundle)")
    args = ap.parse_args()
    feed = json.loads((ROOT / "data" / "fingerprints.json").read_text())
    entries = feed.get("entries", [])
    print(f"{len(entries)} fingerprints in data/fingerprints.json")
    bad = [e for e in entries if len(e.get("manifest_sha256", "")) != 64]
    if bad:
        print(f"FAIL: {len(bad)} entries without a 64-hex manifest_sha256")
        return 1
    if args.offline:
        print("offline: fingerprint file is well-formed")
        return 0
    openssl = shutil.which("openssl")
    cafile = args.cafile or next((c for c in CAFILES if Path(c).exists()), None)
    if not openssl or not cafile:
        print("FAIL: need the openssl command and a root certificate bundle (--cafile)")
        return 1
    ok = fail = 0
    with tempfile.TemporaryDirectory() as tmp:
        for e in entries:
            for r in e.get("rfc3161", []):
                name = f"{e['bundle']}.{r['tsa']}.tsr"
                path = Path(tmp) / name
                try:
                    with urllib.request.urlopen(f"{ORIGIN}/evidence/{name}", timeout=30) as resp:
                        path.write_bytes(resp.read())
                    p = subprocess.run([openssl, "ts", "-verify", "-digest", e["manifest_sha256"], "-in", str(path), "-CAfile", cafile],
                                       capture_output=True, text=True)
                    good = "Verification: OK" in (p.stdout + p.stderr)
                except Exception as exc:  # network or file problem: report, keep going
                    good, p = False, None
                    print(f"  {name}: error {exc}")
                ok, fail = ok + good, fail + (not good)
                print(f"  {name}: {'OK' if good else 'FAILED'}  (signed {r.get('gen_time')})")
    print(f"{ok} receipts verified, {fail} failed")
    return 0 if fail == 0 and ok > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
