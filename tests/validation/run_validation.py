#!/usr/bin/env python3
"""
run_validation.py — TRL10 validation harness for the Khepra security detector.

This replaces the previous grep-for-the-marker smoke test. It drives the REAL
detector (detector.py) over labelled fixtures and asserts BOTH failure modes:

  * every fixture under fixtures/fail/<category>/  MUST be flagged  (no false negatives)
  * every fixture under fixtures/pass/<category>/  MUST be clean    (no false positives)
  * a flagged fail-fixture whose category is known MUST be flagged for the RIGHT reason

It prints a confusion matrix with precision/recall and exits non-zero on ANY
false negative or false positive, or if there are no fixtures (guards a silent no-op).
"""
import os
import sys
import glob

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import detector  # noqa: E402

# fail-fixture directory name -> category the detector must report.
CATEGORY_MAP = {
    "hardcoded_keys": "secret",
    "exposed_secrets": "secret",
    "sql_injection": "sql_injection",
    "command_injection": "command_injection",
    "weak_crypto": "weak_crypto",
}

C = {
    "g": "\033[0;32m", "r": "\033[0;31m", "y": "\033[1;33m",
    "b": "\033[0;34m", "n": "\033[0m",
}


def fixtures(kind):
    # Layout-agnostic: supports nested (fixtures/fail/<cat>/*.go) and flat
    # (fixtures/fail/*.go) fixture trees.
    base = os.path.join(HERE, "fixtures", kind)
    out = set()
    for ext in ("go", "ts", "js", "py"):
        out.update(glob.glob(os.path.join(base, "**", f"*.{ext}"), recursive=True))
        out.update(glob.glob(os.path.join(base, f"*.{ext}")))
    return sorted(out)


def category_of(path):
    parent = os.path.basename(os.path.dirname(path))
    if parent in ("fail", "pass"):  # flat layout → derive from filename stem
        return os.path.splitext(os.path.basename(path))[0]
    return parent


def main():
    print(f"{C['b']}╔════════════════════════════════════════════════════════════╗{C['n']}")
    print(f"{C['b']}║      Khepra Protocol — TRL10 Detector Validation Suite     ║{C['n']}")
    print(f"{C['b']}╚════════════════════════════════════════════════════════════╝{C['n']}\n")

    fail_fx = fixtures("fail")
    pass_fx = fixtures("pass")

    if not fail_fx or not pass_fx:
        print(f"{C['r']}✗ No fixtures discovered (fail={len(fail_fx)}, pass={len(pass_fx)}). "
              f"A validation suite with nothing to validate is a silent no-op.{C['n']}")
        return 2

    tp = fn = tn = fp = 0
    wrong_cat = 0

    print(f"{C['b']}[1/2] Vulnerable fixtures — the detector MUST flag each{C['n']}")
    print("-" * 60)
    for path in fail_fx:
        rel = os.path.relpath(path, HERE)
        cats = {c for (c, _r, _l, _m) in detector.scan(path)}
        expected = CATEGORY_MAP.get(category_of(path))
        if cats:
            tp += 1
            if expected and expected not in cats:
                wrong_cat += 1
                print(f"  {C['y']}⚠ FLAGGED (wrong category){C['n']} {rel} "
                      f"→ got {sorted(cats)}, expected '{expected}'")
            else:
                print(f"  {C['g']}✓ detected{C['n']} {rel} → {sorted(cats)}")
        else:
            fn += 1
            print(f"  {C['r']}✗ MISSED (false negative){C['n']} {rel}")

    print(f"\n{C['b']}[2/2] Safe fixtures — the detector MUST NOT flag any{C['n']}")
    print("-" * 60)
    for path in pass_fx:
        rel = os.path.relpath(path, HERE)
        findings = detector.scan(path)
        if not findings:
            tn += 1
            print(f"  {C['g']}✓ clean{C['n']} {rel}")
        else:
            fp += 1
            detail = ", ".join(f"{c}:{ln}" for (c, _r, ln, _m) in findings)
            print(f"  {C['r']}✗ FALSE POSITIVE{C['n']} {rel} → {detail}")

    total = tp + fn + tn + fp
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0

    print(f"\n{C['b']}╔════════════════════════════════════════════════════════════╗{C['n']}")
    print(f"{C['b']}║                     Confusion Matrix                       ║{C['n']}")
    print(f"{C['b']}╚════════════════════════════════════════════════════════════╝{C['n']}\n")
    print(f"  Vulnerable fixtures : {len(fail_fx)}   (true positives {tp}, false negatives {fn})")
    print(f"  Safe fixtures       : {len(pass_fx)}   (true negatives {tn}, false positives {fp})")
    print(f"  Wrong-category flags: {wrong_cat}")
    print(f"  Precision           : {precision:.3f}")
    print(f"  Recall              : {recall:.3f}\n")

    ok = (fn == 0 and fp == 0 and wrong_cat == 0)
    if ok:
        print(f"{C['g']}✓ TRL10 PASS — {total} fixtures, no false negatives, "
              f"no false positives, all categories correct.{C['n']}")
        return 0
    print(f"{C['r']}✗ VALIDATION FAILED — "
          f"{fn} missed vuln(s), {fp} false positive(s), {wrong_cat} wrong-category.{C['n']}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
