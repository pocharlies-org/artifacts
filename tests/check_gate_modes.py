#!/usr/bin/env python3
"""Render the chart in both gate code modes and assert the exact difference (needs helm).

    python3 -I tests/check_gate_modes.py        # HELM=/path/to/helm to pick another binary

ConfigMap mode (gate.bakedImage=false, the default) and baked-image mode (true) must differ in the
gate Deployment only: the image line, and the `code` volume, its mount and the ConfigMap reference,
which exist only in ConfigMap mode. Baked mode takes the image as <repository>@sha256:<digest> and
the chart refuses a missing or malformed digest, a tagged repository and a non-boolean switch.
"""
import difflib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHART = os.path.join(ROOT, "helm", "artifacts")
VALUES = os.path.join(CHART, "values.yaml")
HELM = os.environ.get("HELM", "helm")
DIGEST = "sha256:" + "0123456789abcdef" * 4
REPO = "ghcr.io/pocharlies-org/artifacts-gate"


def render(*args):
    p = subprocess.run([HELM, "template", "t", CHART, "-f", VALUES, *args],
                       capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def ok_render(*args):
    rc, out, err = render(*args)
    if rc != 0:
        sys.exit(f"FAIL: helm template {' '.join(args)} exited {rc}: {err.strip()}")
    return out


def gate_deployment(text):
    docs = [d for d in text.split("\n---\n")
            if "\nkind: Deployment\n" in d and "\n  name: artifact-gate\n" in d]
    if len(docs) != 1:
        sys.exit(f"FAIL: expected one artifact-gate Deployment, found {len(docs)}")
    return docs[0]


def image_line(doc):
    lines = [ln.strip() for ln in doc.splitlines() if ln.strip().startswith("image: ")]
    if len(lines) != 1:
        sys.exit(f"FAIL: expected one image line in the gate Deployment, found {lines}")
    return lines[0]


def check(cond, msg):
    if not cond:
        sys.exit("FAIL: " + msg)
    print("ok:", msg)


configmap = ok_render()
baked = ok_render("--set", "gate.bakedImage=true", "--set", f"gate.bakedImageDigest={DIGEST}")

cm_gate, baked_gate = gate_deployment(configmap), gate_deployment(baked)
check("name: artifact-gate-code" in cm_gate and "- {name: code, mountPath: /app, readOnly: true}" in cm_gate,
      "ConfigMap mode (default) mounts ConfigMap artifact-gate-code as volume code at /app")
check(image_line(baked_gate) == f"image: {REPO}@{DIGEST}",
      f"baked mode image is {REPO}@<digest> (no tag)")
check("artifact-gate-code" not in baked and "configMap:" not in baked_gate
      and "name: code" not in baked_gate,
      "baked mode renders no code volume, no mount and no ConfigMap reference")

# The whole difference between the two renders, line by line.
diff = [d for d in difflib.ndiff(configmap.splitlines(), baked.splitlines()) if d[:2] in ("- ", "+ ")]
removed = sorted(d[2:].strip() for d in diff if d.startswith("- "))
added = sorted(d[2:].strip() for d in diff if d.startswith("+ "))
check(removed == sorted([image_line(cm_gate), "- {name: code, mountPath: /app, readOnly: true}",
                         "- name: code", "configMap:", "name: artifact-gate-code",
                         "defaultMode: 0444"]),
      "baked mode removes exactly the ConfigMap image, the code mount and the code volume")
check(added == [f"image: {REPO}@{DIGEST}"], "baked mode adds exactly the digest image line")

check(ok_render("--set", "gate.bakedImage=false", "--set", "gate.bakedImageDigest=not-a-digest") == configmap,
      "bakedImage=false ignores the baked image settings (render equals the default)")
mirror = "registry.example.com:5000/mirror/artifacts-gate"
check(image_line(gate_deployment(ok_render(
          "--set", "gate.bakedImage=true", "--set", f"gate.bakedImageRepository={mirror}",
          "--set", f"gate.bakedImageDigest={DIGEST}"))) == f"image: {mirror}@{DIGEST}",
      "baked mode accepts a mirror repository with a registry port")

refusals = [
    (("--set", "gate.bakedImage=true"), "gate.bakedImageDigest"),
    (("--set", "gate.bakedImage=true", "--set", "gate.bakedImageDigest=sha256:abc"), "gate.bakedImageDigest"),
    (("--set", "gate.bakedImage=true", "--set", "gate.bakedImageDigest=" + DIGEST.upper()), "gate.bakedImageDigest"),
    (("--set", "gate.bakedImage=true", "--set", "gate.bakedImageDigest=" + DIGEST[7:]), "gate.bakedImageDigest"),
    (("--set", "gate.bakedImage=true", "--set", f"gate.bakedImageDigest={DIGEST}",
      "--set", f"gate.bakedImageRepository={REPO}:latest"), "gate.bakedImageRepository"),
    (("--set", "gate.bakedImage=true", "--set", f"gate.bakedImageDigest={DIGEST}",
      "--set", f"gate.bakedImageRepository={REPO}@{DIGEST}"), "gate.bakedImageRepository"),
    (("--set", "gate.bakedImage=true", "--set", f"gate.bakedImageDigest={DIGEST}",
      "--set", "gate.bakedImageRepository="), "gate.bakedImageRepository"),
    # characters: only a repository reference reaches the Deployment (no newline, space,
    # quote or upper case)
    (("--set", "gate.bakedImage=true", "--set", f"gate.bakedImageDigest={DIGEST}",
      "--set-json", 'gate.bakedImageRepository="ghcr.io/x/gate\\n          command: [sh]"'),
     "gate.bakedImageRepository"),
    (("--set", "gate.bakedImage=true", "--set", f"gate.bakedImageDigest={DIGEST}",
      "--set", "gate.bakedImageRepository=ghcr.io/x/gate other"), "gate.bakedImageRepository"),
    (("--set", "gate.bakedImage=true", "--set", f"gate.bakedImageDigest={DIGEST}",
      "--set", 'gate.bakedImageRepository=ghcr.io/x/gate"'), "gate.bakedImageRepository"),
    (("--set", "gate.bakedImage=true", "--set", f"gate.bakedImageDigest={DIGEST}",
      "--set", "gate.bakedImageRepository=ghcr.io/X/gate"), "gate.bakedImageRepository"),
    (("--set-string", "gate.bakedImage=true"), "gate.bakedImage must be a boolean"),
    (("--set-string", "gate.bakedImage=false"), "gate.bakedImage must be a boolean"),
]
for args, needle in refusals:
    rc, _, err = render(*args)
    check(rc != 0 and needle in err, f"refused: {' '.join(args)}")
print("gate modes: all checks passed")
