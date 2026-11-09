#!/usr/bin/env python3
"""render.py — render layer of the artifacts publisher.

Converts markdown to HTML (house style), passes .html through, copies the rest,
and generates an index.html for the run (the bucket is never listable).

Usage: render.py --dir <outdir> --run <run> --audience <pub|users|slug> --ttl <days> <file>...
Output: one line per file to upload:  <local_path>\t<content_type>\t<served_name>
(including the index.html line).
"""
import argparse
import datetime
import html
import os
import subprocess
import sys

STYLE = """body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:14px;color:#1f1f1f;line-height:1.55;max-width:860px;margin:24px auto;padding:0 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin-top:28px}h3{font-size:15px}
pre{background:#f3f4f6;padding:10px;border-radius:6px;overflow:auto;font-size:12.5px}
code{background:#f3f4f6;padding:1px 4px;border-radius:4px;font-size:12.5px}
pre code{padding:0;background:none}
table{border-collapse:collapse;margin:12px 0}th,td{border:1px solid #d1d5db;padding:6px 10px;text-align:left}th{background:#f3f4f6}
a{color:#1a73e8}blockquote{border-left:3px solid #d1d5db;margin:12px 0;padding:2px 14px;color:#4b5563}
.meta{color:#6b7280;font-size:12.5px;margin-bottom:20px}.footer{color:#9ca3af;font-size:12px;margin-top:36px;border-top:1px solid #e5e7eb;padding-top:8px}
.vis{font-size:12.5px;font-weight:600;border-radius:6px;padding:6px 12px;margin:16px auto 0;max-width:860px}
.vis.grp{background:#eff6ff;color:#1e40af;border:1px solid #bfdbfe}.vis.pub{background:#fefce8;color:#854d0e;border:1px solid #fde68a}"""

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>{style}</style></head><body>
<div class="vis {vis_class}">{vis_label}</div>
<h1>{title}</h1>
<div class="meta">run <b>{run}</b> · published by <b>{author}</b> · session <b>{session}</b> · {pub} · <b>expires {exp}</b> (ttl={ttl} d)</div>
{content}
<div class="footer">Published with the artifacts publisher</div>
</body></html>"""


def md_to_html(text):
    try:
        import markdown
    except ImportError:
        sys.exit("python package 'markdown' is missing (pip3 install markdown) "
                 "or upload the file already rendered as .html")
    return markdown.markdown(text, extensions=["tables", "fenced_code", "toc"])


def md_title(text, fallback):
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("# "):
            return s[2:].strip()
    return fallback


def guess_ct(path):
    ct = subprocess.run(["file", "-b", "--mime-type", path],
                        capture_output=True, text=True).stdout.strip()
    if ct.startswith("text/"):
        ct += "; charset=utf-8"
    return ct


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--audience", required=True,
                    help="pub | users | <group slug> (drives the visibility banner only)")
    ap.add_argument("--ttl", required=True, type=int)
    ap.add_argument("--author", default="unknown")
    ap.add_argument("--session", default="no-id")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()

    if a.audience == "pub":
        vis_label, vis_class = ("PUBLIC — anyone who can reach the host opens it without login", "pub")
    elif a.audience == "users":
        vis_label, vis_class = ("USERS — only the people listed in the run ACL (requires login)", "grp")
    else:
        vis_label, vis_class = (f"GROUP {a.audience} — only members of the configured group (requires login)", "grp")
    now = datetime.datetime.now()
    pub = now.strftime("%Y-%m-%d %H:%M")
    exp = (now + datetime.timedelta(days=a.ttl)).strftime("%Y-%m-%d")
    os.makedirs(a.dir, exist_ok=True)

    manifest = []  # (local_path, content_type, served_name)
    for src in a.files:
        base = os.path.basename(src)
        if base == "index.html":
            sys.exit("do not publish a file named index.html; it is reserved for the run index")
        ext = os.path.splitext(base)[1].lower()
        if ext in (".md", ".markdown"):
            text = open(src, encoding="utf-8").read()
            body = md_to_html(text)
            title = md_title(text, base)
            out = os.path.join(a.dir, os.path.splitext(base)[0] + ".html")
            open(out, "w", encoding="utf-8").write(
                PAGE.format(title=html.escape(title), style=STYLE, run=html.escape(a.run),
                            pub=pub, exp=exp, ttl=a.ttl,
                            author=html.escape(a.author), session=html.escape(a.session),
                            vis_label=html.escape(vis_label), vis_class=vis_class, content=body))
            manifest.append((out, "text/html; charset=utf-8", os.path.basename(out)))
        elif ext == ".html":
            out = os.path.join(a.dir, base)
            open(out, "wb").write(open(src, "rb").read())
            manifest.append((out, "text/html; charset=utf-8", base))
        else:
            out = os.path.join(a.dir, base)
            open(out, "wb").write(open(src, "rb").read())
            manifest.append((out, guess_ct(src), base))

    rows = "\n".join(
        f'<tr><td><a href="{html.escape(name)}">{html.escape(name)}</a></td><td>{html.escape(ct)}</td></tr>'
        for _, ct, name in sorted(manifest, key=lambda m: m[2]))
    idx = os.path.join(a.dir, "index.html")
    open(idx, "w", encoding="utf-8").write(
        PAGE.format(title=f"Run {a.run}", style=STYLE, run=html.escape(a.run),
                    pub=pub, exp=exp, ttl=a.ttl,
                    author=html.escape(a.author), session=html.escape(a.session),
                    vis_label=html.escape(vis_label), vis_class=vis_class,
                    content=f"<p>Files in this run:</p><table><tr><th>File</th><th>Type</th></tr>{rows}</table>"))
    manifest.append((idx, "text/html; charset=utf-8", "index.html"))

    for path, ct, name in manifest:
        print(f"{path}\t{ct}\t{name}")


if __name__ == "__main__":
    main()
