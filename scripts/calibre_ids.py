#!/usr/bin/env python3
"""Map KOReader sync document ids to titles using a Calibre content server.

    CALIBRE_PASS=... python3 scripts/calibre_ids.py URL USER [--out labels.json]

The sync server only knows a document id, which KOReader computes on the
device as a partial MD5 of the file (see partial_md5 below). This computes the
same id for every book the content server offers, using HTTP range requests so
only about a dozen 1 KB samples are fetched per book, and writes
{"<id>": "Title - Author"} as JSON. Read-only: it only issues GET requests.

Ids only match when the file on the device is byte-identical to the one Calibre
serves. Anything converted or rewritten in transit will not match.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# KOReader hashes 1024 bytes at offsets 1024 << (2 * i) for i = -1 .. 10. The
# i = -1 shift wraps to 0 in LuaJIT, so the first sample is the file start.
OFFSETS = [0] + [1024 << (2 * i) for i in range(0, 11)]
FORMAT_ORDER = ["epub", "kepub", "mobi", "azw3", "pdf", "cbz", "fb2", "djvu"]


def client(base, user, password):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": "Basic " + token}

    def get(path, extra=None, timeout=60):
        req = urllib.request.Request(base + path, headers={**headers, **(extra or {})})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()

    return get


def partial_md5(get, path):
    """The document id for the file at `path`, or None if ranges are unsupported."""
    md5 = hashlib.md5()
    for offset in OFFSETS:
        try:
            status, sample = get(path, {"Range": f"bytes={offset}-{offset + 1023}"})
        except urllib.error.HTTPError as err:
            if err.code == 416:  # past the end of the file
                break
            raise
        if status != 206:
            return None
        if not sample:
            break
        md5.update(sample)
    return md5.hexdigest()


def pick_format(formats):
    lowered = [f.lower() for f in formats]
    for wanted in FORMAT_ORDER:
        if wanted in lowered:
            return wanted
    return lowered[0] if lowered else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("url", help="content server base URL, e.g. https://calibre.example.com")
    ap.add_argument("user")
    ap.add_argument("--out", default="labels.json")
    ap.add_argument("--library", default="library")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, help="only the first N books (for a trial run)")
    args = ap.parse_args()

    password = os.environ.get("CALIBRE_PASS")
    if not password:
        sys.exit("Set CALIBRE_PASS in the environment.")
    base = args.url.rstrip("/")
    get = client(base, args.user, password)
    lib = f"library_id={args.library}"

    _, body = get(f"/ajax/search?num=100000&{lib}")
    ids = json.loads(body)["book_ids"]
    if args.limit:
        ids = ids[: args.limit]

    books = {}
    for start in range(0, len(ids), 100):
        chunk = ids[start:start + 100]
        _, body = get("/ajax/books?ids=" + ",".join(map(str, chunk)) + f"&{lib}")
        books.update(json.loads(body))

    def one(book_id):
        meta = books.get(str(book_id))
        fmt = pick_format(meta["formats"]) if meta else None
        if not fmt:
            return book_id, None, None, "no format"
        label = meta["title"]
        if meta.get("authors"):
            label += " - " + ", ".join(meta["authors"])
        try:
            doc = partial_md5(get, f"/get/{fmt}/{book_id}/{args.library}")
        except Exception as err:
            return book_id, None, label, str(err)
        return book_id, doc, label, None if doc else "server ignored Range"

    labels, problems = {}, []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for book_id, doc, label, problem in pool.map(one, ids):
            if problem:
                problems.append((book_id, label, problem))
            else:
                labels[doc] = label

    with open(args.out, "w") as f:
        json.dump(labels, f, indent=1, ensure_ascii=False, sort_keys=True)
    print(f"{len(labels)} of {len(ids)} books written to {args.out}", file=sys.stderr)
    for book_id, label, problem in problems[:20]:
        print(f"  skipped {book_id} {label or ''}: {problem}", file=sys.stderr)


if __name__ == "__main__":
    main()
