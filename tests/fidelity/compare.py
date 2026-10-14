#!/usr/bin/env python3
"""Compare two KDBX files with an independent reader (pykeepass).

Every element of both decrypted XML trees becomes one "path = value" line,
with repeated children keyed by what identifies them (UUID, Key, position).
Attachments compare by content hash, times by the second they name (KDBX 3
writes ISO text, KDBX 4 base64 seconds), booleans by lower case. What is left
after the expected changes (the edited title, its history and times, the
generator, KDBX 3's header hash and binary pool) is a finding.

  compare.py BEFORE AFTER [--password P] [--keyfile K] [--edited JSON]

Prints one JSON object: {ok, lost, changed, added, expected, header}.
"""

import base64
import datetime
import hashlib
import json
import re
import sys

from pykeepass import PyKeePass

EPOCH = datetime.datetime(1, 1, 1, tzinfo=datetime.timezone.utc)
TIME_TAGS = {
    "CreationTime", "LastModificationTime", "LastAccessTime", "ExpiryTime",
    "LocationChanged", "DeletionTime", "DatabaseNameChanged",
    "DatabaseDescriptionChanged", "DefaultUserNameChanged", "MasterKeyChanged",
    "RecycleBinChanged", "EntryTemplatesGroupChanged", "SettingsChanged",
}
DROP = {"Meta/HeaderHash", "Meta/Binaries"}
# defaults a writer may spell out or leave out
DEFAULT_LINES = ("/QualityCheck = true", "/EnableAutoType = null", "/EnableSearching = null",
                 "@Protected = false",
                 # KeePass writes IconID 0 next to a custom icon; 0 is also the default
                 "/IconID = 0")


def norm_time(text):
    if not text:
        return ""
    try:
        if "-" in text:
            t = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
            return t.strftime("%Y-%m-%dT%H:%M:%SZ")
        secs = int.from_bytes(base64.b64decode(text), "little")
        return (EPOCH + datetime.timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        return "raw:" + text


def norm_text(tag, text):
    # values keep their whitespace: a password or note with spaces must survive
    text = text or ""
    if tag != "Value":
        text = text.strip()
    if tag in TIME_TAGS:
        return norm_time(text)
    if text in ("True", "False", "true", "false"):
        return text.lower()
    return text


def child_id(el, index, in_history):
    tag = el.tag
    if tag in ("Group", "Entry") and not in_history:
        return "%s[%s]" % (tag, el.findtext("UUID"))
    if tag == "Entry":
        return "Entry[h%d %s]" % (index, norm_time(el.findtext("Times/LastModificationTime")))
    if tag in ("String", "Binary", "Item"):
        return "%s[%s]" % (tag, el.findtext("Key"))
    if tag in ("Icon", "DeletedObject"):
        return "%s[%s]" % (tag, el.findtext("UUID"))
    return "%s[%d]" % (tag, index)


def flatten(kp):
    pool = []
    try:
        pool = list(kp.binaries)
    except Exception:  # noqa: BLE001 — a file without a pool
        pass
    lines = set()

    def walk(el, path, in_history):
        counts = {}
        for child in el:
            if not isinstance(child.tag, str):
                continue
            i = counts.get(child.tag, 0)
            counts[child.tag] = i + 1
            cpath = path + "/" + child_id(child, i, in_history)
            bare = re.sub(r"\[[^\]]*\]", "", path + "/" + child.tag).lstrip("/")
            if bare in DROP:
                continue
            for k, v in sorted(child.attrib.items()):
                if k == "Ref":
                    try:
                        v = "sha256:" + hashlib.sha256(pool[int(v)]).hexdigest()[:16]
                    except (IndexError, ValueError):
                        v = "dangling:" + v
                elif v in ("True", "False", "true", "false"):
                    v = v.lower()
                line = "%s@%s = %s" % (cpath, k, v)
                if not any(line.replace("[0]", "").endswith(d) for d in DEFAULT_LINES):
                    lines.add(line)
            if len(child):
                walk(child, cpath, in_history or child.tag == "History")
                continue
            value = norm_text(child.tag, child.text)
            # an empty optional element is the same as no element; a String
            # or Binary Value stays, empty or not (its Key line says it exists)
            if value == "" and child.tag != "Value":
                continue
            if child.tag == "Tags":
                value = ";".join(sorted(t.strip() for t in value.replace(",", ";").split(";") if t.strip()))
            line = "%s = %s" % (cpath, value)
            if any(line.replace("[0]", "").endswith(d) for d in DEFAULT_LINES):
                continue
            lines.add(line)

    walk(kp.tree.getroot(), "", False)
    return lines


def header(kp):
    out = {"version": "%d.%d" % kp.version, "cipher": kp.encryption_algorithm,
           "kdf": kp.kdf_algorithm}
    try:
        dh = kp.kdbx.header.value.dynamic_header
        out["compression"] = str(dh.compression_flags.data)
        if kp.version >= (4, 0) and "public_custom_data" in dh:
            out["public_custom_data"] = str(dh.public_custom_data.data)
    except Exception:  # noqa: BLE001
        pass
    return out


def expected(line, edited):
    if line.startswith("/Meta/Generator"):
        return True
    if not edited:
        return False
    mine = "/Entry[%s]" % edited["uuid_b64"]
    if mine not in line:
        return False
    rest = re.sub(r"\[\d+\]", "", line.split(mine, 1)[1])
    return (rest.startswith("/History/")
            or rest.startswith("/String[Title]/Value")
            or rest.startswith("/Times/LastModificationTime")
            or rest.startswith("/Times/LastAccessTime"))


def main(argv):
    before, after = argv[1], argv[2]
    opt = {k: argv[i + 1] for i, k in enumerate(argv) if k.startswith("--") and i + 1 < len(argv)}
    pw, kf = opt.get("--password"), opt.get("--keyfile")
    edited = json.loads(opt["--edited"]) if opt.get("--edited") not in (None, "null") else None
    if edited:
        import uuid
        edited["uuid_b64"] = base64.b64encode(uuid.UUID(edited["uuid"]).bytes).decode()

    a, b = PyKeePass(before, password=pw, keyfile=kf), PyKeePass(after, password=pw, keyfile=kf)
    la, lb = flatten(a), flatten(b)
    only_a, only_b = la - lb, lb - la

    def key(line):
        return line.split(" = ", 1)[0]

    ka = {key(x): x for x in only_a}
    kb = {key(x): x for x in only_b}
    changed = sorted("%s  ->  %s" % (ka[k], kb[k].split(" = ", 1)[1]) for k in ka.keys() & kb.keys())
    lost = sorted(ka[k] for k in ka.keys() - kb.keys())
    added = sorted(kb[k] for k in kb.keys() - ka.keys())

    exp = [x for x in changed + lost + added if expected(x, edited)]
    changed = [x for x in changed if not expected(x, edited)]
    lost = [x for x in lost if not expected(x, edited)]
    added = [x for x in added if not expected(x, edited)]

    title_ok = True
    if edited:
        e = b.find_entries(uuid=__import__("uuid").UUID(edited["uuid"]), first=True)
        title_ok = bool(e) and e.title == edited["new_title"]

    print(json.dumps({
        "ok": not lost and not changed and not added and title_ok,
        "title_edit_landed": title_ok,
        "lost": lost, "changed": changed, "added": added, "expected": sorted(exp),
        "header": {"before": header(a), "after": header(b)},
        "lines": {"before": len(la), "after": len(lb)},
    }, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main(sys.argv)
