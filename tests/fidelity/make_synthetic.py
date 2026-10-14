#!/usr/bin/env python3
"""Build synth_rich.kdbx: a real KeePassXC 2.7 file (test_db_kdbx41_features)
with everything else other apps put in a safe added by hand — passkeys,
one-time codes, extra URLs, attachments (one shared by two entries), entry
history, custom icons, custom data with times, colours, auto-type windows,
expiry, a recycle bin, deleted objects, KDBX 4.1 elements and elements no
spec knows. Written by pykeepass, which edits the XML tree as it is.

  make_synthetic.py BASE.kdbx PASSWORD OUT.kdbx [UNKNOWN]

UNKNOWN puts one element (or attribute) no spec knows at one place: meta,
group, entry, root or attr. Without it the file has none, so the rest of
the features are tested on their own. "interleaved" skips the reordering
below and keeps pykeepass's own order, where an entry's String fields are
not next to each other (a later notes field lands after AutoType).
"""

import base64
import datetime
import sys
import uuid

from lxml import etree
from pykeepass import PyKeePass

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")


def sub(parent, tag, text=None, **attrs):
    el = etree.SubElement(parent, tag, **attrs)
    if text is not None:
        el.text = text
    return el


def put(parent, tag, text):
    el = parent.find(tag)
    if el is None:
        el = etree.SubElement(parent, tag)
    el.text = text
    return el


ENTRY_ORDER = ["UUID", "IconID", "CustomIconUUID", "ForegroundColor", "BackgroundColor",
               "OverrideURL", "QualityCheck", "Tags", "PreviousParentGroup", "Times",
               "String", "Binary", "AutoType", "CustomData", "History"]


def canonical(tree):
    """KeePass's own element order inside every entry (unknown tags last)"""
    for e in tree.iter("Entry"):
        kids = list(e)
        kids.sort(key=lambda c: ENTRY_ORDER.index(c.tag) if c.tag in ENTRY_ORDER else len(ENTRY_ORDER))
        for c in kids:
            e.remove(c)
            e.append(c)


def b64uuid(u):
    return base64.b64encode(u.bytes).decode()


def main(base, pw, out, unknown=""):
    kp = PyKeePass(base, password=pw)
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    meta = kp.tree.find("Meta")
    root = kp.root_group

    # meta settings other apps set
    put(meta, "DatabaseDescription", "synthetic stress file for ewe-safe")
    put(meta, "DefaultUserName", "sam")
    put(meta, "Color", "#336699")
    put(meta, "MasterKeyChangeRec", "180")
    put(meta, "HistoryMaxItems", "5")
    if unknown == "meta":
        sub(meta, "FutureMetaElement", "meta from a newer app")

    # a custom icon with a 4.1 name and time
    icon_uuid = uuid.uuid4()
    icon = sub(meta.find("CustomIcons"), "Icon")
    sub(icon, "UUID", b64uuid(icon_uuid))
    sub(icon, "Data", base64.b64encode(PNG).decode())
    sub(icon, "Name", "dot")
    sub(icon, "LastModificationTime", kp._encode_time(now))

    # a group with every group-level setting
    g = kp.add_group(root, "Work")
    g.notes = "work logins"
    ge = g._element
    put(ge, "EnableAutoType", "false")
    put(ge, "EnableSearching", "false")
    put(ge, "DefaultAutoTypeSequence", "{USERNAME}{ENTER}")
    sub(ge, "Tags", "office")
    sub(ge, "CustomIconUUID", b64uuid(icon_uuid))
    gcd = sub(ge, "CustomData")
    it = sub(gcd, "Item")
    sub(it, "Key", "ewe.group.flag")
    sub(it, "Value", "yes")
    sub(it, "LastModificationTime", kp._encode_time(now))
    if unknown == "group":
        sub(ge, "FutureGroupElement", "group from a newer app")

    # a login with passkey, otp, extra urls, odd whitespace and non-ascii text
    e = kp.add_entry(g, "Bänk ☃", "sam", "  pass with spaces  ", url="https://bank.example")
    e.notes = "line one\n  line two  \n"
    e.tags = ["money", "app:org.example.Bank"]
    e.otp = "otpauth://totp/Bank:sam?secret=JBSWY3DPEHPK3PXP&issuer=Bank"
    e.set_custom_property("KP2A_URL_1", "https://login.bank.example")
    e.set_custom_property("KP2A_URL_2", "androidapp://com.bank.app")
    e.set_custom_property("KPEX_PASSKEY_CREDENTIAL_ID", "cred-id-abc")
    e.set_custom_property("KPEX_PASSKEY_PRIVATE_KEY_PEM", "-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----", protect=True)
    e.set_custom_property("KPEX_PASSKEY_RELYING_PARTY", "bank.example")
    e.set_custom_property("KPEX_PASSKEY_USERNAME", "sam")
    e.set_custom_property("KPEX_PASSKEY_USER_HANDLE", "aGFuZGxl", protect=True)
    e.set_custom_property("Empty field", "")
    ee = e._element
    put(ee, "ForegroundColor", "#FF0000")
    put(ee, "BackgroundColor", "#00FF00")
    put(ee, "OverrideURL", "cmd://firefox %1")
    sub(ee, "QualityCheck", "False")
    sub(ee, "CustomIconUUID", b64uuid(icon_uuid))
    put(ee, "IconID", "12")  # the fallback for apps without custom icons
    cd = sub(ee, "CustomData")
    it = sub(cd, "Item")
    sub(it, "Key", "KPXC_BROWSER_HIDE_ENTRY")
    sub(it, "Value", "true")
    sub(it, "LastModificationTime", kp._encode_time(now))
    if unknown == "entry":
        sub(ee, "FutureEntryElement", "entry from a newer app")
    if unknown == "attr":
        ee.find("String/Value").set("FutureAttribute", "x")
    e.expires = True
    e.expiry_time = now + datetime.timedelta(days=90)
    at = ee.find("AutoType")
    if at is None:
        at = sub(ee, "AutoType")
        sub(at, "Enabled", "True")
        sub(at, "DataTransferObfuscation", "0")
    assoc = sub(at, "Association")
    sub(assoc, "Window", "Bank — Firefox*")
    sub(assoc, "KeystrokeSequence", "{USERNAME}{TAB}{PASSWORD}{ENTER}")

    # two attachments, one of them shared with a second entry
    shared = kp.add_binary(b"shared attachment bytes\x00\x01\x02", protected=False)
    own = kp.add_binary(b"private attachment" * 50, protected=True)
    e.add_attachment(shared, "shared.bin")
    e.add_attachment(own, "own.txt")
    e2 = kp.add_entry(g, "Second", "sam2", "pw2")
    e2.add_attachment(shared, "same-bytes.bin")

    # history: two older versions
    e.save_history()
    e.password = "older password"
    e.save_history()
    e.password = "  pass with spaces  "

    # a note-style entry with ewe's kind marker
    n = kp.add_entry(root, "Wi-Fi at home", "", "")
    n.notes = "the router is in the hall"
    n_cd = sub(n._element, "CustomData")
    it = sub(n_cd, "Item")
    sub(it, "Key", "ewe.kind")
    sub(it, "Value", "note")

    # a recycle bin with something in it, and a deleted object
    rb = kp.add_group(root, "Recycle Bin")
    put(meta, "RecycleBinUUID", b64uuid(rb.uuid))
    put(meta, "RecycleBinEnabled", "True")
    gone = kp.add_entry(rb, "Old login", "old", "old")
    sub(gone._element, "PreviousParentGroup", b64uuid(g.uuid))
    dob = kp.tree.find("Root/DeletedObjects")
    d = sub(dob, "DeletedObject")
    sub(d, "UUID", b64uuid(uuid.uuid4()))
    sub(d, "DeletionTime", kp._encode_time(now))

    if unknown == "root":
        sub(kp.tree.find("Root"), "FutureRootElement", "root from a newer app")
    if unknown != "interleaved":
        canonical(kp.tree)
    kp.save(out)
    print(out)


if __name__ == "__main__":
    main(*sys.argv[1:5])
