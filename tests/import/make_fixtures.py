#!/usr/bin/env python3
"""Make the import fixtures (docs/IMPORT.md): a 1PUX export, a 1Password
CSV export, and what `op` prints, all synthetic — written from 1Password's
published 1PUX format and the op CLI's documented JSON, never from a real
account. Run it after changing what the fixtures hold; the files it writes
are committed:

    python3 tests/import/make_fixtures.py
"""
import json
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "fixtures")
TOTP = "otpauth://totp/Discord:sam?secret=JBSWY3DPEHPK3PXP&issuer=Discord"


def field(title, value, fid=""):
    return {"title": title, "id": fid or title, "value": value, "indexAtSource": 0,
            "guarded": False, "multiline": False, "dontGenerate": False,
            "inputTraits": {"keyboard": "default", "correction": "default",
                            "capitalization": "default"}}


def item(uuid, category, title, details, overview=None, **extra):
    o = {"subtitle": "", "title": title, "urls": [], "tags": []}
    o.update(overview or {})
    it = {"uuid": uuid, "favIndex": 0, "createdAt": 1500000000, "updatedAt": 1700000000,
          "state": "active", "categoryUuid": category, "details": details, "overview": o}
    it.update(extra)
    return it


PERSONAL = [
    item("discorduuid", "001", "Discord", {
        "loginFields": [
            {"value": "sam", "id": "", "name": "username", "fieldType": "T", "designation": "username"},
            {"value": "Disc-pw-Zq9!", "id": "", "name": "password", "fieldType": "P", "designation": "password"},
            {"value": "✓", "id": "", "name": "remember", "fieldType": "C"},
            {"value": "eu-west", "id": "", "name": "server", "fieldType": "T"},
        ],
        "notesPlain": "Discord *main* account",
        "sections": [
            {"title": "Security", "name": "Section_sec", "fields": [
                field("PIN", {"concealed": "4242"}),
                field("one-time password", {"totp": TOTP}),
            ]},
            {"title": "", "name": "Section_files", "fields": [
                field("codes", {"file": {"fileName": "backup-codes.txt", "documentId": "doc1abc", "decryptedSize": 23}}),
            ]},
        ],
        "passwordHistory": [
            {"value": "old-disc-2", "time": 1650000000},
            {"value": "old-disc-1", "time": 1600000000},
        ],
    }, {"url": "https://discord.com/login", "tags": ["chat"],
        "urls": [{"label": "", "url": "https://discord.com/login"},
                 {"label": "app", "url": "https://discordapp.com"},
                 {"label": "", "url": "https://canary.discord.com"}]}, favIndex=1),
    item("routeruuid", "005", "Router admin", {"password": "router-pw-55"},
         {"url": "http://192.168.1.1"}),
    # a Credit Card and an Identity with 1Password's own field ids (its
    # templates: `op item template get "Credit Card"`, "Identity")
    item("visauuid", "002", "Visa", {
        "notesPlain": "Daily card",
        "sections": [
            {"title": "", "name": "", "fields": [
                field("cardholder name", {"string": "Sam Shepherd"}, "cardholder"),
                field("type", {"creditCardType": "visa"}, "type"),
                field("number", {"creditCardNumber": "4111111111111111"}, "ccnum"),
                field("verification number", {"concealed": "123"}, "cvv"),
                field("expiry date", {"monthYear": 202704}, "expiry"),
                field("valid from", {"monthYear": 202304}, "validFrom"),
            ]},
            {"title": "Contact Information", "name": "contactInfo", "fields": [
                field("issuing bank", {"string": "Ewe Bank"}, "bank"),
                field("phone (local)", {"phone": "+64 21 000 000"}, "phoneLocal"),
            ]},
            {"title": "Additional Details", "name": "details", "fields": [
                field("PIN", {"concealed": "9876"}, "pin"),
                field("credit limit", {"string": "5000"}, "creditLimit"),
            ]},
        ],
    }),
    item("identityuuid", "004", "Sam Shepherd", {
        "sections": [
            {"title": "Identification", "name": "name", "fields": [
                field("first name", {"string": "Sam"}, "firstname"),
                field("last name", {"string": "Shepherd"}, "lastname"),
                field("birth date", {"date": 631152000}, "birthdate"),
                field("company", {"string": "Flock Ltd"}, "company"),
            ]},
            {"title": "Address", "name": "address", "fields": [
                field("address", {"address": {"street": "1 Hill Rd", "city": "Ewetown",
                                              "state": "", "zip": "9012", "country": "nz"}}, "address"),
                field("default phone", {"phone": "+64 21 000 001"}, "defphone"),
            ]},
            {"title": "Internet Details", "name": "internet", "fields": [
                field("email", {"email": {"email_address": "sam@example.org", "provider": None}}, "email"),
                field("reminder answer", {"concealed": "Woolly"}, "remindera"),
            ]},
        ],
    }),
    item("noteuuid", "003", "Wi-Fi at home", {"notesPlain": "SSID: Flock\nPassword: baa-baa-77"},
         {"tags": ["home"]}),
    item("passportuuid", "006", "Passport scan", {
        "documentAttributes": {"fileName": "passport.pdf", "documentId": "doc2pdf", "decryptedSize": 15},
    }),
    item("forumuuid", "001", "Old forum", {
        "loginFields": [
            {"value": "sam_old", "id": "", "name": "u", "fieldType": "T", "designation": "username"},
            {"value": "forum-pw", "id": "", "name": "p", "fieldType": "P", "designation": "password"},
        ],
    }, {"url": "https://forum.example.net"}, state="archived"),
    item("trashuuid", "001", "Thrown away", {
        "loginFields": [{"value": "gone-pw", "id": "", "name": "p", "fieldType": "P", "designation": "password"}],
    }, trashed=True),
    item("sshuuid", "114", "Laptop key", {
        "sections": [{"title": "", "name": "", "fields": [
            field("private key", {"sshKey": {
                "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----",
                "metadata": {"publicKey": "ssh-ed25519 AAAAC3Nz sam@laptop",
                             "fingerprint": "SHA256:fakefingerprint", "keyType": "ed25519"}}}),
        ]}],
    }),
]

WORK = [
    item("githubuuid", "001", "GitHub", {
        "loginFields": [
            {"value": "sam-work", "id": "", "name": "login", "fieldType": "T", "designation": "username"},
            {"value": "gh-pw-X7", "id": "", "name": "password", "fieldType": "P", "designation": "password"},
        ],
        "sections": [{"title": "", "name": "", "fields": [
            field("one-time password", {"totp": "jbsw y3dp ehpk 3pxp"}),
            field("lost", {"file": {"fileName": "missing.txt", "documentId": "doc404", "decryptedSize": 4}}),
        ]}],
    }, {"url": "https://github.com/login"}),
]

EXPORT = {"accounts": [{
    "attrs": {"accountName": "Sam Shepherd", "name": "Sam Shepherd", "avatar": "",
              "email": "sam@example.org", "uuid": "SAMPLEACCOUNT", "domain": "https://my.1password.com/"},
    "vaults": [
        {"attrs": {"uuid": "personalvault", "desc": "", "avatar": "", "name": "Personal", "type": "P"},
         "items": PERSONAL},
        {"attrs": {"uuid": "workvault", "desc": "", "avatar": "", "name": "Work", "type": "U"},
         "items": WORK},
    ],
}]}

CSV = (
    "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n"
    '"Bank","https://bank.example","sam","bank-pw-1",'
    '"otpauth://totp/Bank:sam?secret=JBSWY3DPEHPK3PXP&issuer=Bank",true,false,"money;work",'
    '"Line 1\nLine 2, with a comma"\n'
    "Old site,old.example,sam,old-pw,,false,true,,\n"
    ",,,,,,,,\n"
)

OP = {
    "vaults": [{"id": "v1", "name": "Personal"}, {"id": "v2", "name": "Work"}],
    "lists": {
        "v1": [
            {"id": "i1", "title": "Discord", "category": "LOGIN", "vault": {"id": "v1", "name": "Personal"}},
            {"id": "i2", "title": "Passport", "category": "DOCUMENT", "vault": {"id": "v1", "name": "Personal"}},
            {"id": "i3", "title": "Old forum", "category": "LOGIN", "state": "ARCHIVED",
             "vault": {"id": "v1", "name": "Personal"}},
        ],
        "v2": [{"id": "i4", "title": "Visa", "category": "CREDIT_CARD", "vault": {"id": "v2", "name": "Work"}},
               {"id": "i5", "title": "Sam at work", "category": "IDENTITY", "vault": {"id": "v2", "name": "Work"}}],
    },
    "items": {
        "i1": {"id": "i1", "title": "Discord", "category": "LOGIN", "vault": {"id": "v1", "name": "Personal"},
               "created_at": "2017-07-14T02:40:00Z", "updated_at": "2023-11-14T22:13:20Z",
               "tags": ["chat"], "favorite": True,
               "urls": [{"label": "website", "primary": True, "href": "https://discord.com/login"},
                        {"label": "", "href": "https://discordapp.com"}],
               "sections": [{"id": "add more"}, {"id": "s1", "label": "Security"}],
               "fields": [
                   {"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": "sam"},
                   {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password",
                    "value": "Disc-pw-Zq9!",
                    "password_details": {"strength": "FANTASTIC", "history": ["old-disc-1", "old-disc-2"]}},
                   {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain",
                    "value": "Discord *main* account"},
                   {"id": "pin", "section": {"id": "s1", "label": "Security"}, "type": "CONCEALED",
                    "label": "PIN", "value": "4242"},
                   {"id": "otp1", "section": {"id": "s1", "label": "Security"}, "type": "OTP",
                    "label": "one-time password", "value": TOTP, "totp": "123456"},
               ],
               "files": [{"id": "f1", "name": "backup-codes.txt", "size": 23,
                          "content_path": "/v1/vaults/v1/items/i1/files/f1/content"}]},
        "i2": {"id": "i2", "title": "Passport", "category": "DOCUMENT", "vault": {"id": "v1", "name": "Personal"},
               "created_at": "2020-01-01T00:00:00Z", "updated_at": "2020-01-02T00:00:00Z",
               "fields": [{"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain"}],
               "files": [{"id": "d1", "name": "passport.pdf", "size": 15}]},
        "i3": {"id": "i3", "title": "Old forum", "category": "LOGIN", "state": "ARCHIVED",
               "vault": {"id": "v1", "name": "Personal"},
               "urls": [{"primary": True, "href": "https://forum.example.net"}],
               "fields": [
                   {"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": "sam_old"},
                   {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "forum-pw"},
               ]},
        "i4": {"id": "i4", "title": "Visa", "category": "CREDIT_CARD", "vault": {"id": "v2", "name": "Work"},
               "fields": [
                   {"id": "cardholder", "type": "STRING", "label": "cardholder name", "value": "Sam Shepherd"},
                   {"id": "type", "type": "CREDIT_CARD_TYPE", "label": "type", "value": "visa"},
                   {"id": "ccnum", "type": "CREDIT_CARD_NUMBER", "label": "number", "value": "4111111111111111"},
                   {"id": "cvv", "type": "CONCEALED", "label": "verification number", "value": "123"},
                   {"id": "expiry", "type": "MONTH_YEAR", "label": "expiry date", "value": "202704"},
                   {"id": "pin", "section": {"id": "details", "label": "Additional Details"}, "type": "CONCEALED",
                    "label": "PIN", "value": "9876"},
               ]},
        "i5": {"id": "i5", "title": "Sam at work", "category": "IDENTITY", "vault": {"id": "v2", "name": "Work"},
               "fields": [
                   {"id": "firstname", "section": {"id": "name", "label": "Identification"}, "type": "STRING",
                    "label": "first name", "value": "Sam"},
                   {"id": "lastname", "section": {"id": "name", "label": "Identification"}, "type": "STRING",
                    "label": "last name", "value": "Shepherd"},
                   {"id": "company", "section": {"id": "name", "label": "Identification"}, "type": "STRING",
                    "label": "company", "value": "Flock Ltd"},
                   {"id": "address", "section": {"id": "address", "label": "Address"}, "type": "ADDRESS",
                    "label": "address", "value": {"street": "2 Wool St", "city": "Ewetown", "state": "Canterbury",
                                                  "zip": "8011", "country": "nz"}},
                   {"id": "email", "section": {"id": "internet", "label": "Internet Details"}, "type": "EMAIL",
                    "label": "email", "value": "sam@work.example"},
               ]},
    },
    "files": {"op://v1/i1/f1": "BACKUP-CODES 1111 2222\n"},
    "documents": {"i2": "%PDF-1.4 fake\n"},
}


def main():
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "sample.1pux")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("export.attributes", json.dumps(
            {"version": 3, "description": "1Password Unencrypted Export", "createdAt": 1700000000}))
        z.writestr("export.data", json.dumps(EXPORT, indent=1))
        # the docs show three underscores, KeePassXC reads two: one of each
        z.writestr("files/doc1abc__backup-codes.txt", "BACKUP-CODES 1111 2222\n")
        z.writestr("files/doc2pdf___passport.pdf", "%PDF-1.4 fake\n")
    with open(os.path.join(OUT, "1password.csv"), "w", newline="") as f:
        f.write(CSV)
    with open(os.path.join(OUT, "op.json"), "w") as f:
        json.dump(OP, f, indent=1)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
