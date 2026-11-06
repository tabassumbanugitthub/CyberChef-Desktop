"""
CyberChef Desktop  -  a native "cyber swiss-army knife" built with Python, Tkinter and SQLite.
Pure standard library. No browser. Run it straight from Spyder (F5).

Features
  * 70+ operations: encoding, crypto/ciphers, hashing, compression, text, forensics, analysis
  * Drag-free recipe builder (double-click an operation to add it), reorder / disable / remove
  * Live auto-bake, hex-dump output view, load file / save output
  * Magic: automatically tries chains of decoders to find readable output
  * SQLite: saved recipes + full bake history (restore any previous session)
"""
import base64, binascii, bz2, collections, datetime, gzip, hashlib, hmac, html, json, math
import os, re, sqlite3, string, time, urllib.parse, zlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

# ═════════════════════════════════════════════════════════════════════════════
#  OPERATION REGISTRY
# ═════════════════════════════════════════════════════════════════════════════
class Op:
    def __init__(self, cat, name, fn, params, desc):
        self.cat, self.name, self.fn, self.params, self.desc = cat, name, fn, params or [], desc

REG = collections.OrderedDict()


def op(cat, name, params=None, desc=""):
    """params: list of (label, default, kind) ; kind = 'str' | 'int' | list-of-choices"""
    def deco(fn):
        REG[name] = Op(cat, name, fn, params, desc or (fn.__doc__ or "").strip())
        return fn
    return deco


def defaults(o):
    d = {}
    for label, default, kind in o.params:
        d[label] = kind[0] if isinstance(kind, list) else default
    return d


def T(data):          # bytes -> str (utf-8 if possible, else latin-1 so nothing is lost)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def B(s):             # str -> bytes
    return s.encode("utf-8", "replace")


def I(v, d=0):
    try:
        return int(str(v).strip(), 0)
    except Exception:
        return d


# ── Encoding ────────────────────────────────────────────────────────────────
@op("Encoding", "To Base64", [("Alphabet", "", ["Standard", "URL-safe"])], "Encode bytes as Base64")
def _(d, Alphabet="Standard"):
    return base64.urlsafe_b64encode(d) if Alphabet == "URL-safe" else base64.b64encode(d)


@op("Encoding", "From Base64", desc="Decode Base64 (tolerates whitespace, URL-safe, missing padding)")
def _(d):
    s = re.sub(rb"\s+", b"", d).replace(b"-", b"+").replace(b"_", b"/")
    return base64.b64decode(s + b"=" * (-len(s) % 4))


@op("Encoding", "To Base32")
def _(d): return base64.b32encode(d)


@op("Encoding", "From Base32")
def _(d):
    s = re.sub(rb"\s+", b"", d).upper()
    return base64.b32decode(s + b"=" * (-len(s) % 8))


@op("Encoding", "To Base85")
def _(d): return base64.a85encode(d)


@op("Encoding", "From Base85")
def _(d): return base64.a85decode(d.strip())


@op("Encoding", "To Hex", [("Delimiter", "Space", ["Space", "None", "Comma", "0x", "\\x"])])
def _(d, Delimiter="Space"):
    h = [f"{b:02x}" for b in d]
    return B({"Space": " ", "None": "", "Comma": ","}.get(Delimiter, " ").join(h)) if Delimiter in ("Space", "None", "Comma") \
        else B("".join(Delimiter + x for x in h))


@op("Encoding", "From Hex")
def _(d):
    s = re.sub(rb"0x|\\x|[^0-9a-fA-F]", b"", d)
    return binascii.unhexlify(s)


@op("Encoding", "To Binary")
def _(d): return B(" ".join(f"{b:08b}" for b in d))


@op("Encoding", "From Binary")
def _(d):
    s = re.sub(r"[^01]", "", T(d))
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s) - len(s) % 8, 8))


@op("Encoding", "To Decimal")
def _(d): return B(" ".join(str(b) for b in d))


@op("Encoding", "From Decimal")
def _(d): return bytes(int(x) & 255 for x in re.findall(r"\d+", T(d)))


@op("Encoding", "URL Encode", [("Encode all", "", ["No", "Yes"])])
def _(d, **a):
    return B(urllib.parse.quote(d, safe="") if a.get("Encode all") == "Yes" else urllib.parse.quote(d))


@op("Encoding", "URL Decode")
def _(d): return urllib.parse.unquote_to_bytes(T(d).replace("+", " "))


@op("Encoding", "HTML Entity Encode")
def _(d): return B(html.escape(T(d)).encode("ascii", "xmlcharrefreplace").decode())


@op("Encoding", "HTML Entity Decode")
def _(d): return B(html.unescape(T(d)))


MORSE = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....", "I": "..",
         "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
         "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..",
         "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....",
         "7": "--...", "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..", "/": "-..-."}
MORSE_R = {v: k for k, v in MORSE.items()}


@op("Encoding", "To Morse Code")
def _(d): return B(" ".join("/" if c == " " else MORSE.get(c.upper(), "?") for c in T(d)))


@op("Encoding", "From Morse Code")
def _(d): return B("".join(" " if t == "/" else MORSE_R.get(t, "?") for t in T(d).split()))


# ── Ciphers / Crypto ────────────────────────────────────────────────────────
def _shift(text, n):
    out = []
    for c in text:
        if c.isascii() and c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c) - base + n) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


@op("Crypto", "ROT13", [("Amount", 13, "int")])
def _(d, Amount=13): return B(_shift(T(d), I(Amount, 13)))


@op("Crypto", "Caesar Brute Force", desc="Show all 25 Caesar shifts")
def _(d): return B("\n".join(f"{n:>2}: {_shift(T(d), n)}" for n in range(1, 26)))


@op("Crypto", "Atbash Cipher")
def _(d):
    tr = str.maketrans(string.ascii_lowercase + string.ascii_uppercase,
                       string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1])
    return B(T(d).translate(tr))


@op("Crypto", "Vigenere", [("Key", "KEY", "str"), ("Mode", "", ["Encode", "Decode"])])
def _(d, Key="KEY", Mode="Encode"):
    k = [ord(c.lower()) - 97 for c in Key if c.isalpha()]
    if not k: raise ValueError("Key must contain letters")
    out, i = [], 0
    for c in T(d):
        if c.isascii() and c.isalpha():
            s = k[i % len(k)] * (1 if Mode == "Encode" else -1)
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c) - base + s) % 26 + base)); i += 1
        else:
            out.append(c)
    return B("".join(out))


def _keybytes(key, fmt):
    return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", key)) if fmt == "Hex" else B(key)


@op("Crypto", "XOR", [("Key", "key", "str"), ("Key format", "", ["UTF8", "Hex"])])
def _(d, Key="key", **a):
    k = _keybytes(Key, a.get("Key format", "UTF8"))
    if not k: raise ValueError("Empty key")
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


@op("Crypto", "XOR Brute Force (1 byte)", [("Crib (optional)", "", "str")],
    "Try all 256 single-byte keys, rank by readability")
def _(d, **a):
    crib = a.get("Crib (optional)", "").lower()
    rows = []
    for k in range(256):
        x = bytes(b ^ k for b in d)
        score = sum(32 <= c < 127 or c in (9, 10, 13) for c in x) / max(len(x), 1)
        t = x.decode("latin-1")
        if crib and crib not in t.lower(): continue
        rows.append((score, k, t[:80].replace("\n", " ")))
    rows.sort(reverse=True)
    return B("\n".join(f"key=0x{k:02x}  score={s:.2f}  {t}" for s, k, t in rows[:15]))


@op("Crypto", "RC4", [("Key", "secret", "str"), ("Key format", "", ["UTF8", "Hex"])])
def _(d, Key="secret", **a):
    k = _keybytes(Key, a.get("Key format", "UTF8"))
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) % 256; S[i], S[j] = S[j], S[i]
    out, i, j = bytearray(), 0, 0
    for c in d:
        i = (i + 1) % 256; j = (j + S[i]) % 256; S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


# ── Hashing ─────────────────────────────────────────────────────────────────
def _mk_hash(name, algo):
    @op("Hashing", name, desc=f"{name} digest (hex)")
    def _(d): return B(hashlib.new(algo, d).hexdigest())

for _n, _a in [("MD5", "md5"), ("SHA1", "sha1"), ("SHA224", "sha224"), ("SHA256", "sha256"), ("SHA384", "sha384"),
               ("SHA512", "sha512"), ("SHA3-256", "sha3_256"), ("SHA3-512", "sha3_512"), ("BLAKE2b", "blake2b"),
               ("BLAKE2s", "blake2s")]:
    _mk_hash(_n, _a)


@op("Hashing", "HMAC", [("Key", "key", "str"), ("Algorithm", "", ["sha256", "sha1", "md5", "sha512"])])
def _(d, Key="key", Algorithm="sha256"): return B(hmac.new(B(Key), d, Algorithm).hexdigest())


@op("Hashing", "CRC32")
def _(d): return B(f"{zlib.crc32(d) & 0xffffffff:08x}")


@op("Hashing", "Adler32")
def _(d): return B(f"{zlib.adler32(d) & 0xffffffff:08x}")


@op("Hashing", "All Hashes", desc="MD5 / SHA1 / SHA256 / SHA512 / CRC32 at once")
def _(d):
    r = [f"{n:<8}{hashlib.new(a, d).hexdigest()}" for n, a in
         [("MD5", "md5"), ("SHA1", "sha1"), ("SHA256", "sha256"), ("SHA512", "sha512")]]
    r.append(f"{'CRC32':<8}{zlib.crc32(d) & 0xffffffff:08x}")
    return B("\n".join(r))


# ── Compression ─────────────────────────────────────────────────────────────
@op("Compression", "Gzip Compress")
def _(d): return gzip.compress(d)


@op("Compression", "Gzip Decompress")
def _(d): return gzip.decompress(d)


@op("Compression", "Zlib Compress")
def _(d): return zlib.compress(d)


@op("Compression", "Zlib Decompress")
def _(d):
    try: return zlib.decompress(d)
    except zlib.error: return zlib.decompress(d, -15)   # raw deflate fallback


@op("Compression", "Bzip2 Compress")
def _(d): return bz2.compress(d)


@op("Compression", "Bzip2 Decompress")
def _(d): return bz2.decompress(d)


# ── Text utilities ──────────────────────────────────────────────────────────
@op("Text", "To Upper case")
def _(d): return B(T(d).upper())


@op("Text", "To Lower case")
def _(d): return B(T(d).lower())


@op("Text", "Swap case")
def _(d): return B(T(d).swapcase())


@op("Text", "Reverse", [("By", "", ["Character", "Line", "Byte"])])
def _(d, By="Character"):
    if By == "Byte": return d[::-1]
    if By == "Line": return B("\n".join(T(d).splitlines()[::-1]))
    return B(T(d)[::-1])


@op("Text", "Remove whitespace")
def _(d): return re.sub(rb"\s+", b"", d)


@op("Text", "Remove null bytes")
def _(d): return d.replace(b"\x00", b"")


@op("Text", "Sort lines", [("Order", "", ["Ascending", "Descending"])])
def _(d, Order="Ascending"): return B("\n".join(sorted(T(d).splitlines(), reverse=Order == "Descending")))


@op("Text", "Unique lines")
def _(d): return B("\n".join(dict.fromkeys(T(d).splitlines())))


@op("Text", "Find / Replace", [("Find", "", "str"), ("Replace", "", "str"), ("Regex", "", ["No", "Yes"]),
                               ("Ignore case", "", ["No", "Yes"])])
def _(d, **a):
    pat = a.get("Find", "")
    if not pat: return d
    flags = re.I if a.get("Ignore case") == "Yes" else 0
    if a.get("Regex") != "Yes": pat = re.escape(pat)
    return B(re.sub(pat, a.get("Replace", ""), T(d), flags=flags))


@op("Text", "Regex Extract", [("Pattern", r"\w+", "str")])
def _(d, Pattern=r"\w+"):
    m = re.findall(Pattern, T(d))
    return B("\n".join(x if isinstance(x, str) else "\t".join(x) for x in m))


@op("Text", "Take bytes", [("Start", 0, "int"), ("Length", 16, "int")])
def _(d, Start=0, Length=16): s = I(Start); return d[s:s + I(Length, 16)]


# ── Forensics / Analysis ────────────────────────────────────────────────────
IP_RE = r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
URL_RE = r"(?:https?|ftp|hxxps?)://[^\s\"'<>]+"
MAIL_RE = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
HASH_RE = r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"


def _extract(rx):
    def f(d): return B("\n".join(dict.fromkeys(re.findall(rx, T(d)))))
    return f

REG["Extract IP addresses"] = Op("Forensics", "Extract IP addresses", _extract(IP_RE), [], "IPv4 indicators")
REG["Extract URLs"] = Op("Forensics", "Extract URLs", _extract(URL_RE), [], "URL indicators")
REG["Extract Email addresses"] = Op("Forensics", "Extract Email addresses", _extract(MAIL_RE), [], "Email indicators")
REG["Extract Hashes"] = Op("Forensics", "Extract Hashes", _extract(HASH_RE), [], "MD5/SHA1/SHA256-looking strings")


@op("Forensics", "Defang URLs", desc="Make URLs / IPs safe to share: http -> hxxp, . -> [.]")
def _(d):
    s = T(d).replace("http", "hxxp").replace("://", "[://]")
    return B(re.sub(r"(?<=\w)\.(?=\w)", "[.]", s))


@op("Forensics", "Fang URLs")
def _(d): return B(T(d).replace("hxxp", "http").replace("[://]", "://").replace("[.]", "."))


@op("Forensics", "Strings", [("Min length", 4, "int")], "Printable ASCII runs (like the strings tool)")
def _(d, **a):
    n = I(a.get("Min length"), 4)
    return B("\n".join(m.decode() for m in re.findall(rb"[\x20-\x7e]{%d,}" % n, d)))


@op("Forensics", "Hexdump", [("Width", 16, "int")])
def _(d, Width=16):
    w, rows = max(I(Width, 16), 1), []
    for i in range(0, len(d), w):
        c = d[i:i + w]
        rows.append(f"{i:08x}  {' '.join(f'{b:02x}' for b in c):<{w * 3}} |{''.join(chr(b) if 32 <= b < 127 else '.' for b in c)}|")
    return B("\n".join(rows))


SIGS = [(b"\x89PNG\r\n\x1a\n", "PNG image"), (b"\xff\xd8\xff", "JPEG image"), (b"GIF8", "GIF image"),
        (b"%PDF", "PDF document"), (b"PK\x03\x04", "ZIP / Office / JAR / APK"), (b"\x1f\x8b", "GZIP"),
        (b"Rar!", "RAR archive"), (b"7z\xbc\xaf\x27\x1c", "7-Zip"), (b"\x7fELF", "ELF executable"),
        (b"MZ", "Windows PE executable"), (b"\xcf\xfa\xed\xfe", "Mach-O binary"), (b"SQLite format 3", "SQLite DB"),
        (b"BZh", "BZIP2"), (b"\xfd7zXZ", "XZ"), (b"II*\x00", "TIFF"), (b"RIFF", "RIFF (WAV/AVI/WEBP)"),
        (b"ID3", "MP3 audio"), (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat"),
        (b"\xd0\xcf\x11\xe0", "OLE2 (legacy Office)"), (b"x\x9c", "zlib stream"), (b"x\xda", "zlib stream"),
        (b"{\\rtf", "RTF document"), (b"<?xml", "XML"), (b"-----BEGIN", "PEM key / certificate")]


def sniff(d):
    for sig, name in SIGS:
        if d.startswith(sig): return name
    if d[257:262] == b"ustar": return "TAR archive"
    return None


@op("Forensics", "Detect File Type", desc="Identify data by magic-number signature")
def _(d):
    t = sniff(d)
    return B(f"{t}" if t else "No known signature (probably text or encrypted/raw data)")


@op("Forensics", "Parse JWT")
def _(d):
    parts = T(d).strip().split(".")
    if len(parts) < 2: raise ValueError("Not a JWT")
    dec = lambda p: base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))
    h, p = json.loads(dec(parts[0])), json.loads(dec(parts[1]))
    return B(json.dumps({"header": h, "payload": p, "signature": parts[2] if len(parts) > 2 else ""}, indent=2))


@op("Forensics", "Unix Timestamp -> Date", [("Unit", "", ["seconds", "milliseconds"])])
def _(d, Unit="seconds"):
    out = []
    for n in re.findall(r"\d+(?:\.\d+)?", T(d)):
        v = float(n) / (1000 if Unit == "milliseconds" else 1)
        out.append(datetime.datetime.fromtimestamp(v, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    return B("\n".join(out))


@op("Forensics", "Date -> Unix Timestamp", desc="Input: YYYY-MM-DD[ HH:MM:SS] (UTC)")
def _(d):
    out = []
    for line in T(d).splitlines():
        if not line.strip(): continue
        dt = datetime.datetime.fromisoformat(line.strip()).replace(tzinfo=datetime.timezone.utc)
        out.append(str(int(dt.timestamp())))
    return B("\n".join(out))


def entropy(d):
    if not d: return 0.0
    c = collections.Counter(d); n = len(d)
    return -sum(v / n * math.log2(v / n) for v in c.values())


@op("Analysis", "Entropy", desc="Shannon entropy (0-8 bits/byte) with verdict")
def _(d):
    e = entropy(d)
    verdict = ("very low – repetitive/structured" if e < 2 else "low – plain text / code" if e < 5 else
               "medium – text / mixed data" if e < 7 else "HIGH – compressed or encrypted likely")
    bar = "█" * int(e / 8 * 40) + "░" * (40 - int(e / 8 * 40))
    return B(f"Entropy: {e:.4f} bits/byte\n[{bar}]\nVerdict: {verdict}")


@op("Analysis", "Byte Frequency", [("Top N", 15, "int")])
def _(d, **a):
    c = collections.Counter(d).most_common(I(a.get("Top N"), 15)); mx = c[0][1] if c else 1
    return B("\n".join(f"0x{b:02x} {chr(b) if 32 <= b < 127 else '.'}  {n:>7}  {'▇' * max(1, int(n / mx * 30))}" for b, n in c))


@op("Analysis", "Data Statistics")
def _(d):
    t = T(d)
    return B(f"Bytes: {len(d)}\nChars: {len(t)}\nLines: {len(t.splitlines())}\nWords: {len(t.split())}\n"
             f"Unique bytes: {len(set(d))}\nPrintable: {sum(32 <= b < 127 for b in d) / max(len(d), 1) * 100:.1f}%\n"
             f"Entropy: {entropy(d):.3f}\nType: {sniff(d) or 'unknown/text'}")


@op("Data format", "JSON Beautify", [("Indent", 2, "int")])
def _(d, Indent=2): return B(json.dumps(json.loads(T(d)), indent=I(Indent, 2), ensure_ascii=False))


@op("Data format", "JSON Minify")
def _(d): return B(json.dumps(json.loads(T(d)), separators=(",", ":"), ensure_ascii=False))


@op("Data format", "Parse Query String")
def _(d):
    q = urllib.parse.urlparse(T(d).strip()).query or T(d).strip()
    return B("\n".join(f"{k} = {v}" for k, v in urllib.parse.parse_qsl(q)))


# ═════════════════════════════════════════════════════════════════════════════
#  RUNNER + MAGIC
# ═════════════════════════════════════════════════════════════════════════════
def run_recipe(data, steps):
    for n, st in enumerate(steps, 1):
        if st.get("off"): continue
        o = REG[st["op"]]
        args = defaults(o); args.update(st.get("args", {}))
        try:
            data = o.fn(data, **args)
        except Exception as e:
            raise RuntimeError(f"Step {n} ({st['op']}): {type(e).__name__}: {e}") from None
    return data


def printable(d):
    return sum(32 <= b < 127 or b in (9, 10, 13) for b in d) / len(d) if d else 0


MAGIC_TRY = [
    ("From Base64", lambda s: re.fullmatch(r"[A-Za-z0-9+/_\-=\s]{8,}", s)),
    ("From Base32", lambda s: re.fullmatch(r"[A-Z2-7=\s]{8,}", s.upper())),
    ("From Hex", lambda s: re.fullmatch(r"(?:0x|\\x|\s|[0-9a-fA-F])+", s) and len(re.sub(r"\W|0x", "", s)) >= 4),
    ("From Binary", lambda s: re.fullmatch(r"[01\s]{8,}", s)),
    ("From Decimal", lambda s: re.fullmatch(r"(?:\d{1,3}\s+)+\d{1,3}", s.strip())),
    ("URL Decode", lambda s: "%" in s),
    ("HTML Entity Decode", lambda s: "&" in s and ";" in s),
    ("From Morse Code", lambda s: re.fullmatch(r"[.\-/\s]{3,}", s)),
    ("Gzip Decompress", lambda s: True), ("Zlib Decompress", lambda s: True), ("Bzip2 Decompress", lambda s: True),
    ("ROT13", lambda s: True),
]
ENGLISH = re.compile(r"\b(the|and|flag|password|http|admin|user|http|that|this|with|have|from)\b", re.I)


def magic(data, depth=3):
    found, seen, frontier = [], {data}, [(data, [])]
    for _ in range(depth):
        nxt = []
        for cur, path in frontier:
            s = cur.decode("latin-1")
            for name, pre in MAGIC_TRY:
                try:
                    if not pre(s): continue
                    out = REG[name].fn(cur, **defaults(REG[name]))
                except Exception:
                    continue
                if not out or out in seen: continue
                if name == "ROT13" and not ENGLISH.search(T(out)): continue
                seen.add(out)
                p = path + [{"op": name, "args": defaults(REG[name])}]
                score = printable(out) + (0.3 if sniff(out) else 0) + (0.3 if ENGLISH.search(T(out)) else 0)
                if printable(out) > 0.9 or sniff(out):
                    found.append((score, p, out))
                nxt.append((out, p))
        frontier = nxt[:40]
    found.sort(key=lambda x: (-x[0], len(x[1])))
    return found[:25]


# ═════════════════════════════════════════════════════════════════════════════
#  SQLITE
# ═════════════════════════════════════════════════════════════════════════════
class DB:
    def __init__(self, path):
        self.c = sqlite3.connect(path)
        self.c.executescript("""
            CREATE TABLE IF NOT EXISTS recipes(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
                steps TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY, ts TEXT DEFAULT CURRENT_TIMESTAMP,
                steps TEXT, input TEXT, in_len INTEGER, out_preview TEXT, out_len INTEGER, ms REAL);
        """)
        self.c.commit()

    def save_recipe(self, name, steps):
        self.c.execute("INSERT INTO recipes(name,steps) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET steps=excluded.steps",
                       (name, json.dumps(steps)))
        self.c.commit()

    def recipes(self):
        return self.c.execute("SELECT name,steps,created FROM recipes ORDER BY name").fetchall()

    def delete_recipe(self, name):
        self.c.execute("DELETE FROM recipes WHERE name=?", (name,)); self.c.commit()

    def log(self, steps, inp, out, ms):
        self.c.execute("INSERT INTO history(steps,input,in_len,out_preview,out_len,ms) VALUES(?,?,?,?,?,?)",
                       (json.dumps(steps), inp[:200000], len(inp), out[:120].decode("latin-1"), len(out), ms))
        self.c.execute("DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT 500)")
        self.c.commit()

    def history(self):
        return self.c.execute("SELECT id,ts,steps,input,out_preview,out_len FROM history ORDER BY id DESC LIMIT 200").fetchall()

    def clear_history(self):
        self.c.execute("DELETE FROM history"); self.c.commit()


# ═════════════════════════════════════════════════════════════════════════════
#  UI
# ═════════════════════════════════════════════════════════════════════════════
C = dict(bg="#11151c", panel="#171c26", card="#1e2532", edge="#2b3446", fg="#d7dde8", dim="#7f8aa3",
         accent="#3ddc97", accent2="#4aa8ff", warn="#ff6b6b", sel="#26334d")
MONO = ("Consolas", 10)


class App:
    def __init__(self, root):
        self.root = root
        try:
            base = os.path.dirname(os.path.abspath(__file__))
        except NameError:
            base = os.getcwd()
        self.db = DB(os.path.join(base, "cyberchef_desktop.db"))
        self.steps, self.sel, self.in_enc, self.out_bytes, self._job = [], None, "utf-8", b"", None
        self.auto = tk.BooleanVar(value=True)
        self.view = tk.StringVar(value="Text")
        root.title("CyberChef Desktop  ·  Python + SQLite")
        root.geometry("1380x820"); root.minsize(1000, 600); root.configure(bg=C["bg"])
        self._style(); self._build()
        root.bind("<Control-Return>", lambda e: self.bake(log=True))
        root.bind("<Control-o>", lambda e: self.open_file())
        root.bind("<Control-s>", lambda e: self.save_output())

    # ---- styling
    def _style(self):
        s = ttk.Style(); s.theme_use("clam")
        s.configure(".", background=C["bg"], foreground=C["fg"], fieldbackground=C["card"], bordercolor=C["edge"],
                    lightcolor=C["edge"], darkcolor=C["edge"], font=("Segoe UI", 10))
        s.configure("TFrame", background=C["bg"])
        s.configure("Panel.TFrame", background=C["panel"])
        s.configure("TLabel", background=C["bg"], foreground=C["fg"])
        s.configure("Head.TLabel", background=C["panel"], foreground=C["accent"], font=("Segoe UI Semibold", 11))
        s.configure("Dim.TLabel", background=C["panel"], foreground=C["dim"])
        s.configure("TButton", background=C["card"], foreground=C["fg"], padding=(10, 5), borderwidth=0)
        s.map("TButton", background=[("active", C["sel"])])
        s.configure("Bake.TButton", background=C["accent"], foreground="#06130d", font=("Segoe UI Semibold", 11), padding=(18, 8))
        s.map("Bake.TButton", background=[("active", "#62f0b3")])
        s.configure("Treeview", background=C["card"], fieldbackground=C["card"], foreground=C["fg"], rowheight=24, borderwidth=0)
        s.map("Treeview", background=[("selected", C["sel"])], foreground=[("selected", C["accent"])])
        s.configure("Treeview.Heading", background=C["panel"], foreground=C["dim"])
        s.configure("TEntry", fieldbackground=C["card"], foreground=C["fg"], insertcolor=C["fg"])
        s.configure("TCombobox", fieldbackground=C["card"], foreground=C["fg"], arrowcolor=C["accent"])
        s.configure("TCheckbutton", background=C["bg"], foreground=C["fg"])
        s.configure("TRadiobutton", background=C["panel"], foreground=C["fg"])
        s.configure("TPanedwindow", background=C["bg"])
        self.root.option_add("*TCombobox*Listbox.background", C["card"])
        self.root.option_add("*TCombobox*Listbox.foreground", C["fg"])

    def _text(self, parent, **kw):
        t = tk.Text(parent, bg=C["card"], fg=C["fg"], insertbackground=C["accent"], selectbackground=C["sel"],
                    relief="flat", font=MONO, wrap="char", undo=True, padx=8, pady=6, bd=0,
                    highlightthickness=1, highlightbackground=C["edge"], highlightcolor=C["accent2"], **kw)
        return t

    # ---- layout
    def _build(self):
        top = ttk.Frame(self.root); top.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(top, text="◆ CyberChef", bg=C["bg"], fg=C["accent"], font=("Segoe UI Semibold", 16)).pack(side="left")
        tk.Label(top, text=" Desktop", bg=C["bg"], fg=C["dim"], font=("Segoe UI", 16)).pack(side="left")
        for txt, cmd in [("History", self.show_history), ("Load recipe", self.load_recipe),
                         ("Save recipe", self.save_recipe), ("Save output", self.save_output),
                         ("Open file", self.open_file)]:
            ttk.Button(top, text=txt, command=cmd).pack(side="right", padx=3)

        pw = ttk.PanedWindow(self.root, orient="horizontal"); pw.pack(fill="both", expand=True, padx=10, pady=6)

        # operations
        left = ttk.Frame(pw, style="Panel.TFrame"); pw.add(left, weight=1)
        ttk.Label(left, text="OPERATIONS", style="Head.TLabel").pack(anchor="w", padx=10, pady=(10, 4))
        self.q = tk.StringVar(); self.q.trace_add("write", lambda *a: self.fill_ops())
        ttk.Entry(left, textvariable=self.q).pack(fill="x", padx=10)
        ttk.Label(left, text="search · double-click to add", style="Dim.TLabel").pack(anchor="w", padx=10)
        self.tree = ttk.Treeview(left, show="tree", selectmode="browse")
        self.tree.pack(fill="both", expand=True, padx=10, pady=8)
        self.tree.bind("<Double-1>", self.on_add); self.tree.bind("<Return>", self.on_add)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_sel)
        self.desc = ttk.Label(left, text="", style="Dim.TLabel", wraplength=260, justify="left")
        self.desc.pack(anchor="w", padx=10, pady=(0, 10))
        self.fill_ops()

        # recipe
        mid = ttk.Frame(pw, style="Panel.TFrame"); pw.add(mid, weight=1)
        ttk.Label(mid, text="RECIPE", style="Head.TLabel").pack(anchor="w", padx=10, pady=(10, 4))
        self.rl = tk.Listbox(mid, bg=C["card"], fg=C["fg"], selectbackground=C["sel"], selectforeground=C["accent"],
                             relief="flat", font=("Segoe UI", 10), activestyle="none", highlightthickness=1,
                             highlightbackground=C["edge"], exportselection=False, height=10)
        self.rl.pack(fill="both", expand=True, padx=10)
        self.rl.bind("<<ListboxSelect>>", self.on_step_sel)
        bar = ttk.Frame(mid, style="Panel.TFrame"); bar.pack(fill="x", padx=10, pady=6)
        for txt, cmd in [("▲", lambda: self.move(-1)), ("▼", lambda: self.move(1)), ("⏸ Toggle", self.toggle),
                         ("✕ Remove", self.remove), ("Clear", self.clear)]:
            ttk.Button(bar, text=txt, command=cmd, width=8 if len(txt) > 1 else 3).pack(side="left", padx=2)
        ttk.Label(mid, text="ARGUMENTS", style="Head.TLabel").pack(anchor="w", padx=10, pady=(6, 2))
        self.args = ttk.Frame(mid, style="Panel.TFrame"); self.args.pack(fill="x", padx=10, pady=(0, 10))
        bot = ttk.Frame(mid, style="Panel.TFrame"); bot.pack(fill="x", padx=10, pady=(0, 12))
        ttk.Button(bot, text="🔮 Magic", command=self.do_magic).pack(side="left")
        ttk.Checkbutton(bot, text="Auto bake", variable=self.auto, style="TCheckbutton").pack(side="left", padx=12)
        ttk.Button(bot, text="BAKE  ▶", style="Bake.TButton", command=lambda: self.bake(log=True)).pack(side="right")

        # I/O
        right = ttk.Frame(pw); pw.add(right, weight=3)
        hi = ttk.Frame(right); hi.pack(fill="x")
        ttk.Label(hi, text="INPUT", foreground=C["accent2"], font=("Segoe UI Semibold", 11)).pack(side="left")
        ttk.Button(hi, text="Clear", command=lambda: self.inp.delete("1.0", "end")).pack(side="right")
        self.inp = self._text(right, height=10); self.inp.pack(fill="both", expand=True, pady=(2, 8))
        self.inp.bind("<<Modified>>", self.on_input)
        ho = ttk.Frame(right); ho.pack(fill="x")
        ttk.Label(ho, text="OUTPUT", foreground=C["accent"], font=("Segoe UI Semibold", 11)).pack(side="left")
        ttk.Button(ho, text="Copy", command=self.copy_out).pack(side="right", padx=2)
        ttk.Button(ho, text="⇧ Use as input", command=self.out_to_in).pack(side="right", padx=2)
        for v in ("Text", "Hex"):
            ttk.Radiobutton(ho, text=v, value=v, variable=self.view, command=self.render,
                            style="TRadiobutton").pack(side="right", padx=4)
        ttk.Label(ho, text="view:").pack(side="right")
        self.out = self._text(right, height=14, state="disabled"); self.out.pack(fill="both", expand=True, pady=(2, 4))
        self.out.tag_configure("err", foreground=C["warn"])
        self.status = tk.Label(self.root, text="Ready", anchor="w", bg=C["panel"], fg=C["dim"], font=("Consolas", 9), padx=10)
        self.status.pack(fill="x", side="bottom")

    # ---- operations tree
    def fill_ops(self):
        q = self.q.get().lower().strip()
        self.tree.delete(*self.tree.get_children())
        cats = collections.OrderedDict()
        for o in REG.values():
            if not q or q in o.name.lower() or q in o.cat.lower() or q in o.desc.lower():
                cats.setdefault(o.cat, []).append(o)
        for cat, ops in cats.items():
            p = self.tree.insert("", "end", text=f"  {cat}  ({len(ops)})", open=bool(q), tags=("cat",))
            for o in ops: self.tree.insert(p, "end", text=o.name, values=(o.name,))

    def on_tree_sel(self, _):
        s = self.tree.selection()
        if s and self.tree.item(s[0], "values"):
            o = REG[self.tree.item(s[0], "values")[0]]
            self.desc.config(text=o.desc)

    def on_add(self, _):
        s = self.tree.selection()
        if not s: return
        v = self.tree.item(s[0], "values")
        if v: self.add_step(v[0])
        else: self.tree.item(s[0], open=not self.tree.item(s[0], "open"))

    # ---- recipe
    def add_step(self, name):
        self.steps.append({"op": name, "args": defaults(REG[name])})
        self.refresh_recipe(len(self.steps) - 1); self.schedule()

    def refresh_recipe(self, select=None):
        self.rl.delete(0, "end")
        for i, st in enumerate(self.steps):
            a = ", ".join(f"{k}={v}" for k, v in st["args"].items() if v != "")
            self.rl.insert("end", f" {i + 1}. {'⏸ ' if st.get('off') else ''}{st['op']}" + (f"   ({a[:36]})" if a else ""))
            if st.get("off"): self.rl.itemconfig(i, fg=C["dim"])
        if select is not None and 0 <= select < len(self.steps):
            self.rl.selection_set(select); self.sel = select
        else:
            self.sel = None
        self.build_args()

    def on_step_sel(self, _):
        s = self.rl.curselection()
        self.sel = s[0] if s else None; self.build_args()

    def build_args(self):
        for w in self.args.winfo_children(): w.destroy()
        if self.sel is None or self.sel >= len(self.steps):
            ttk.Label(self.args, text="Select a step to edit its arguments.", style="Dim.TLabel").pack(anchor="w"); return
        st = self.steps[self.sel]; o = REG[st["op"]]
        if not o.params:
            ttk.Label(self.args, text="This operation has no arguments.", style="Dim.TLabel").pack(anchor="w"); return
        for label, default, kind in o.params:
            row = ttk.Frame(self.args, style="Panel.TFrame"); row.pack(fill="x", pady=2)
            ttk.Label(row, text=label, style="Dim.TLabel", width=16).pack(side="left")
            var = tk.StringVar(value=str(st["args"].get(label, kind[0] if isinstance(kind, list) else default)))
            var.trace_add("write", lambda *a, l=label, v=var, i=self.sel: self.set_arg(i, l, v.get()))
            if isinstance(kind, list): ttk.Combobox(row, textvariable=var, values=kind, state="readonly").pack(side="left", fill="x", expand=True)
            else: ttk.Entry(row, textvariable=var).pack(side="left", fill="x", expand=True)

    def set_arg(self, i, label, val):
        if i < len(self.steps):
            self.steps[i]["args"][label] = val; self.schedule()
            a = ", ".join(f"{k}={v}" for k, v in self.steps[i]["args"].items() if v != "")
            self.rl.delete(i); self.rl.insert(i, f" {i + 1}. {'⏸ ' if self.steps[i].get('off') else ''}{self.steps[i]['op']}" + (f"   ({a[:36]})" if a else ""))
            self.rl.selection_set(i)

    def move(self, d):
        i = self.sel
        if i is None or not 0 <= i + d < len(self.steps): return
        self.steps[i], self.steps[i + d] = self.steps[i + d], self.steps[i]
        self.refresh_recipe(i + d); self.schedule()

    def toggle(self):
        if self.sel is not None:
            self.steps[self.sel]["off"] = not self.steps[self.sel].get("off"); self.refresh_recipe(self.sel); self.schedule()

    def remove(self):
        if self.sel is not None:
            del self.steps[self.sel]; self.refresh_recipe(min(self.sel, len(self.steps) - 1)); self.schedule()

    def clear(self):
        self.steps = []; self.refresh_recipe(); self.schedule()

    # ---- baking
    def get_input(self):
        return self.inp.get("1.0", "end-1c").encode(self.in_enc, "replace")

    def on_input(self, _):
        if self.inp.edit_modified():
            self.inp.edit_modified(False); self.schedule()

    def schedule(self):
        if not self.auto.get(): return
        if self._job: self.root.after_cancel(self._job)
        self._job = self.root.after(250, self.bake)

    def bake(self, log=False):
        self._job = None
        data = self.get_input(); t0 = time.perf_counter()
        try:
            out = run_recipe(data, self.steps); err = None
        except Exception as e:
            out, err = b"", str(e)
        ms = (time.perf_counter() - t0) * 1000
        self.out_bytes = out; self.render(err)
        if err: self.set_status(f"✖ {err}", C["warn"])
        else:
            self.set_status(f"Input {len(data)} B  →  Output {len(out)} B   |   {ms:.1f} ms   |   "
                            f"entropy {entropy(out):.2f}   |   {sniff(out) or 'no signature'}", C["dim"])
            if log and self.steps: self.db.log(self.steps, data, out, ms)

    def render(self, err=None):
        self.out.config(state="normal"); self.out.delete("1.0", "end")
        if err: self.out.insert("end", err, "err")
        else:
            d = self.out_bytes[:2_000_000]
            if self.view.get() == "Hex": d = REG["Hexdump"].fn(d, Width=16)
            self.out.insert("end", T(d) if self.view.get() == "Text" else d.decode())
        self.out.config(state="disabled")

    def set_status(self, msg, color):
        self.status.config(text=msg, fg=color)

    # ---- actions
    def open_file(self):
        p = filedialog.askopenfilename()
        if not p: return
        with open(p, "rb") as f: raw = f.read(20_000_000)
        try: txt, self.in_enc = raw.decode("utf-8"), "utf-8"
        except UnicodeDecodeError: txt, self.in_enc = raw.decode("latin-1"), "latin-1"
        self.inp.delete("1.0", "end"); self.inp.insert("1.0", txt)
        self.set_status(f"Loaded {os.path.basename(p)} ({len(raw)} bytes, {self.in_enc})", C["accent2"])
        self.bake()

    def save_output(self):
        p = filedialog.asksaveasfilename(defaultextension=".bin")
        if p:
            with open(p, "wb") as f: f.write(self.out_bytes)
            self.set_status(f"Saved {len(self.out_bytes)} bytes to {p}", C["accent"])

    def copy_out(self):
        self.root.clipboard_clear(); self.root.clipboard_append(T(self.out_bytes))
        self.set_status("Output copied to clipboard", C["accent"])

    def out_to_in(self):
        self.in_enc = "utf-8"
        self.inp.delete("1.0", "end"); self.inp.insert("1.0", T(self.out_bytes))
        self.clear()

    def save_recipe(self):
        if not self.steps: return messagebox.showinfo("Recipe", "Recipe is empty.")
        n = simpledialog.askstring("Save recipe", "Recipe name:", parent=self.root)
        if n: self.db.save_recipe(n.strip(), self.steps); self.set_status(f"Recipe '{n}' saved to SQLite", C["accent"])

    def _picker(self, title, cols, rows, on_open, on_delete=None):
        w = tk.Toplevel(self.root); w.title(title); w.geometry("900x460"); w.configure(bg=C["bg"]); w.transient(self.root)
        tv = ttk.Treeview(w, columns=[c for c, _ in cols], show="headings")
        for c, wd in cols: tv.heading(c, text=c.title()); tv.column(c, width=wd, anchor="w")
        tv.pack(fill="both", expand=True, padx=10, pady=10)
        for i, r in enumerate(rows): tv.insert("", "end", iid=str(i), values=r[0])
        def go(_=None):
            s = tv.selection()
            if s: on_open(rows[int(s[0])][1]); w.destroy()
        tv.bind("<Double-1>", go)
        b = ttk.Frame(w); b.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(b, text="Open", command=go).pack(side="left")
        if on_delete:
            def de():
                on_delete(); w.destroy()
            ttk.Button(b, text="Delete selected", command=lambda: (on_delete(tv.selection(), rows), w.destroy())).pack(side="left", padx=6)
        return w

    def load_recipe(self):
        rows = [((n, " → ".join(s["op"] for s in json.loads(st))[:90], c), json.loads(st)) for n, st, c in self.db.recipes()]
        if not rows: return messagebox.showinfo("Recipes", "No saved recipes yet.")
        def op_(steps): self.steps = steps; self.refresh_recipe(); self.bake()
        def dele(sel, rws):
            if sel: self.db.delete_recipe(rws[int(sel[0])][0][0])
        self._picker("Saved recipes (SQLite)", [("name", 200), ("operations", 520), ("created", 150)], rows, op_, dele)

    def show_history(self):
        rows = []
        for id_, ts, st, inp, prev, ol in self.db.history():
            steps = json.loads(st)
            rows.append(((ts, " → ".join(s["op"] for s in steps)[:50], inp[:35].replace("\n", " "),
                          prev[:35].replace("\n", " "), ol), (steps, inp)))
        if not rows: return messagebox.showinfo("History", "No bakes logged yet. Press BAKE (Ctrl+Enter) to log one.")
        def op_(v):
            self.steps, inp = v[0], v[1]; self.in_enc = "utf-8"
            self.inp.delete("1.0", "end"); self.inp.insert("1.0", inp); self.refresh_recipe(); self.bake()
        self._picker("Bake history (SQLite) – double-click to restore",
                     [("time", 140), ("recipe", 230), ("input", 200), ("output", 200), ("bytes", 60)], rows, op_)

    def do_magic(self):
        data = self.get_input()
        if not data: return messagebox.showinfo("Magic", "Enter some input first.")
        self.set_status("Magic: exploring decoder chains…", C["accent2"]); self.root.update_idletasks()
        res = magic(data)
        if not res: return self.set_status("Magic: nothing readable found.", C["warn"])
        rows = [((f"{s:.2f}", " → ".join(x["op"] for x in p), T(o)[:80].replace("\n", " ")), p) for s, p, o in res]
        def op_(p): self.steps = [dict(x) for x in p]; self.refresh_recipe(); self.bake(log=True)
        self._picker("🔮 Magic results – double-click to apply", [("score", 60), ("recipe", 300), ("preview", 500)], rows, op_)
        self.set_status(f"Magic: {len(res)} candidates", C["accent"])


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()