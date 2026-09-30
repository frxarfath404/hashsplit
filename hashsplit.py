#!/usr/bin/env python3
"""
hashsplit.py — Smart NTLM Hash-Dump Splitter
=================================================================
coded by frx arfath  ·  github.com/frxarfath404

  ⚠  FOR AUTHORIZED PENETRATION TESTING / OSCP LABS ONLY.
     Using this against systems you do not own or have written permission
     to test is illegal. You are responsible for how you use this tool.

WHAT THIS IS
------------
You just dumped SAM / NTDS / LSA secrets (secretsdump, nxc --sam, nxc --lsa,
whatever) and now you're staring at 20-30 lines like:

    CORP.LOCAL\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    CORP.LOCAL\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7a38310ea6f0027ff5eb0538c92a6ba9:::
    CORP.LOCAL\\svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::

Copy-pasting each username and each hash into two separate wordlists by
hand, one at a time, is exactly the kind of tedious, error-prone busywork
that costs you time (and mistakes) under exam pressure.

Point hashsplit.py at that raw text (any file, any tool's output — it
doesn't care about the surrounding junk/banner lines) and it hands you back
two clean files:

    dump_users.txt    ->  one bare username per line   (no domain\\ prefix)
    dump_hashes.txt   ->  the matching NT hash per line, SAME ORDER

Line N of dump_users.txt always matches line N of dump_hashes.txt, so you
can feed them straight into hashcat (--username / a combined user:hash
file, see --combined) or any pass-the-hash tool.

It's also SMART about what it finds, and calls out the stuff that matters
most on an exam, loudly, right when you run it:

  - Blank/empty passwords (instant login, no cracking needed at all)
  - krbtgt captured (Golden Ticket material)
  - The SAME password hash reused across multiple accounts (crack one,
    you have all of them — huge lateral-movement shortcut)
  - A real (non-placeholder) LM hash present — LM cracks far faster than
    NTLM, so this is a shortcut worth taking
  - Duplicate lines and stale password-history entries are automatically
    cleaned up so your wordlists don't have any repeats in them

It never talks to the network, never guesses at anything, and never
silently drops a hash it found — every match is accounted for in the
final summary.
"""

import argparse
import re
import sys
from collections import OrderedDict, defaultdict

# ----------------------------------------------------------------------------
# colour helpers (optional colorama, degrades cleanly without it)
# ----------------------------------------------------------------------------
try:
    from colorama import init as _cinit, Fore, Style
    _cinit(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False

    class _NoColor:
        def __getattr__(self, _name):
            return ""

    Fore = Style = _NoColor()

_PALETTE = {
    "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
    "blue": Fore.BLUE, "magenta": Fore.MAGENTA, "cyan": Fore.CYAN,
    "white": Fore.WHITE,
}


def c(text, color=None, style=None):
    out = ""
    if color:
        out += _PALETTE.get(color, "")
    if style == "bold":
        out += Style.BRIGHT
    out += str(text)
    if _HAS_COLOR:
        out += Style.RESET_ALL
    return out


def banner():
    art = r"""
    ██╗  ██╗ █████╗ ███████╗██╗  ██╗███████╗██████╗ ██╗     ██╗████████╗
    ██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗██║     ██║╚══██╔══╝
    ███████║███████║███████╗███████║███████╗██████╔╝██║     ██║   ██║
    ██╔══██║██╔══██║╚════██║██╔══██║╚════██║██╔═══╝ ██║     ██║   ██║
    ██║  ██║██║  ██║███████║██║  ██║███████║██║     ███████╗██║   ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚═╝   ╚═╝
    """
    rainbow = ["red", "yellow", "green", "cyan", "blue", "magenta"]
    print(c(art, "cyan", "bold"))
    name = "F R X   A R F A T H"
    colored_name = "".join(
        c(ch, rainbow[i % len(rainbow)], "bold") for i, ch in enumerate(name)
    )
    bar = c("═" * 68, "blue")
    print("        " + bar)
    print("           " + c("⚡ coded by  ", "white", "bold") + colored_name + c("  ⚡", "yellow", "bold"))
    print("        " + bar)
    print("        " + c("smart hash-dump splitter — users / hashes / cleartext, all clean", "cyan"))
    print("        " + c("works on secretsdump / nxc --sam / nxc --lsa / any raw paste", "white"))
    print("        " + c("⚠  authorized testing / OSCP labs only", "yellow", "bold"))
    print()


# ----------------------------------------------------------------------------
# parsing
# ----------------------------------------------------------------------------
# Matches the classic pwdump/secretsdump line shape: user:rid:lmhash:nthash:::
# found ANYWHERE in a line (not anchored), so it doesn't matter whether the
# line is bare secretsdump output, or nxc's own "SMB ip port host <payload>"
# column-prefixed output, or has a domain\ or DOMAIN/ prefix in front of the
# username, or has other junk/banner text around it -- exactly the same
# "search, don't anchor" approach that adenum's own real-world-tested parsers
# use, because raw tool output is never as clean as the docs suggest.
#
# The RID field is made OPTIONAL (`(?:(?P<rid>\d+):)?`) because a real-world
# nxc/secretsdump `--lsa` dump prints the $MACHINE.ACC (computer account) NTLM
# hash in a DIFFERENT, shorter shape with no RID at all:
#     OSCP\MS01$:aad3b435b51404eeaad3b435b51404ee:00297cbc22beccf731ab09f44905209d:::
# A real run against MS01 confirmed this exact line was being silently missed
# before this fix -- the machine account's hash simply never made it into
# dump_hashes.txt even though it was sitting right there in the raw output.
NTLM_RE = re.compile(
    r"(?P<user>[^\s:\\/]+):(?:(?P<rid>\d+):)?(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::"
)

# Cached domain-logon hash, printed by nxc/secretsdump --lsa as
# domain/user:$DCC2$rounds#user#hash: (date) -- a completely different,
# non-NTLM crackable format (hashcat -m 2100), so it's kept in its own file
# rather than mixed into dump_hashes.txt where it would be meaningless.
DCC2_RE = re.compile(r"\$DCC2\$\d+#[^#\s]+#[0-9a-fA-F]+")

EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"

HISTORY_RE = re.compile(r"^(?P<base>.+)_history\d+$", re.IGNORECASE)

# ---- cleartext-credential detection ----------------------------------------
# LSA secrets output mixes NTLM hashes, Kerberos keys, DCC2 cached hashes,
# DPAPI master keys, AND actual recovered cleartext passwords (identifier:
# password) all in the same dump -- the cleartext lines are the single most
# valuable thing in the whole file and the easiest to miss because they look
# exactly like every other "word:word" line at a glance.
#
# Because hashsplit.py accepts ANY raw pasted blob (not just the output of
# one specific command the way adenum.py's own parser can assume), it has to
# tell a genuine "identifier:password" secret apart from every other
# colon-suffixed line that shows up in a typical OSCP session transcript --
# nxc's own "(name:MS01) (signing:False)" status text, its "[+] user:pass"
# login-echo lines, its "logon_server: MS01" field, and even another tool's
# own "Groups enumerated: 0"-style summary output copy-pasted into the same
# file. Each of the checks below was added because a REAL line of that exact
# shape was found in a real captured OSCP transcript and would otherwise have
# been mis-reported as a cleartext credential:
#
#   - secret must not contain a colon itself, so a timestamp like
#     "12:01:42.962825" can never be mistaken for a password
#     (real: "adenum.py summary — 2026-09-26T12:01:42.962825")
#   - secret must not be pure digits, so a count line like
#     "Groups enumerated: 0" is never mistaken for a credential
#   - lines carrying nxc's own "[*]"/"[+]"/"[-]" status markers are skipped
#     entirely, so its own login-echo ("[+] MS01\Administrator:Falak@143")
#     is never re-reported as a "found" secret
#   - a small blacklist of known non-credential field identifiers
#     ("logon_server", "domain", "sid", ...) catches the rest
#     (real: "MS01\cloudbase-init    logon_server: MS01")
CLEARTEXT_RE = re.compile(
    r"(?:^|\s)(?P<ident>[A-Za-z0-9_.$-]+(?:\\[A-Za-z0-9_.$-]+)?):(?P<secret>[^\s:]+)$"
)
_KERB_KEY_LABELS = ("aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96",
                    "des-cbc-md5", "plain_password_hex")
_HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F]+$")
_STATUS_MARKER_RE = re.compile(r"\[[+\-*]\]")
_NON_CRED_IDENTS = {
    "logon_server", "domain", "sid", "os", "build", "arch", "signing",
    "smb1", "smbv1", "port", "host", "target", "module", "status",
    "access_level", "source", "domain_sid",
}


def try_cleartext(line):
    """Returns (ident, secret) if `line` looks like a genuine recovered
    cleartext credential, otherwise None. See the block comment above for
    exactly why each guard exists -- every one of them is a real false
    positive that was found and eliminated, not a hypothetical.

    Two more real ones, found from an actual full OSCP-session transcript
    (nxc/secretsdump output pasted alongside the shell session that produced
    it, not just the tool output in isolation):
      - a shell-prompt command ECHO line, e.g.
        "$ impacket-secretsdump Administrator:Falak@143@10.10.10.5" -- this
        is the command being typed, not tool output, and would otherwise be
        misread as a cleartext credential "Administrator:Falak@143@10.10.10.5"
      - a Windows drive-letter path at the end of a line, e.g.
        "PS_HISTORY: C:\\Users\\Administrator\\...\\ConsoleHost_history.txt"
        -- the "C:" drive letter looks exactly like a one-character
        "identifier:value" pair once everything after the LAST colon is
        taken as the secret, since a file path's backslashes don't contain
        colons either
    """
    stripped = line.strip()
    if stripped.startswith("$ ") or stripped.startswith("# ") or stripped.startswith(">>> "):
        return None  # a typed command being echoed back, not tool output
    if _STATUS_MARKER_RE.search(line):
        return None
    if any(label in line for label in _KERB_KEY_LABELS):
        return None
    m = CLEARTEXT_RE.search(line)
    if not m:
        return None
    ident, secret = m.group("ident"), m.group("secret")
    if len(ident) <= 1:
        return None  # a bare drive letter ("C", "D", ...), never a real identifier
    if secret.startswith("\\") or secret.startswith("/"):
        return None  # rest of a filesystem path, not a password
    if ident.lower() in _NON_CRED_IDENTS or ident.lower().startswith("dpapi_"):
        return None
    if secret.isdigit():
        return None
    if _HEX_ONLY_RE.match(secret) or secret.startswith("0x"):
        return None
    return ident, secret


class Entry:
    __slots__ = ("user", "rid", "lm", "nt", "is_history", "is_machine", "raw_user")

    def __init__(self, user, rid, lm, nt):
        self.raw_user = user
        m = HISTORY_RE.match(user)
        self.is_history = bool(m)
        self.user = m.group("base") if m else user
        self.is_machine = self.user.endswith("$")
        self.rid = rid
        self.lm = lm.lower()
        self.nt = nt.lower()


def parse_text(text):
    """Walks the input line by line and classifies each line as, in order:
    an NTLM hash line, a DCC2 cached-domain-hash line, or (if neither
    matched) a possible cleartext credential. A line only gets ONE
    classification -- once it's claimed as a hash line it's never also
    considered for cleartext, which is what keeps a real hash line like
    '...:aad3b435...:00297cbc...:::' from ever being mistaken for a
    cleartext secret too.

    Returns (ntlm_entries, dcc2_hashes, cleartext_pairs, total_hash_matches).
    """
    ntlm_entries = []
    dcc2_hashes = []
    cleartext_pairs = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        matched = False
        for m in NTLM_RE.finditer(line):
            ntlm_entries.append(Entry(m.group("user"), m.group("rid"), m.group("lm"), m.group("nt")))
            matched = True
        for m in DCC2_RE.finditer(line):
            dcc2_hashes.append(m.group(0))
            matched = True

        if not matched:
            ct = try_cleartext(line)
            if ct:
                cleartext_pairs.append(ct)

    total_hash_matches = len(ntlm_entries) + len(dcc2_hashes)
    return ntlm_entries, dcc2_hashes, cleartext_pairs, total_hash_matches


def dedupe_pairs(pairs):
    """De-duplicates (ident, secret) tuples by ident (case-insensitive),
    keeping the first occurrence -- the same 'same username showing up
    repeatedly' problem the hash side has, handled the same smart way."""
    seen = OrderedDict()
    conflicts = []
    exact_dupes = 0
    for ident, secret in pairs:
        key = ident.lower()
        if key in seen:
            if seen[key][1] == secret:
                exact_dupes += 1
            else:
                conflicts.append(ident)
            continue
        seen[key] = (ident, secret)
    return list(seen.values()), exact_dupes, conflicts


def dedupe_and_filter(entries, include_history=False, skip_machine=False):
    """
    Applies, in order:
      1. history-entry filtering (unless --include-history)
      2. machine-account filtering (only if --skip-machine-accounts)
      3. de-duplication by username (case-insensitive), keeping the FIRST
         occurrence's hash and counting exact-duplicate vs conflicting-hash
         skips separately, so nothing is silently lost from the stats.

    Returns (final_entries, stats dict).
    """
    stats = {
        "total_matches": len(entries),
        "history_skipped": 0,
        "machine_skipped": 0,
        "exact_duplicates_skipped": 0,
        "conflicting_duplicates_skipped": 0,
        "conflicting_users": [],
    }

    seen = OrderedDict()  # lower(username) -> Entry (first occurrence kept)
    for e in entries:
        if e.is_history and not include_history:
            stats["history_skipped"] += 1
            continue
        if e.is_machine and skip_machine:
            stats["machine_skipped"] += 1
            continue

        key = e.user.lower()
        if key in seen:
            prev = seen[key]
            if prev.nt == e.nt and prev.lm == e.lm:
                stats["exact_duplicates_skipped"] += 1
            else:
                stats["conflicting_duplicates_skipped"] += 1
                stats["conflicting_users"].append(e.user)
            continue
        seen[key] = e

    return list(seen.values()), stats


# ----------------------------------------------------------------------------
# smart analysis -- the stuff that's actually worth shouting about on exam day
# ----------------------------------------------------------------------------
def analyze(entries, cleartext_pairs):
    blank_password = [e for e in entries if e.nt == EMPTY_NT_HASH]
    krbtgt = [e for e in entries if e.user.lower() == "krbtgt"]
    administrator = [e for e in entries if e.user.lower() == "administrator"]
    real_lm = [e for e in entries if e.lm != EMPTY_LM_HASH and e.lm != "0" * 32]

    by_hash = defaultdict(list)
    for e in entries:
        if e.nt != EMPTY_NT_HASH:  # a shared "blank password" isn't a useful reuse signal
            by_hash[e.nt].append(e.user)
    reused = {h: users for h, users in by_hash.items() if len(users) > 1}

    # cross-reference: a cleartext password recovered for a name that ALSO
    # has an NTLM hash in this same dump means you can verify/use it right
    # now with zero cracking -- a real find from the MS01 box: "cloudbase-init"
    # had both its own SAM hash AND its plaintext password recovered from an
    # LSA service secret.
    hash_users_lower = {e.user.lower(): e.user for e in entries}
    cleartext_bare_names = {
        ident.split("\\")[-1].lower(): (ident, secret) for ident, secret in cleartext_pairs
    }
    verified = [
        (hash_users_lower[name], ident, secret)
        for name, (ident, secret) in cleartext_bare_names.items()
        if name in hash_users_lower
    ]

    return {
        "blank_password": blank_password,
        "krbtgt": krbtgt,
        "administrator": administrator,
        "real_lm": real_lm,
        "reused": reused,
        "verified": verified,
    }


# ----------------------------------------------------------------------------
# output
# ----------------------------------------------------------------------------
def write_outputs(entries, users_path, hashes_path, combined_path=None,
                   cleartext_pairs=None, cleartext_path=None,
                   dcc2_hashes=None, dcc2_path=None):
    with open(users_path, "w") as f:
        for e in entries:
            f.write(e.user + "\n")
    with open(hashes_path, "w") as f:
        for e in entries:
            f.write(e.nt + "\n")
    if combined_path:
        with open(combined_path, "w") as f:
            for e in entries:
                f.write(f"{e.user}:{e.nt}\n")
    if cleartext_pairs and cleartext_path:
        with open(cleartext_path, "w") as f:
            for ident, secret in cleartext_pairs:
                f.write(f"{ident}:{secret}\n")
    if dcc2_hashes and dcc2_path:
        with open(dcc2_path, "w") as f:
            for h in dcc2_hashes:
                f.write(h + "\n")


def print_summary(entries, stats, findings, users_path, hashes_path, combined_path=None,
                   cleartext_pairs=None, cleartext_path=None, cleartext_conflicts=None,
                   dcc2_hashes=None, dcc2_path=None):
    cleartext_pairs = cleartext_pairs or []
    cleartext_conflicts = cleartext_conflicts or []
    dcc2_hashes = dcc2_hashes or []

    print()
    print(c("=" * 74, "blue"))
    print(c("  HASH-DUMP SPLIT SUMMARY  — frx arfath", "white", "bold"))
    print(c("=" * 74, "blue"))
    print(f"  NTLM hash lines found in input  : {stats['total_matches']}")
    print(f"  Unique user:hash pairs written  : {len(entries)}")
    print(f"  Exact duplicate lines skipped   : {stats['exact_duplicates_skipped']}")
    print(f"  Password-history entries skipped: {stats['history_skipped']}")
    if stats["machine_skipped"]:
        print(f"  Machine ($) accounts skipped    : {stats['machine_skipped']}")
    if stats["conflicting_duplicates_skipped"]:
        print(c(f"  [!] {stats['conflicting_duplicates_skipped']} user(s) appeared twice with "
                f"DIFFERENT hashes — kept the first, dropped the rest: "
                f"{', '.join(stats['conflicting_users'])}", "yellow"))
    print(f"  Cleartext passwords recovered   : {len(cleartext_pairs)}")
    print(f"  Cached domain hashes (DCC2)     : {len(dcc2_hashes)}")

    if findings["krbtgt"]:
        print(c("  [!!!] krbtgt hash captured — Golden Ticket material.", "red", "bold"))
    if cleartext_pairs:
        names = ", ".join(ident for ident, _ in cleartext_pairs)
        print(c(f"  [!!!] CLEARTEXT PASSWORD(S) RECOVERED for: {names} — these are real "
                f"passwords, no cracking needed, try them directly.", "red", "bold"))
    if cleartext_conflicts:
        print(c(f"  [!] {len(cleartext_conflicts)} identifier(s) had two DIFFERENT cleartext "
                f"values seen — kept the first: {', '.join(cleartext_conflicts)}", "yellow"))
    if findings["verified"]:
        for hash_user, ident, secret in findings["verified"]:
            print(c(f"  [!!!] '{hash_user}' has BOTH an NTLM hash AND a recovered cleartext "
                    f"password ({secret}) in this dump — skip cracking, use it directly.",
                    "red", "bold"))
    if findings["blank_password"]:
        names = ", ".join(e.user for e in findings["blank_password"])
        print(c(f"  [!!!] BLANK PASSWORD account(s): {names} — instant login / "
                f"pass-the-hash, no cracking needed at all.", "red", "bold"))
    if findings["reused"]:
        for h, users in findings["reused"].items():
            print(c(f"  [!] password reuse: {', '.join(users)} all share the SAME hash "
                    f"({h[:8]}...) — crack it once, you have all {len(users)} accounts.",
                    "yellow", "bold"))
    if findings["real_lm"]:
        names = ", ".join(e.user for e in findings["real_lm"])
        print(c(f"  [!] real LM hash present for: {names} — LM cracks MUCH faster than "
                f"NTLM (case-insensitive, splits into two 7-char halves). "
                f"Try hashcat -m 3000 on these first.", "yellow"))
    if findings["administrator"] and not findings["blank_password"]:
        print(c("  [*] 'Administrator' account is in this dump — worth prioritizing "
                "if you crack anything.", "cyan"))
    if dcc2_hashes:
        print(c(f"  [*] {len(dcc2_hashes)} cached domain logon hash(es) saved separately "
                f"(hashcat -m 2100) — these are DOMAIN credentials, not local ones.", "cyan"))

    print(c("=" * 74, "blue"))
    print(f"  users     -> {users_path}")
    print(f"  hashes    -> {hashes_path}")
    if combined_path:
        print(f"  combined  -> {combined_path}")
    if cleartext_pairs and cleartext_path:
        print(f"  cleartext -> {cleartext_path}")
    if dcc2_hashes and dcc2_path:
        print(f"  cached hashes -> {dcc2_path}")
    print(c("=" * 74, "blue"))
    print()


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="hashsplit.py",
        description="Split any secretsdump/nxc/pwdump-style hash dump into clean users.txt + hashes.txt",
    )
    p.add_argument("-i", "--input", nargs="+", metavar="FILE",
                    help="one or more files containing raw dump output (secretsdump, "
                         "nxc --sam/--lsa, a straight terminal paste — junk lines around "
                         "the hashes are fine). Omit to read from stdin.")
    p.add_argument("-o", "--outdir", default=".", help="output directory (default: current directory)")
    p.add_argument("--users-out", default="dump_users.txt", help="output filename for usernames")
    p.add_argument("--hashes-out", default="dump_hashes.txt", help="output filename for NT hashes")
    p.add_argument("--combined", action="store_true",
                    help="also write dump_combined.txt with 'user:hash' pairs, one per line")
    p.add_argument("--cleartext-out", default="dump_cleartext.txt",
                    help="output filename for recovered cleartext passwords (LSA DefaultPassword, "
                         "service secrets, etc.) — only written if any are found")
    p.add_argument("--cached-hashes-out", default="dump_cached_hashes.txt",
                    help="output filename for cached domain logon hashes ($DCC2$, hashcat -m 2100) "
                         "— only written if any are found")
    p.add_argument("--include-history", action="store_true",
                    help="also include password-history entries (name_history0, _history1, ...) "
                         "instead of skipping them (default: skipped)")
    p.add_argument("--skip-machine-accounts", action="store_true",
                    help="exclude computer/machine accounts ending in '$' (default: included)")
    p.add_argument("-v", "--verbose", action="store_true",
                    help="also print every user:hash pair found, not just the summary")
    p.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if not args.no_banner:
        banner()

    if args.input:
        chunks = []
        for path in args.input:
            try:
                with open(path, "r", errors="replace") as f:
                    chunks.append(f.read())
            except OSError as ex:
                print(c(f"[-] could not read {path}: {ex}", "red"))
        text = "\n".join(chunks)
    else:
        if sys.stdin.isatty():
            print(c("[-] no --input given and nothing piped on stdin — nothing to do.", "red"))
            return 2
        text = sys.stdin.read()

    raw_entries, raw_dcc2, raw_cleartext, total = parse_text(text)
    if total == 0:
        print(c("[-] no user:rid:lmhash:nthash::: style hash lines were found in the "
                "given input. Nothing was written.", "red"))
        return 1

    entries, stats = dedupe_and_filter(
        raw_entries,
        include_history=args.include_history,
        skip_machine=args.skip_machine_accounts,
    )
    dcc2_hashes = list(OrderedDict.fromkeys(raw_dcc2))  # order-preserving dedupe
    cleartext_pairs, _ct_exact_dupes, cleartext_conflicts = dedupe_pairs(raw_cleartext)

    if args.verbose:
        for e in entries:
            tag = " (machine)" if e.is_machine else ""
            print(c(f"  [+] {e.user}{tag} : {e.nt}", "green"))
        for ident, secret in cleartext_pairs:
            print(c(f"  [+] {ident} : {secret}  (cleartext)", "magenta"))

    import os
    os.makedirs(args.outdir, exist_ok=True)
    users_path = os.path.join(args.outdir, args.users_out)
    hashes_path = os.path.join(args.outdir, args.hashes_out)
    combined_path = os.path.join(args.outdir, "dump_combined.txt") if args.combined else None
    cleartext_path = os.path.join(args.outdir, args.cleartext_out) if cleartext_pairs else None
    dcc2_path = os.path.join(args.outdir, args.cached_hashes_out) if dcc2_hashes else None

    write_outputs(entries, users_path, hashes_path, combined_path,
                  cleartext_pairs, cleartext_path, dcc2_hashes, dcc2_path)
    findings = analyze(entries, cleartext_pairs)
    print_summary(entries, stats, findings, users_path, hashes_path, combined_path,
                  cleartext_pairs, cleartext_path, cleartext_conflicts, dcc2_hashes, dcc2_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
