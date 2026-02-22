# W6_Work
Repo for Global Attack/Defend W6 tourney



### ECDSA k-Nonce Reuse
**What it does:**

Every game action in the W6 service (create game, make move, join game) is ECDSA-signed by the player's private key. When a player creates a game with `creator_first=True`, they sign two actions at once — the `CreateGame` action and their first `MakeMove` action — using a function called `SignBatch`.

**Why it's broken:**

`SignBatch` computes an AES key from the private key and some entropy, then uses that same key with the same fixed IV (`"IV for ECDSA CTR"`) to generate the random nonce `k` for every signature in the batch. Same key + same IV = same keystream = **same `k` for every signature**.

In ECDSA, using the same `k` for two signatures over different messages leaks the private key entirely. The math:

```
k  = (e1 - e2) * modinv(s1 - s2, n)  mod n
d  = (s1 * k - e1) * modinv(r, n)    mod n
```

Where `e1`, `e2` are the message hashes, `r` is the shared value from both signatures (the giveaway — `r1 == r2` confirms k-reuse), `s1`, `s2` are the two signature values, and `n` is the P-256 curve order.

If the key derivation function isn't in the correct loop, it can be exploited.
