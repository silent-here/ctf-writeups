# Operator Notes

## Verified Remote

Instance:

```text
https://filtered-reality-f04611748c00.instancer.sekai.team
```

Command:

```bash
python3 solve.py --base https://filtered-reality-f04611748c00.instancer.sekai.team --self-seal
```

Observed result:

```text
SEKAI{th3_d4y_n3v3r_3nds_1f_y0u_r34d_f4st}
```

## Why `--self-seal` Matters

The queue file path from the original solve path is:

```text
/wp-content/uploads/.reports.queue
```

Relying on that file is fragile on a fresh remote instance because there may be no seeded ref yet. `--self-seal` creates a ref, logs in as the shared clerk, leaks the seal nonce through the WordPress path confusion primitive, and seals the ref so the bot reviews it.

## GitHub Token Handling

A GitHub classic token was pasted into chat during this session. It should be considered compromised and revoked before any GitHub operation.

Do not commit, push, or log that token. After revocation, use one of these safer options:

```bash
gh auth login
```

or:

```bash
gh auth status
```

Then create/push the local writeup repo with normal authenticated `gh` or `git`.

## Suggested Publish Layout

```text
ctf-writeups/
└── SekaiCTF/
    └── Filtered-Reality/
        ├── README.md
        ├── NOTES.md
        ├── solve.py
        ├── keeper_payload.php
        └── pop_payload.b64
```

