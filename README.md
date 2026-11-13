# 🔓 RSA Break Lab

A cryptanalysis teaching project: generate deliberately weak RSA keys and
break them with five classic textbook attacks, with every attempt logged
in a structured, reproducible way for a lab report.

**[Live demo](https://YOUR-USERNAME.github.io/rsa-break-lab/)** &mdash; runs
the real Python attack code in your browser via WebAssembly (Pyodide). Update
this link once you've pushed to GitHub and enabled Pages (see
[Hosting the live demo](#hosting-the-live-demo) below).

![tests](https://github.com/YOUR-USERNAME/rsa-break-lab/actions/workflows/ci.yml/badge.svg)
![license](https://img.shields.io/badge/license-MIT-blue)

---

## What this is

Textbook RSA is only secure if certain conditions hold: the two primes
must be far apart, the private exponent can't be too small, you can't
reuse a modulus, you can't broadcast the same message with a small
exponent, and your random primes actually need to be random. Break any
one of those assumptions and RSA falls apart &mdash; often without
factoring anything at all.

This project implements both sides: **weak key generators** that plant
each flaw on purpose, and **attacks** that exploit them, with
**structured logging** and a **benchmark suite** so the results are
measurable and reproducible rather than anecdotal.

| # | Weakness | Attack | Attacker needs |
|---|----------|--------|-----------------|
| 1 | `p`, `q` too close together | Fermat factorization | just `n` |
| 2 | private exponent `d` too small | Wiener's attack | just `(e, n)` |
| 3 | same message, same small `e`, many moduli | Hastad's broadcast attack | `e` ciphertext/modulus pairs |
| 4 | same modulus, two exponents | Common modulus attack | `(n, e1, c1, e2, c2)` |
| 5 | low-entropy key generation shared across devices | Batch GCD | a pool of moduli |

All five are **real, historically documented failure modes** &mdash; see
[References](#references).

---

## The math, briefly

### 1. Fermat factorization
If `n = p·q` with `p` and `q` close together, write `n` as a difference of
squares: `n = a² - b² = (a-b)(a+b)` where `a ≈ √n`. Starting at
`a = ⌈√n⌉` and incrementing until `a² - n` is a perfect square `b²` finds
`p = a - b`, `q = a + b`. Cost scales with `|p - q| / 2`, so it's only
practical when the gap is abnormally small.

### 2. Wiener's attack
If `d < (1/3)·n^0.25`, then `d` appears as a numerator in the continued
fraction expansion of `e/n`. Walking that expansion's convergents and
testing each one lets you recover `d`, then factor `n` via the quadratic
`x² - (n - φ(n) + 1)x + n = 0`.

### 3. Hastad's broadcast attack
Encrypting the same message `m` under the same small exponent `e` to `e`
(or more) recipients with pairwise-coprime moduli leaks `m` outright: CRT
combines the `e` ciphertexts into a single value `x ≡ mᵉ (mod N)` where
`N` is the product of the moduli; since `m < every nᵢ`, we have `mᵉ < N`,
so `x` **is** `mᵉ` exactly, and an ordinary integer `e`-th root recovers
`m`. No private key, no factoring.

### 4. Common modulus attack
Two "users" sharing one modulus `n` with coprime exponents `e1`, `e2`
leak any message encrypted to both of them: Bezout's identity gives
`a·e1 + b·e2 = 1`, so `c1ᵃ · c2ᵇ ≡ m (mod n)`.

### 5. Batch GCD
If two "independent" moduli secretly share a prime factor,
`gcd(n_i, n_j)` finds it directly &mdash; no factoring algorithm needed at
all. This is the O(k²) pairwise version; real internet-wide scans use an
O(k log k) product-tree version (noted in the code, not implemented here
since a classroom-sized pool doesn't need it).

---

## Project structure

```
rsa-break-lab/
├── src/rsa_break_lab/
│   ├── mathutils.py        # Miller-Rabin, prime gen, modinv, egcd, integer nth root
│   ├── rsa_core.py         # encrypt/decrypt + 5 weak-key generators
│   ├── logging_utils.py    # structured JSONL logging for every attack attempt
│   ├── cli.py              # `generate` + `break` (auto-detects the weakness)
│   └── attacks/
│       ├── fermat.py
│       ├── wiener.py
│       ├── hastad.py
│       ├── common_modulus.py
│       └── batch_gcd.py
├── tests/                  # one test file per attack + mathutils (16 tests, all passing)
├── benchmarks/
│   ├── run_benchmarks.py   # parameter sweeps -> CSV/JSON + matplotlib charts
│   └── results/            # committed output of the last run (see below)
├── sample_data/            # example weak-key targets + a sample attack log
└── docs/                   # the GitHub Pages live demo (Pyodide + Chart.js)
```

---

## Getting started

```bash
git clone https://github.com/YOUR-USERNAME/rsa-break-lab.git
cd rsa-break-lab
pip install -e .          # installs the rsa_break_lab package + CLI, no required deps
pip install -r requirements.txt   # optional: pytest + matplotlib, for tests/benchmarks

python -m unittest discover -s tests -v    # or: pytest tests/
```

### Using the CLI

```bash
# plant a weakness
python -m rsa_break_lab generate close_primes --bits 512 --gap-bits 8 -o target.json
python -m rsa_break_lab generate small_d       --bits 1024 --d-bits 60 -o target.json
python -m rsa_break_lab generate broadcast     --bits 512 --k 3 --e 3  -o target.json
python -m rsa_break_lab generate common_modulus --bits 1024           -o target.json
python -m rsa_break_lab generate shared_prime  --count 12 --bits 256  -o target.json

# auto-detect and break it (tries cheap attacks first, logs every attempt)
python -m rsa_break_lab break target.json
```

Example output:

```
Loaded target (declared weakness: close_primes). Running auto-detection...

  -> FACTORED via Fermat: p=90773577040295315591870673905201319272953651897334120125413006479997768328951
                  q=90773577040295315591870673905201319272953651897334120125413006479997768329131
[2026-11-13T05:34:33] SUCCESS  fermat               0.03 ms  n_bits=512, iterations=1

Done. Full structured log written to logs/attack_log.jsonl
```

Sample targets and a sample log are already committed under
[`sample_data/`](sample_data/) if you want to see real output without
generating your own.

---

## Benchmarks & statistics

```bash
python benchmarks/run_benchmarks.py
```

This sweeps each attack over its relevant parameter (prime gap, `|d|`,
number of intercepted ciphertexts, pool size, modulus size), 3&ndash;5
trials per data point, and writes:

- `benchmarks/results/benchmark_results.{csv,json}` &mdash; every trial, raw
- `benchmarks/results/*.png` &mdash; three charts (also embedded live in the
  web demo via Chart.js, reading the same JSON)

These are the numbers the report should cite; they're committed to the
repo so they're reproducible, not cherry-picked. Two results are worth
highlighting because they land exactly where the theory predicts:

- **Fermat's cost explodes exponentially** once the prime gap exceeds
  ~130 bits for a 512-bit modulus &mdash; see `fermat_time_vs_gap.png`.
- **Wiener's attack has a sharp cutoff at `d ≈ 254` bits** for a
  1024-bit modulus, matching the theoretical bound of `(1/3)·n^0.25`
  almost exactly &mdash; see `wiener_success_vs_dbits.png`.

---

## Logs for the report

Every attack attempt &mdash; successful or not &mdash; is appended as one JSON
line to `logs/attack_log.jsonl` by `logging_utils.AttackLogger`:

```json
{"attack": "fermat", "details": {"iterations": 1, "n_bits": 512}, "duration_ms": 0.03, "success": true, "timestamp": "2026-11-13T05:34:33"}
```

This is the single source of truth behind both the CLI's console output
and the benchmark CSV/JSON &mdash; so anything you screenshot from the
terminal is independently re-derivable from a committed log file.

---

## Hosting the live demo

The `docs/` folder is a complete, static GitHub Pages site. It loads
[Pyodide](https://pyodide.org) (Python compiled to WebAssembly), copies
in the **actual** `src/rsa_break_lab` source files, and runs the attacks
for real in the browser &mdash; nothing is pre-recorded.

1. Push this repo to GitHub.
2. Go to **Settings → Pages**.
3. Under **Build and deployment**, set **Source: Deploy from a branch**.
4. Branch: `main`, folder: **`/docs`**. Save.
5. GitHub will publish to `https://YOUR-USERNAME.github.io/rsa-break-lab/`
   within a minute or two. Update the link at the top of this README.

No build step, no Actions workflow needed for the demo itself (the
`ci.yml` workflow only runs the test suite). If you rename the repo,
the Pages URL changes to match.

> **Note:** the CRT / root-finding logic in `docs/app.js` is the same
> algorithm verified by `tests/`, and was independently re-executed
> outside the browser (same code, plain CPython) while building this
> project to confirm correctness. The live-in-browser path itself
> (loading Pyodide, writing files into its virtual filesystem, calling
> back into JS for streaming logs) couldn't be executed where this
> project was built, since that sandbox has no network access to fetch
> the Pyodide runtime. Test it once it's live, and flag anything that
> doesn't load so it can be fixed.

---

## Limitations &amp; honest caveats

- This is **textbook RSA with no padding** (no OAEP), on purpose &mdash; padding
  is specifically what defeats attacks #3 and #4 in practice, so removing
  it is what makes the lesson visible. **Never use any code in this repo
  for real encryption.**
- Primality testing, prime generation, and all the number theory are
  implemented from scratch (no `sympy`/`cryptography` dependency) so the
  project is self-contained and the same code runs natively and inside
  Pyodide.
- Batch GCD here is the simple O(k²) pairwise version, appropriate for a
  classroom-sized pool. Production-scale scanning (millions of keys)
  uses an O(k log k) product-tree version.

---

## References

- Wiener, M. (1990). *Cryptanalysis of short RSA secret exponents.* IEEE
  Transactions on Information Theory.
- Håstad, J. (1988). *Solving simultaneous modular equations of low
  degree.* SIAM Journal on Computing.
- Lenstra, A. et al. (2012). *Ron was wrong, Whit is right* &mdash; the
  first large-scale empirical batch-GCD study of real-world RSA keys.
- Heninger, N. et al. (2012). *Mining your Ps and Qs: detection of
  widespread weak keys in network devices.* USENIX Security.

## License

MIT &mdash; see [LICENSE](LICENSE). Educational use. Don't actually use any
of this to encrypt anything you care about.
