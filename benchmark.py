import mtree, bls as bls_module, lattice as lattice_module, rsa as rsa_module
import time
import statistics
import argparse
import random
import string
import sys

# ---------------------------------------------------------------------------
# CLI / config
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Benchmark accumulator schemes over N repeated trials."
    )
    parser.add_argument(
        "-n", "--iterations", type=int, default=10,
        help="Number of times each operation is repeated (default: 10)"
    )
    parser.add_argument(
        "--set-size", type=int, default=4,
        help="Number of elements in the accumulator set (default: 4)"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)"
    )
    parser.add_argument(
        "--schemes", nargs="+",
        choices=["merkle", "bls", "lattice", "rsa", "all"],
        default=["all"],
        help="Which schemes to benchmark (default: all)"
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def random_name(rng, length=6):
    return "".join(rng.choices(string.ascii_lowercase, k=length))


def make_dataset(set_size: int, seed: int):
    rng = random.Random(seed)
    elems = [random_name(rng) for _ in range(set_size)]
    # Guarantee uniqueness
    elems = list(dict.fromkeys(elems))
    while len(elems) < set_size:
        elems.append(random_name(rng))
        elems = list(dict.fromkeys(elems))

    # Pick a member and a guaranteed non-member
    target = rng.choice(elems)
    non_target = random_name(rng)
    while non_target in elems:
        non_target = random_name(rng)

    return elems, target, non_target


def timed_run(fn, n: int):
    """Run *fn* n times and return (results_list, timings_list_in_sec)."""
    results, timings = [], []
    for _ in range(n):
        t0 = time.perf_counter()
        result = fn()
        t1 = time.perf_counter()
        results.append(result)
        timings.append(t1 - t0)
    return results, timings


def stats(timings):
    mean = statistics.mean(timings)
    lo   = min(timings)
    hi   = max(timings)
    std  = statistics.stdev(timings) if len(timings) > 1 else 0.0
    return mean, lo, hi, std


def print_stats(label: str, op: str, n: int, timings):
    mean, lo, hi, std = stats(timings)
    print(
        f"  [{label}] {op:40s} "
        f"mean={mean*1e3:8.3f}ms  "
        f"min={lo*1e3:8.3f}ms  "
        f"max={hi*1e3:8.3f}ms  "
        f"std={std*1e3:8.3f}ms  (n={n})"
    )


# ---------------------------------------------------------------------------
# Core benchmark driver
# ---------------------------------------------------------------------------

def benchmark(
    label: str,
    n: int,
    m_proof_fn,
    m_verify_fn,
    nm_proof_fn,
    nm_verify_fn,
    target: str,
    non_target: str,
):
    """
    Run each of the four operations N times and print aggregate statistics.

    m_proof_fn()       -> proof
    m_verify_fn(proof) -> (ignored; assumed correct)
    nm_proof_fn()      -> proof
    nm_verify_fn(proof)-> (ignored)
    """
    print(f"\n{'='*70}")
    print(f"  Scheme : {label}")
    print(f"  Member : {target!r}   Non-member : {non_target!r}   Iterations : {n}")
    print(f"{'='*70}")

    # -- membership proof --
    m_proofs, m_proof_times = timed_run(m_proof_fn, n)
    print_stats(label, f"membership proof   ({target!r})", n, m_proof_times)

    # -- membership verify --
    _, m_verify_times = timed_run(lambda: m_verify_fn(m_proofs[0]), n)
    print_stats(label, f"membership verify  ({target!r})", n, m_verify_times)

    # -- non-membership proof --
    nm_proofs, nm_proof_times = timed_run(nm_proof_fn, n)
    print_stats(label, f"non-membership proof   ({non_target!r})", n, nm_proof_times)

    # -- non-membership verify --
    _, nm_verify_times = timed_run(lambda: nm_verify_fn(nm_proofs[0]), n)
    print_stats(label, f"non-membership verify  ({non_target!r})", n, nm_verify_times)

    return {
        "m_proof":    m_proof_times,
        "m_verify":   m_verify_times,
        "nm_proof":   nm_proof_times,
        "nm_verify":  nm_verify_times,
    }


# ---------------------------------------------------------------------------
# Per-scheme setup + benchmark wrappers
# ---------------------------------------------------------------------------

def run_merkle(elems, target, non_target, n):
    mt = mtree.Tree(elems)
    root = mt.get_root()
    return benchmark(
        "Merkle", n,
        m_proof_fn  = lambda: mt.get_membership_proof(target),
        m_verify_fn = lambda p: mt.verify(root, target, p[0], p[1]),
        nm_proof_fn = lambda: mt.get_nonmembership_proof(non_target),
        nm_verify_fn= lambda p: mt.verify_nonmembership_proof(root, non_target, p[0], p[1]),
        target=target, non_target=non_target,
    )


def run_bls(elems, target, non_target, n):
    acc_obj = bls_module.BLSAcc(max_set_size=max(len(elems) + 5, 10), secret_s=5)
    poly, acc = acc_obj.accumulate(elems)
    return benchmark(
        "BLS", n,
        m_proof_fn  = lambda: acc_obj.prove_membership(poly, target),
        m_verify_fn = lambda p: acc_obj.verify_membership(acc, target, p),
        nm_proof_fn = lambda: acc_obj.prove_non_membership(poly, non_target),
        nm_verify_fn= lambda p: acc_obj.verify_non_membership(acc, non_target, p),
        target=target, non_target=non_target,
    )


def run_lattice(elems, target, non_target, n):
    lat = lattice_module.LatticeAccumulator(seed=0)
    lat.accumulate(elems)
    return benchmark(
        "Lattice", n,
        m_proof_fn  = lambda: lat.prove_membership(target),
        m_verify_fn = lambda p: lat.verify_membership(p),
        nm_proof_fn = lambda: lat.prove_non_membership(non_target),
        nm_verify_fn= lambda p: lat.verify_non_membership(p),
        target=target, non_target=non_target,
    )


def run_rsa(elems, target, non_target, n):
    rsa_acc = rsa_module.RSAAccumulator(bits=1024)
    rsa_acc.batch_add(elems)
    return benchmark(
        "RSA", n,
        m_proof_fn  = lambda: rsa_acc.prove_membership(target),
        m_verify_fn = lambda p: rsa_acc.verify_membership(target, p),
        nm_proof_fn = lambda: rsa_acc.prove_non_membership(non_target),
        nm_verify_fn= lambda p: rsa_acc.verify_non_membership(non_target, p),
        target=target, non_target=non_target,
    )


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def print_summary(all_results: dict):
    ops = ["m_proof", "m_verify", "nm_proof", "nm_verify"]
    op_labels = {
        "m_proof":  "Membership proof",
        "m_verify": "Membership verify",
        "nm_proof": "Non-membership proof",
        "nm_verify":"Non-membership verify",
    }

    print(f"\n{'='*70}")
    print("  SUMMARY  (mean latency in ms)")
    print(f"{'='*70}")
    header = f"  {'Operation':<24}" + "".join(f"  {s:>10}" for s in all_results)
    print(header)
    print(f"  {'-'*22}" + ("  " + "-"*10) * len(all_results))

    for op in ops:
        row = f"  {op_labels[op]:<24}"
        for scheme, res in all_results.items():
            if op in res:
                m = statistics.mean(res[op]) * 1e3
                row += f"  {m:>10.3f}"
            else:
                row += f"  {'N/A':>10}"
        print(row)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

SCHEME_RUNNERS = {
    "merkle":  run_merkle,
    "bls":     run_bls,
    "lattice": run_lattice,
    "rsa":     run_rsa,
}

def main():
    args = parse_args()
    n         = args.iterations
    set_size  = args.set_size
    seed      = args.seed
    schemes   = args.schemes

    if "all" in schemes:
        schemes = list(SCHEME_RUNNERS.keys())

    elems, target, non_target = make_dataset(set_size, seed)

    print(f"\nBenchmark configuration")
    print(f"  Iterations : {n}")
    print(f"  Set size   : {len(elems)}")
    print(f"  Elements   : {elems}")
    print(f"  Member     : {target!r}")
    print(f"  Non-member : {non_target!r}")
    print(f"  Schemes    : {schemes}")

    all_results = {}
    for scheme in schemes:
        runner = SCHEME_RUNNERS[scheme]
        try:
            all_results[scheme] = runner(elems, target, non_target, n)
        except Exception as exc:
            print(f"\n[{scheme}] ERROR: {exc}", file=sys.stderr)

    if len(all_results) > 1:
        print_summary(all_results)


if __name__ == "__main__":
    main()
