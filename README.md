# Latent Logic

> Offensive security research tool for authorized penetration testing and red team engagements. Use only on systems you own or have written permission to test.

A Z3 constraint solver that models Windows privilege escalation paths and AV evasion strategies. Feed it a system state — integrity level, privileges, installed security products — and it finds viable paths to SYSTEM and payload placement strategies that avoid detection.

## Install

```bash
pip install -e .
```

Requires Python 3.10+. Dependencies: `z3-solver`.

## How it works

Latent Logic has four layers:

**State** models a Windows system: user context, integrity level, privileges, security products, attack surface (modifiable services, hijackable DLLs, writable paths).

**Knowledge** contains empirical scanner behavioral categories derived from testing across 24 static analysis engines, 54 privilege escalation operations mapped to MITRE ATT&CK, and evasion primitives with per-category blind spot data.

**Solver** encodes the state and operations as Z3 constraints and finds satisfying assignments. For privesc, it finds operation chains that reach SYSTEM from your current integrity level. For evasion, it finds payload placement positions that fall in the blind spots of all specified AVs simultaneously.

**Generator** takes the solver's recommended strategy and builds actual files — PE overlays, header placements, section caves — with the payload positioned where the solver says scanners won't look.

## Usage

### Python API

```python
from latent_logic import LatentLogic
from latent_logic.state import SystemState, Integrity
from latent_logic.solver import UnifiedSolver

# Build state manually (or use ll.analyze() on a live Windows system)
state = SystemState()
state.integrity = Integrity.MEDIUM
state.privileges = {"SeImpersonatePrivilege"}
state.av_products = ["Windows Defender", "CrowdStrike Falcon"]
state._compute_flags()

solver = UnifiedSolver(state)
solver.set_state(state)

# Find path to SYSTEM
privesc = solver.solve_privesc()
print(f"Privesc: {privesc.path}")      # → ['potato_godpotato']
print(f"  {privesc.explanation}")

# Find evasion strategy
evasion = solver.solve_evasion(av_names=["Windows Defender", "CrowdStrike Falcon"])
print(f"Evasion: {evasion.path}")      # → ['pe_header']
print(f"  {evasion.explanation}")

# Solve both together
combined = solver.solve_combined(av_names=["Windows Defender", "CrowdStrike Falcon"])
```

### Generate payload

```python
from latent_logic.generator import PayloadGenerator

gen = PayloadGenerator()
result = gen.generate(payload=shellcode, strategy="pe_overlay")
# result.data        → complete PE with payload in overlay
# result.payload_offset → where the payload sits
# result.description → what was done
```

### CLI (on Windows targets)

```bash
# Scan current system and report everything
python -m latent_logic analyze

# Find privilege escalation path
python -m latent_logic privesc

# Find evasion strategy for specific AVs
python -m latent_logic evade --target WindowsPELoader --avoid Defender

# Generate evasive payload
python -m latent_logic generate --payload shellcode.bin --strategy pe_overlay
```

## Scanner coverage data

The knowledge base categorizes static scanner behavior into four classes based on which PE file regions are inspected during analysis. These categories were derived from empirical testing across 24 static analysis engines.

| Category | Prevalence | Start | Middle | End | Overlay | Header |
|----------|:----------:|:-----:|:------:|:---:|:-------:|:------:|
| Start-only | 67% | ✓ | ✗ | ✗ | ✗ | ✗ |
| Start + overlay | 17% | ✓ | ✗ | ✗ | ✓ | ✗ |
| Broad | 12% | ✓ | ✓ | ✓ | ✗ | ✗ |
| Header-aware | 4% | ✓ | ✗ | ✗ | ✗ | ✓ |

These observations reflect static scanning behavior only. Full endpoint products with behavioral, heuristic, or cloud-based analysis may detect differently at runtime.

## Tests

```bash
python tests/test_state.py       # State model, flags, operations (42 tests)
python tests/test_knowledge.py   # Scanner categories, privesc ops, evasion (54 tests)
python tests/test_solver.py      # Z3 privesc + evasion solving (28 tests)
python tests/test_generator.py   # Payload generation, all strategies (37 tests)
```

161 tests total.

## Architecture

```
latent_logic/
├── state.py       # SystemState, Integrity, UserType, Operation, Goal
├── knowledge.py   # AV profiles (24 vendors), 54 privesc ops, evasion primitives
├── solver.py      # Z3 constraint solver — privesc + evasion
├── generator.py   # Payload generator — PE overlay, header, caves
└── system.py      # LatentLogic orchestrator + CLI (live Windows ingestion)
```

## License

MIT — see [LICENSE](LICENSE).

---

*Bombadil Systems LLC — [bombadil.systems](https://bombadil.systems)*
