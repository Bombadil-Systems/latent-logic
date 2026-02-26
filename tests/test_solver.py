"""
Latent Logic — Solver Tests

Tests Z3 constraint solving for privilege escalation and AV evasion.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latent_logic.state import SystemState, Integrity, UserType
from latent_logic.solver import UnifiedSolver, SolverResult, find_privesc_path, find_evasion

passed = 0
failed = 0

def test(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")
    if detail:
        print(f"       → {detail}")

def test_section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ============================================================================
test_section("1. Solver Initialization")
# ============================================================================

solver = UnifiedSolver()
test("Solver instantiates without state", solver is not None)
test("Solver has Z3 solver", solver.solver is not None)

state = SystemState()
solver_with_state = UnifiedSolver(state)
test("Solver instantiates with state", solver_with_state.state is not None)

# ============================================================================
test_section("2. SolverResult Structure")
# ============================================================================

result = SolverResult(
    success=True,
    path=["op1", "op2"],
    explanation="test",
    confidence=0.85,
    details={"key": "value"}
)
test("SolverResult success field", result.success is True)
test("SolverResult path field", len(result.path) == 2)
test("SolverResult confidence field", result.confidence == 0.85)
test("SolverResult details field", "key" in result.details)

# ============================================================================
test_section("3. Privesc — SeImpersonate → SYSTEM")
# ============================================================================

state = SystemState()
state.integrity = Integrity.MEDIUM
state.privileges = {"SeImpersonatePrivilege"}
state._compute_flags()

solver = UnifiedSolver(state)
solver.set_state(state)
result = solver.solve_privesc()

test("Privesc succeeds with SeImpersonate",
     result.success,
     f"path={result.path}")
test("Path is not empty", len(result.path) > 0)
test("Explanation provided", len(result.explanation) > 0)

# Check it found a potato-family technique
potato_found = any("potato" in p.lower() or "impersonate" in p.lower()
                    for p in result.path)
test("Found potato/impersonate technique",
     potato_found,
     f"path={result.path}")

# ============================================================================
test_section("4. Privesc — Standard User (no special privs)")
# ============================================================================

state = SystemState()
state.integrity = Integrity.MEDIUM
state.privileges = {"SeChangeNotifyPrivilege"}
state._compute_flags()

solver = UnifiedSolver(state)
solver.set_state(state)
result = solver.solve_privesc()

test("Privesc returns a result for standard user",
     isinstance(result, SolverResult),
     f"success={result.success}, path={result.path}")

# ============================================================================
test_section("5. Privesc — Already SYSTEM")
# ============================================================================

state = SystemState()
state.integrity = Integrity.SYSTEM
state.privileges = set()

solver = UnifiedSolver(state)
solver.set_state(state)
result = solver.solve_privesc()

test("Already SYSTEM → success (already there)",
     result.success,
     f"explanation={result.explanation[:80]}")

# ============================================================================
test_section("6. Privesc — HIGH Integrity Admin")
# ============================================================================

state = SystemState()
state.integrity = Integrity.HIGH
state.user_type = UserType.ADMIN
state.privileges = {"SeDebugPrivilege", "SeImpersonatePrivilege"}
state._compute_flags()

solver = UnifiedSolver(state)
solver.set_state(state)
result = solver.solve_privesc()

test("HIGH admin can reach SYSTEM",
     result.success,
     f"path={result.path}")

# ============================================================================
test_section("7. Evasion — Single AV")
# ============================================================================

solver = UnifiedSolver()
state = SystemState()
state.av_products = ["Windows Defender"]
solver.set_state(state)

result = solver.solve_evasion(av_names=["Windows Defender"])
test("Evasion succeeds against Microsoft",
     result.success,
     f"path={result.path}")
test("Evasion path not empty", len(result.path) > 0)
test("Explanation provided", len(result.explanation) > 0)

# ============================================================================
test_section("8. Evasion — Multiple AVs")
# ============================================================================

solver = UnifiedSolver()
state = SystemState()
state.av_products = ["Windows Defender", "CrowdStrike Falcon"]
solver.set_state(state)

result = solver.solve_evasion(av_names=["Windows Defender", "CrowdStrike Falcon"])
test("Evasion succeeds against Microsoft+CrowdStrike",
     result.success,
     f"path={result.path}")

# ============================================================================
test_section("9. Evasion — Many AVs (harder constraint)")
# ============================================================================

many_avs = ["Windows Defender", "Kaspersky", "ESET NOD32", "BitDefender", "Sophos"]
solver = UnifiedSolver()
state = SystemState()
solver.set_state(state)

result = solver.solve_evasion(av_names=many_avs)
test("Evasion returns result for 5 AVs",
     isinstance(result, SolverResult),
     f"success={result.success}, path={result.path}")

# ============================================================================
test_section("10. Evasion — No AVs (trivial)")
# ============================================================================

solver = UnifiedSolver()
state = SystemState()
solver.set_state(state)

result = solver.solve_evasion(av_names=[])
test("Empty AV list → success",
     result.success,
     f"path={result.path}")

# ============================================================================
test_section("11. Combined Solve (privesc + evasion)")
# ============================================================================

state = SystemState()
state.integrity = Integrity.MEDIUM
state.privileges = {"SeImpersonatePrivilege"}
state.av_products = ["Windows Defender"]
state._compute_flags()

solver = UnifiedSolver(state)
solver.set_state(state)

result = solver.solve_combined(
    privesc_target=Integrity.SYSTEM,
    av_names=["Windows Defender"]
)
test("Combined solve returns dict", isinstance(result, dict))
test("Combined has privesc key", "privesc" in result)
test("Combined has evasion key", "evasion" in result)
test("Combined privesc succeeded",
     result["privesc"].success,
     f"path={result['privesc'].path}")
test("Combined evasion succeeded",
     result["evasion"].success,
     f"path={result['evasion'].path}")

# ============================================================================
test_section("12. Convenience Functions")
# ============================================================================

state = SystemState()
state.integrity = Integrity.MEDIUM
state.privileges = {"SeImpersonatePrivilege"}
state._compute_flags()

result = find_privesc_path(state)
test("find_privesc_path works",
     isinstance(result, SolverResult),
     f"success={result.success}")

result = find_evasion(["Windows Defender"])
test("find_evasion works",
     isinstance(result, SolverResult),
     f"success={result.success}")

# ============================================================================
test_section("13. Solver Reset Between Runs")
# ============================================================================

solver = UnifiedSolver()

state1 = SystemState()
state1.integrity = Integrity.MEDIUM
state1.privileges = {"SeImpersonatePrivilege"}
state1._compute_flags()
solver.set_state(state1)
r1 = solver.solve_privesc()

state2 = SystemState()
state2.integrity = Integrity.LOW
state2.privileges = set()
state2._compute_flags()
solver.set_state(state2)
r2 = solver.solve_privesc()

test("Different states give different results",
     r1.path != r2.path or r1.success != r2.success,
     f"r1={r1.path}, r2={r2.path}")


# ============================================================================
print(f"\n{'='*60}")
print(f"  RESULTS: {passed}/{passed+failed} passed ({100*passed//(passed+failed)}%)")
print(f"{'='*60}")
