"""
Latent Logic — State Tests

Tests SystemState, Integrity levels, UserType, Goal, and Operation models.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latent_logic.state import (
    SystemState, Integrity, UserType, Goal, Operation
)

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
test_section("1. Integrity Levels")
# ============================================================================

test("UNTRUSTED is 0", Integrity.UNTRUSTED.value == 0)
test("LOW is 1", Integrity.LOW.value == 1)
test("MEDIUM is 2", Integrity.MEDIUM.value == 2)
test("HIGH is 3", Integrity.HIGH.value == 3)
test("SYSTEM is 4", Integrity.SYSTEM.value == 4)
test("Ordering: MEDIUM < HIGH", Integrity.MEDIUM.value < Integrity.HIGH.value)
test("Ordering: HIGH < SYSTEM", Integrity.HIGH.value < Integrity.SYSTEM.value)

# ============================================================================
test_section("2. UserType Enum")
# ============================================================================

test("STANDARD exists", UserType.STANDARD is not None)
test("ADMIN exists", UserType.ADMIN is not None)
test("LOCAL_SERVICE exists", UserType.LOCAL_SERVICE is not None)
test("NETWORK_SERVICE exists", UserType.NETWORK_SERVICE is not None)
test("SYSTEM exists", UserType.SYSTEM is not None)

# ============================================================================
test_section("3. SystemState Defaults")
# ============================================================================

state = SystemState()
test("Default username is empty", state.username == "")
test("Default user_type is STANDARD", state.user_type == UserType.STANDARD)
test("Default integrity is MEDIUM", state.integrity == Integrity.MEDIUM)
test("Default privileges is empty set", len(state.privileges) == 0)
test("Default av_products is empty list", len(state.av_products) == 0)
test("Default defender_enabled is True", state.defender_enabled is True)
test("Default amsi_enabled is True", state.amsi_enabled is True)

# ============================================================================
test_section("4. SystemState Population")
# ============================================================================

state = SystemState()
state.username = "pentest_user"
state.user_type = UserType.ADMIN
state.integrity = Integrity.HIGH
state.privileges = {"SeDebugPrivilege", "SeImpersonatePrivilege"}
state.av_products = ["Windows Defender", "CrowdStrike Falcon"]
state.groups = {"Administrators", "Remote Desktop Users"}

test("Username set", state.username == "pentest_user")
test("UserType set to ADMIN", state.user_type == UserType.ADMIN)
test("Integrity set to HIGH", state.integrity == Integrity.HIGH)
test("Two privileges", len(state.privileges) == 2)
test("SeDebugPrivilege present", "SeDebugPrivilege" in state.privileges)
test("Two AV products", len(state.av_products) == 2)
test("Groups populated", "Administrators" in state.groups)

# ============================================================================
test_section("5. SystemState Flags")
# ============================================================================

state = SystemState()
state.privileges = {"SeImpersonatePrivilege"}
state._compute_flags()
test("can_impersonate flag set",
     state.can_impersonate is True,
     f"privileges={state.privileges}")

state2 = SystemState()
state2.privileges = {"SeChangeNotifyPrivilege"}
state2._compute_flags()
test("can_impersonate not set without privilege",
     state2.can_impersonate is False)

# ============================================================================
test_section("6. SystemState update_privileges")
# ============================================================================

state = SystemState()
state.update_privileges({"SeDebugPrivilege", "SeBackupPrivilege"})
test("update_privileges adds privileges", len(state.privileges) == 2)
test("SeDebugPrivilege present after update", "SeDebugPrivilege" in state.privileges)

# ============================================================================
test_section("7. SystemState to_solver_dict")
# ============================================================================

state = SystemState()
state.username = "test"
state.integrity = Integrity.HIGH
state.privileges = {"SeDebugPrivilege"}
state.av_products = ["Kaspersky"]

d = state.to_solver_dict()
test("solver dict has integrity", "integrity" in d)
test("solver dict integrity value", d["integrity"] == Integrity.HIGH.value)
test("solver dict has av_count", "av_count" in d)

# ============================================================================
test_section("8. SystemState summary")
# ============================================================================

state = SystemState()
state.username = "chris"
state.integrity = Integrity.MEDIUM
s = state.summary()
test("summary is a string", isinstance(s, str))
test("summary contains integrity", "MEDIUM" in s)

# ============================================================================
test_section("9. Goal Construction")
# ============================================================================

g1 = Goal.system()
test("Goal.system() target is SYSTEM", g1.target_integrity == Integrity.SYSTEM)

g2 = Goal.admin()
test("Goal.admin() target is HIGH", g2.target_integrity == Integrity.HIGH)

g3 = Goal.evade(["Defender", "CrowdStrike"])
test("Goal.evade() has avoid list", len(g3.avoid_interpreters) == 2)

# ============================================================================
test_section("10. Operation Model")
# ============================================================================

op = Operation(
    name="test_op",
    description="Test operation",
    requires_integrity=Integrity.MEDIUM,
    grants_integrity=Integrity.HIGH,
    requires_privileges={"SeDebugPrivilege"},
)

# Should work: state has MEDIUM + SeDebug
state_ok = SystemState()
state_ok.integrity = Integrity.MEDIUM
state_ok.privileges = {"SeDebugPrivilege"}
test("Operation executable with correct state", op.can_execute(state_ok))

# Should fail: missing privilege
state_bad = SystemState()
state_bad.integrity = Integrity.MEDIUM
state_bad.privileges = set()
test("Operation blocked without privilege", not op.can_execute(state_bad))

# Should fail: too low integrity
state_low = SystemState()
state_low.integrity = Integrity.LOW
state_low.privileges = {"SeDebugPrivilege"}
test("Operation blocked at LOW integrity", not op.can_execute(state_low))

# Apply
result_state = op.apply(state_ok)
test("Operation.apply raises integrity",
     result_state.integrity == Integrity.HIGH,
     f"got {result_state.integrity}")


# ============================================================================
print(f"\n{'='*60}")
print(f"  RESULTS: {passed}/{passed+failed} passed ({100*passed//(passed+failed)}%)")
print(f"{'='*60}")
