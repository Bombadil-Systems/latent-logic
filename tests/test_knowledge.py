"""
Latent Logic — Knowledge Base Tests

Tests scanner categories, privesc operations, evasion primitives.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latent_logic.knowledge import (
    KnowledgeBase, AV_PROFILES, PRIVESC_OPERATIONS, EVASION_PRIMITIVES,
    get_av_profile, get_common_blind_spots, get_available_operations,
    get_evasion_for_avs, AV_NAME_MAP, SCANNER_CATEGORIES,
    PRODUCT_CATEGORY_MAP, REGION_MISS_RATES,
)
from latent_logic.state import SystemState, Integrity, UserType

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
test_section("1. Scanner Categories Exist")
# ============================================================================

test("SCANNER_CATEGORIES is a dict", isinstance(SCANNER_CATEGORIES, dict))
test("At least 4 categories",
     len(SCANNER_CATEGORIES) >= 4,
     f"found {len(SCANNER_CATEGORIES)}")

for cat in ["start_only", "start_overlay", "broad", "header_aware"]:
    test(f"{cat} category exists", cat in SCANNER_CATEGORIES)

# ============================================================================
test_section("2. Scanner Category Structure")
# ============================================================================

profile = SCANNER_CATEGORIES["start_only"]
test("Category has scans_start", "scans_start" in profile)
test("Category has scans_overlay", "scans_overlay" in profile)
test("Category has scans_header", "scans_header" in profile)
test("Category has unscanned_regions", "unscanned_regions" in profile)
test("unscanned_regions is a list", isinstance(profile["unscanned_regions"], list))
test("Category has prevalence", "prevalence" in profile)

# ============================================================================
test_section("3. Product Category Mapping")
# ============================================================================

test("PRODUCT_CATEGORY_MAP is a dict", isinstance(PRODUCT_CATEGORY_MAP, dict))
test("At least 15 products mapped",
     len(PRODUCT_CATEGORY_MAP) >= 15,
     f"found {len(PRODUCT_CATEGORY_MAP)}")

for product in ["Windows Defender", "Kaspersky", "CrowdStrike Falcon",
                 "BitDefender", "SentinelOne", "Sophos"]:
    test(f"{product} mapped",
         product in PRODUCT_CATEGORY_MAP,
         f"-> {PRODUCT_CATEGORY_MAP.get(product, 'MISSING')}")

# ============================================================================
test_section("4. get_av_profile Lookup")
# ============================================================================

p = get_av_profile("Kaspersky")
test("Kaspersky profile found", p is not None)

p_cat = get_av_profile("start_only")
test("Category name lookup works", p_cat is not None)

p_default = get_av_profile("NonExistentAV_12345")
test("Unknown AV returns default (start_only)", p_default is not None)

# ============================================================================
test_section("5. Common Blind Spots")
# ============================================================================

blind = get_common_blind_spots(["Windows Defender", "Kaspersky"])
test("Returns a set", isinstance(blind, set))
test("Blind spots found for Defender+Kaspersky",
     len(blind) > 0,
     f"unscanned: {blind}")

blind_single = get_common_blind_spots(["Windows Defender"])
test("Single product unscanned regions",
     len(blind_single) > 0,
     f"Defender unscanned: {blind_single}")

blind_empty = get_common_blind_spots([])
test("Empty list returns empty set",
     isinstance(blind_empty, set) and len(blind_empty) == 0)

blind_cross = get_common_blind_spots(["Windows Defender", "TrendMicro"])
test("Cross-category reduces common gaps",
     len(blind_cross) <= len(blind_single),
     f"single={len(blind_single)}, cross={len(blind_cross)}")

# ============================================================================
test_section("6. Region Miss Rates")
# ============================================================================

test("REGION_MISS_RATES is a dict", isinstance(REGION_MISS_RATES, dict))
test("Overlay miss rate exists", "overlay" in REGION_MISS_RATES)
test("Header miss rate exists", "header" in REGION_MISS_RATES)
test("Miss rates are floats between 0 and 1",
     all(0 <= v <= 1 for v in REGION_MISS_RATES.values()))

# ============================================================================
test_section("7. Privesc Operations")
# ============================================================================

test("PRIVESC_OPERATIONS is a list", isinstance(PRIVESC_OPERATIONS, list))
test("At least 5 privesc operations",
     len(PRIVESC_OPERATIONS) >= 5,
     f"found {len(PRIVESC_OPERATIONS)}")

op = PRIVESC_OPERATIONS[0]
test("Operation has name", hasattr(op, 'name'))
test("Operation has description", hasattr(op, 'description'))
test("Operation has requires_integrity", hasattr(op, 'requires_integrity'))
test("Operation has grants_integrity", hasattr(op, 'grants_integrity'))

# ============================================================================
test_section("8. get_available_operations")
# ============================================================================

state = SystemState()
state.integrity = Integrity.MEDIUM
state.privileges = set()
ops_medium = get_available_operations(state)
test("Some ops available at MEDIUM",
     isinstance(ops_medium, list),
     f"found {len(ops_medium)} operations")

state_imp = SystemState()
state_imp.integrity = Integrity.MEDIUM
state_imp.privileges = {"SeImpersonatePrivilege"}
state_imp._compute_flags()
ops_imp = get_available_operations(state_imp)
test("More ops with SeImpersonate",
     len(ops_imp) >= len(ops_medium),
     f"without={len(ops_medium)}, with={len(ops_imp)}")

# ============================================================================
test_section("9. Evasion Primitives")
# ============================================================================

test("EVASION_PRIMITIVES is a list", isinstance(EVASION_PRIMITIVES, list))
test("At least 3 evasion primitives",
     len(EVASION_PRIMITIVES) >= 3,
     f"found {len(EVASION_PRIMITIVES)}")

# ============================================================================
test_section("10. get_evasion_for_avs")
# ============================================================================

evasions = get_evasion_for_avs(["Windows Defender", "Kaspersky"])
test("Returns a list", isinstance(evasions, list))
test("At least one evasion option",
     len(evasions) >= 1,
     f"found {len(evasions)} options")

if evasions:
    ev = evasions[0]
    test("Evasion has name", hasattr(ev, 'name'))
    test("Evasion has description", hasattr(ev, 'description'))

# ============================================================================
test_section("11. KnowledgeBase Class")
# ============================================================================

kb = KnowledgeBase()
test("KnowledgeBase instantiates", kb is not None)
test("kb.av_profiles populated",
     len(kb.av_profiles) >= 20,
     f"found {len(kb.av_profiles)}")

p = kb.get_av_profile("SentinelOne")
test("kb.get_av_profile works", p is not None)

blind = kb.get_common_blind_spots(["Windows Defender", "SentinelOne"])
test("kb.get_common_blind_spots works",
     isinstance(blind, set))

state = SystemState()
state.integrity = Integrity.MEDIUM
ops = kb.get_available_ops(state)
test("kb.get_available_ops works", isinstance(ops, list))

evasions = kb.get_evasion(["Windows Defender"])
test("kb.get_evasion works", isinstance(evasions, list))

# ============================================================================
test_section("12. AV Name Mapping (Legacy)")
# ============================================================================

test("AV_NAME_MAP exists", AV_NAME_MAP is not None)
test("AV_NAME_MAP is a dict", isinstance(AV_NAME_MAP, dict))


# ============================================================================
print(f"\n{'='*60}")
print(f"  RESULTS: {passed}/{passed+failed} passed ({100*passed//(passed+failed)}%)")
print(f"{'='*60}")
