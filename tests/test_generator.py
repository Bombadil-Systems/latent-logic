"""
Latent Logic — Generator Tests

Tests payload generation across placement strategies.
Uses benign test payloads only.
"""

import sys
import os
import struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latent_logic.generator import (
    PayloadGenerator, GeneratedPayload, PlacementStrategy,
    generate_evasive_payload, create_demo_exe
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


BENIGN_PAYLOAD = b"TESTPAYLOAD_NOT_MALICIOUS_1234567890"

# ============================================================================
test_section("1. Generator Initialization")
# ============================================================================

gen = PayloadGenerator()
test("PayloadGenerator instantiates", gen is not None)

# ============================================================================
test_section("2. PE Overlay Placement")
# ============================================================================

result = gen.generate(BENIGN_PAYLOAD, "pe_overlay")
test("Overlay generation succeeds", isinstance(result, GeneratedPayload))
test("Result has data", len(result.data) > 0)
test("Result is larger than payload",
     len(result.data) > len(BENIGN_PAYLOAD),
     f"output={len(result.data)} bytes")
test("Strategy recorded correctly",
     result.strategy == PlacementStrategy.PE_OVERLAY)
test("Payload offset recorded", result.payload_offset > 0)
test("Payload size matches",
     result.payload_size == len(BENIGN_PAYLOAD),
     f"expected={len(BENIGN_PAYLOAD)}, got={result.payload_size}")

# Verify MZ header
test("Output starts with MZ",
     result.data[:2] == b"MZ",
     f"got {result.data[:2]}")

# Verify payload is actually in the output at the recorded offset
extracted = result.data[result.payload_offset:result.payload_offset + result.payload_size]
test("Payload recoverable at recorded offset",
     extracted == BENIGN_PAYLOAD)

# ============================================================================
test_section("3. PE Header Placement")
# ============================================================================

small_payload = b"SMALL"
result = gen.generate(small_payload, "pe_header")
test("Header generation succeeds", isinstance(result, GeneratedPayload))
test("Result has data", len(result.data) > 0)
test("Output starts with MZ", result.data[:2] == b"MZ")
test("Strategy is PE_HEADER",
     result.strategy == PlacementStrategy.PE_HEADER)

# ============================================================================
test_section("4. File End Placement")
# ============================================================================

carrier = b"This is a carrier file with some content." * 10
result = gen.generate(BENIGN_PAYLOAD, "file_end", carrier=carrier)
test("File end generation succeeds", isinstance(result, GeneratedPayload))
test("Output larger than carrier",
     len(result.data) > len(carrier),
     f"carrier={len(carrier)}, output={len(result.data)}")
test("Output ends with payload",
     result.data.endswith(BENIGN_PAYLOAD))

# ============================================================================
test_section("5. File Middle Placement")
# ============================================================================

carrier = b"A" * 200
result = gen.generate(BENIGN_PAYLOAD, "file_middle", carrier=carrier)
test("File middle generation succeeds", isinstance(result, GeneratedPayload))
test("Output larger than carrier",
     len(result.data) > len(carrier),
     f"carrier={len(carrier)}, output={len(result.data)}")
test("Payload offset is in the middle",
     result.payload_offset > 0 and result.payload_offset < len(result.data) - len(BENIGN_PAYLOAD),
     f"offset={result.payload_offset}")

# Verify payload recoverable
extracted = result.data[result.payload_offset:result.payload_offset + result.payload_size]
test("Payload recoverable from middle", extracted == BENIGN_PAYLOAD)

# ============================================================================
test_section("6. Minimal PE Construction")
# ============================================================================

pe_data = gen._create_minimal_pe()
test("Minimal PE created", len(pe_data) > 0)
test("Minimal PE starts with MZ", pe_data[:2] == b"MZ")

# Check for PE signature
e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]
test("e_lfanew points to valid offset",
     e_lfanew < len(pe_data),
     f"e_lfanew={e_lfanew:#x}")
if e_lfanew + 4 <= len(pe_data):
    pe_sig = pe_data[e_lfanew:e_lfanew+4]
    test("PE signature present",
         pe_sig == b"PE\x00\x00",
         f"got {pe_sig}")

# ============================================================================
test_section("7. GeneratedPayload Description")
# ============================================================================

result = gen.generate(BENIGN_PAYLOAD, "pe_overlay")
test("Description is a string", isinstance(result.description, str))
test("Description is not empty", len(result.description) > 0)

# ============================================================================
test_section("8. generate_evasive_payload Convenience Function")
# ============================================================================

result = generate_evasive_payload(BENIGN_PAYLOAD, strategy="pe_overlay")
test("Convenience function works", isinstance(result, GeneratedPayload))
test("Returns valid data", len(result.data) > 0)

# ============================================================================
test_section("9. create_demo_exe")
# ============================================================================

demo = create_demo_exe(strategy="pe_overlay")
test("create_demo_exe returns bytes", isinstance(demo, bytes))
test("Demo starts with MZ", demo[:2] == b"MZ")
test("Demo has reasonable size",
     len(demo) > 100,
     f"{len(demo)} bytes")

# ============================================================================
test_section("10. Different Payload Sizes")
# ============================================================================

for size in [1, 16, 256, 1024]:
    payload = bytes(range(256)) * (size // 256 + 1)
    payload = payload[:size]
    result = gen.generate(payload, "pe_overlay")
    test(f"Overlay works with {size}-byte payload",
         len(result.data) > 0 and result.payload_size == size)

# ============================================================================
test_section("11. Loader Stub")
# ============================================================================

stub = gen.create_loader_stub("pe_overlay")
test("Loader stub generated", isinstance(stub, bytes))
test("Loader stub not empty",
     len(stub) > 0,
     f"{len(stub)} bytes")


# ============================================================================
print(f"\n{'='*60}")
print(f"  RESULTS: {passed}/{passed+failed} passed ({100*passed//(passed+failed)}%)")
print(f"{'='*60}")
