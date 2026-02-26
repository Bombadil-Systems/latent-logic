"""
Latent Logic - Unified Security Analysis System

One system, three layers:
  1. INGEST  - Gather system state (privileges, AVs, services, etc.)
  2. REASON  - Z3 constraint solving (find paths to goals)
  3. ADVISE  - Actionable recommendations
  4. GENERATE - Build evasive payloads

Usage:
    from latent_logic import LatentLogic
    
    ll = LatentLogic()
    ll.analyze()           # Ingest current system
    ll.find_privesc()      # Z3: path to SYSTEM
    ll.find_evasion()      # Z3: path past AV
    ll.report()            # Print everything

CLI:
    python -m latent_logic analyze
    python -m latent_logic privesc
    python -m latent_logic evade --target WindowsPELoader --avoid Defender
    python -m latent_logic generate --payload shellcode.bin --strategy pe_overlay
"""

__version__ = "3.1.0"
__author__ = "Bombadil Systems LLC"

from .system import LatentLogic
from .state import SystemState
from .solver import UnifiedSolver
from .knowledge import KnowledgeBase
from .generator import PayloadGenerator, generate_evasive_payload

__all__ = [
    'LatentLogic', 
    'SystemState', 
    'UnifiedSolver', 
    'KnowledgeBase',
    'PayloadGenerator',
    'generate_evasive_payload',
]
