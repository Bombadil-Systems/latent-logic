"""
Latent Logic - Unified Z3 Solver

Solves two problems:
  1. PRIVESC: Given current state, find path to SYSTEM
  2. EVASION: Given target loader + AVs to avoid, find file configuration

Both use Z3 constraint satisfaction.
"""

from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from z3 import *

from .state import SystemState, Goal, Operation, Integrity, UserType
from .knowledge import (
    PRIVESC_OPERATIONS, AV_PROFILES, EVASION_PRIMITIVES,
    get_av_profile, get_common_blind_spots
)


@dataclass
class SolverResult:
    """Result from Z3 solver."""
    success: bool
    path: List[str]  # Operation names or primitive names
    explanation: str
    confidence: float
    details: Dict


class UnifiedSolver:
    """
    Z3-based solver for security analysis.
    
    Models system state as symbolic variables, operations as constraints,
    and finds satisfying assignments that reach goal states.
    """
    
    def __init__(self, state: Optional[SystemState] = None):
        self.state = state
        self.solver = Solver()
        
        # Symbolic state variables
        self._init_symbols()
    
    def _init_symbols(self):
        """Initialize Z3 symbolic variables."""
        # Integrity level (0-4)
        self.sym_integrity = Int('integrity')
        
        # Privileges as bitvector (each bit = one privilege)
        self.privilege_bits = {
            'SeImpersonatePrivilege': 0,
            'SeDebugPrivilege': 1,
            'SeBackupPrivilege': 2,
            'SeRestorePrivilege': 3,
            'SeLoadDriverPrivilege': 4,
            'SeTakeOwnershipPrivilege': 5,
            'SeChangeNotifyPrivilege': 6,
            'SeAssignPrimaryTokenPrivilege': 7,
        }
        self.sym_privileges = BitVec('privileges', 16)
        
        # Boolean flags
        self.sym_is_admin = Bool('is_admin')
        self.sym_has_modifiable_service = Bool('has_modifiable_service')
        self.sym_has_injectable_process = Bool('has_injectable_process')
        
        # Evasion state
        self.sym_payload_position = Int('payload_position')  # 0=start, 1=middle, 2=end, 3=overlay, 4=header
        self.sym_detected = Bool('detected')
    
    def set_state(self, state: SystemState):
        """Set current system state as initial constraints."""
        self.state = state
        self.solver.reset()
        
        # Set integrity
        self.solver.add(self.sym_integrity == state.integrity.value)
        
        # Set privileges
        priv_value = 0
        for priv, bit in self.privilege_bits.items():
            if priv in state.privileges:
                priv_value |= (1 << bit)
        self.solver.add(self.sym_privileges == priv_value)
        
        # Set flags
        self.solver.add(self.sym_is_admin == state.is_admin)
        self.solver.add(self.sym_has_modifiable_service == (len(state.modifiable_services) > 0))
        self.solver.add(self.sym_has_injectable_process == (len(state.injectable_processes) > 0))
    
    def _simulate_state_after(self, state: SystemState, op) -> SystemState:
        """Simulate state after applying an operation."""
        import copy
        new_state = copy.deepcopy(state)
        
        # Apply operation effects
        if op.grants_integrity:
            new_state.integrity = op.grants_integrity
        if op.grants_privileges:
            new_state.privileges.update(op.grants_privileges)
        if op.grants_user:
            new_state.user_type = op.grants_user
        
        # Typical privileges gained at each level
        if new_state.integrity == Integrity.HIGH and state.is_admin:
            elevated_privs = {
                'SeImpersonatePrivilege', 'SeDebugPrivilege',
                'SeBackupPrivilege', 'SeRestorePrivilege',
                'SeChangeNotifyPrivilege', 'SeCreateGlobalPrivilege',
                'SeIncreaseQuotaPrivilege', 'SeSecurityPrivilege',
            }
            new_state.privileges.update(elevated_privs)
        
        if new_state.integrity == Integrity.SYSTEM:
            system_privs = {
                'SeImpersonatePrivilege', 'SeDebugPrivilege',
                'SeBackupPrivilege', 'SeRestorePrivilege',
                'SeLoadDriverPrivilege', 'SeTakeOwnershipPrivilege',
                'SeAssignPrimaryTokenPrivilege', 'SeTcbPrivilege',
            }
            new_state.privileges.update(system_privs)
        
        new_state._compute_flags()
        return new_state
    
    def _get_prerequisite_ops(self, state: SystemState) -> List:
        """Get operations that should be prepended based on state."""
        prereqs = []
        
        # If AMSI is enabled, consider AMSI bypass for PowerShell-based attacks
        if state.amsi_enabled:
            amsi_ops = [op for op in PRIVESC_OPERATIONS 
                       if op.name.startswith('amsi_') and op.can_execute(state)]
            if amsi_ops:
                prereqs.extend(amsi_ops)
        
        return prereqs
    
    def _find_chains(self, 
                     state: SystemState, 
                     target: Integrity, 
                     max_depth: int = 3,
                     current_path: List = None,
                     visited: set = None) -> List[Dict]:
        """
        Recursively find all chains to target using BFS/DFS hybrid.
        
        Returns list of path dicts.
        """
        if current_path is None:
            current_path = []
        if visited is None:
            visited = set()
        
        # Base case: reached target
        if state.integrity.value >= target.value:
            if current_path:  # Don't return empty paths
                return [{
                    'steps': [op.name for op in current_path],
                    'operations': current_path,
                    'description': ' → '.join(op.description for op in current_path),
                    'techniques': [op.technique_id for op in current_path],
                    'risk': max(op.risk_level for op in current_path),
                    'confidence': 0.95 - (0.05 * len(current_path)),  # Decreases with length
                    'type': f"{len(current_path)}-step",
                }]
            return []
        
        # Base case: max depth reached
        if len(current_path) >= max_depth:
            return []
        
        # Get available operations
        available = [op for op in PRIVESC_OPERATIONS if op.can_execute(state)]
        
        all_chains = []
        
        for op in available:
            # Skip if we've used this exact operation before (avoid loops)
            if op.name in visited:
                continue
            
            # Skip operations that don't advance us
            if not op.grants_integrity and not op.grants_privileges:
                continue
            
            # Simulate applying operation
            new_state = self._simulate_state_after(state, op)
            
            # Only proceed if we made progress
            if (new_state.integrity.value > state.integrity.value or 
                len(new_state.privileges) > len(state.privileges)):
                
                new_visited = visited | {op.name}
                new_path = current_path + [op]
                
                # Recurse
                chains = self._find_chains(
                    new_state, target, max_depth, new_path, new_visited
                )
                all_chains.extend(chains)
        
        return all_chains
    
    def solve_privesc(self, target: Integrity = Integrity.SYSTEM, max_depth: int = 3) -> SolverResult:
        """
        Find path from current state to target integrity.
        
        Uses recursive chain finding to discover multi-step paths.
        Considers prerequisites (AMSI bypass, etc.) and ranks by risk.
        
        Args:
            target: Target integrity level (default: SYSTEM)
            max_depth: Maximum chain length to consider (default: 3)
        
        Returns the best path, with all viable paths in details.
        """
        if not self.state:
            return SolverResult(False, [], "No state set", 0.0, {})
        
        # Already at target?
        if self.state.integrity.value >= target.value:
            return SolverResult(
                True, [], 
                f"Already at {self.state.integrity.name}", 
                1.0, {}
            )
        
        # Find all chains up to max_depth
        all_paths = self._find_chains(self.state, target, max_depth)
        
        if not all_paths:
            available = [op for op in PRIVESC_OPERATIONS if op.can_execute(self.state)]
            return SolverResult(
                False, [],
                "No path to target found with current state",
                0.0,
                {'available_ops': [op.name for op in available]}
            )
        
        # Deduplicate paths (same sequence of steps)
        seen = set()
        unique_paths = []
        for path in all_paths:
            key = tuple(path['steps'])
            if key not in seen:
                seen.add(key)
                unique_paths.append(path)
        
        # Sort paths: prefer lower risk, then higher confidence, then fewer steps
        unique_paths.sort(key=lambda p: (p['risk'], -p['confidence'], len(p['steps'])))
        
        # Check if we should prepend prerequisites
        prereqs = self._get_prerequisite_ops(self.state)
        if prereqs and unique_paths:
            # Create enhanced paths with prereqs for PowerShell-based techniques
            enhanced_paths = []
            for path in unique_paths[:10]:  # Only enhance top paths
                # Check if any step might benefit from AMSI bypass
                needs_amsi = any('powershell' in op.lower() or 'script' in op.lower() 
                                for op in path['steps'])
                if needs_amsi or self.state.amsi_enabled:
                    for prereq in prereqs:
                        enhanced = {
                            'steps': [prereq.name] + path['steps'],
                            'description': f"[PREREQ: {prereq.description}] → {path['description']}",
                            'techniques': [prereq.technique_id] + path['techniques'],
                            'risk': max(prereq.risk_level, path['risk']),
                            'confidence': path['confidence'] * 0.95,
                            'type': f"prereq+{path['type']}",
                        }
                        enhanced_paths.append(enhanced)
            
            # Add enhanced paths but keep originals higher priority
            unique_paths = unique_paths + enhanced_paths
        
        # Best path
        best = unique_paths[0]
        
        return SolverResult(
            True,
            best['steps'],
            best['description'],
            best['confidence'],
            {
                'best_path': best,
                'all_paths': unique_paths,
                'path_count': len(unique_paths),
                'techniques': best['techniques'],
                'risk': best['risk'],
            }
        )
    
    def solve_evasion(self, 
                      av_names: List[str],
                      target_loader: str = "WindowsPELoader") -> SolverResult:
        """
        Find file configuration that evades specified AVs.
        
        Uses Z3 to find payload position that:
          - Loader can execute (payload accessible)
          - All specified AVs miss (position in their blind spots)
        """
        if not av_names:
            return SolverResult(
                True,
                ['any_position'],
                "No AVs to evade",
                1.0,
                {}
            )
        
        # Get blind spots for each AV
        common_blind = get_common_blind_spots(av_names)
        
        if not common_blind:
            return SolverResult(
                False,
                [],
                f"No common blind spots across {av_names}",
                0.0,
                {'avs': av_names}
            )
        
        # Map positions to primitives
        position_map = {
            'end': 'file_end',
            'middle': 'file_middle', 
            'overlay': 'pe_overlay',
            'header': 'pe_header',
        }
        
        # Find best primitive (highest effectiveness)
        best_prim = None
        best_eff = 0.0
        
        for pos in common_blind:
            prim_name = position_map.get(pos)
            if prim_name:
                for prim in EVASION_PRIMITIVES:
                    if prim.name == prim_name and prim.effectiveness > best_eff:
                        best_prim = prim
                        best_eff = prim.effectiveness
        
        if best_prim:
            # Calculate confidence based on number of AVs
            # More AVs = lower confidence (more chances for detection)
            confidence = best_eff * (0.95 ** (len(av_names) - 1))
            
            return SolverResult(
                True,
                [best_prim.name],
                f"Place payload in {best_prim.target_region}: {best_prim.description}",
                confidence,
                {
                    'primitive': best_prim.name,
                    'region': best_prim.target_region,
                    'effectiveness': best_prim.effectiveness,
                    'complexity': best_prim.complexity,
                    'evades': av_names,
                    'blind_spots': list(common_blind),
                }
            )
        
        return SolverResult(
            False,
            [],
            "No effective evasion primitive found",
            0.0,
            {'common_blind': list(common_blind)}
        )
    
    def solve_combined(self, 
                       privesc_target: Integrity = Integrity.SYSTEM,
                       av_names: Optional[List[str]] = None) -> Dict:
        """
        Solve both privesc and evasion together.
        
        Returns combined strategy: how to escalate while evading detection.
        """
        results = {
            'privesc': None,
            'evasion': None,
            'combined_strategy': None,
        }
        
        # Solve privesc
        privesc_result = self.solve_privesc(privesc_target)
        results['privesc'] = privesc_result
        
        # Solve evasion if AVs specified
        if av_names:
            evasion_result = self.solve_evasion(av_names)
            results['evasion'] = evasion_result
            
            # Combine into strategy
            if privesc_result.success and evasion_result.success:
                results['combined_strategy'] = {
                    'payload_delivery': evasion_result.path[0] if evasion_result.path else None,
                    'execution_path': privesc_result.path,
                    'confidence': privesc_result.confidence * evasion_result.confidence,
                    'summary': f"Deliver via {evasion_result.details.get('region', '?')}, "
                              f"execute via {privesc_result.path[0] if privesc_result.path else '?'}"
                }
        
        return results


# Convenience functions
def find_privesc_path(state: SystemState) -> SolverResult:
    """Quick privesc path finding."""
    solver = UnifiedSolver(state)
    solver.set_state(state)
    return solver.solve_privesc()


def find_evasion(av_names: List[str]) -> SolverResult:
    """Quick evasion finding."""
    solver = UnifiedSolver()
    return solver.solve_evasion(av_names)
