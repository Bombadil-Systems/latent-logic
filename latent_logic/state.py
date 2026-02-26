"""
Latent Logic - System State

Represents the current system state in a form Z3 can reason about.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional
from enum import Enum, auto


class Integrity(Enum):
    """Windows integrity levels."""
    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    SYSTEM = 4


class UserType(Enum):
    """User account types."""
    STANDARD = auto()
    ADMIN = auto()
    LOCAL_SERVICE = auto()
    NETWORK_SERVICE = auto()
    SYSTEM = auto()


@dataclass
class SystemState:
    """
    Complete system state - input to the Z3 solver.
    
    This is the "world" that the solver reasons about.
    """
    
    # === USER CONTEXT ===
    username: str = ""
    user_type: UserType = UserType.STANDARD
    integrity: Integrity = Integrity.MEDIUM
    privileges: Set[str] = field(default_factory=set)
    groups: Set[str] = field(default_factory=set)
    
    # === SECURITY PRODUCTS ===
    av_products: List[str] = field(default_factory=list)
    edr_products: List[str] = field(default_factory=list)
    defender_enabled: bool = True
    amsi_enabled: bool = True
    
    # === ATTACK SURFACE ===
    # Services we can modify
    modifiable_services: List[Dict] = field(default_factory=list)
    # Scheduled tasks we can modify  
    modifiable_tasks: List[Dict] = field(default_factory=list)
    # Writable paths in system locations
    writable_paths: List[str] = field(default_factory=list)
    # Hijackable DLLs
    hijackable_dlls: List[Dict] = field(default_factory=list)
    # Processes we can interact with
    injectable_processes: List[Dict] = field(default_factory=list)
    # Handles we hold
    handles: Dict[str, List[str]] = field(default_factory=dict)
    
    # === NETWORK ===
    domain_joined: bool = False
    domain_name: str = ""
    
    # === DERIVED FLAGS (computed) ===
    can_impersonate: bool = False
    can_debug: bool = False
    can_load_driver: bool = False
    can_backup: bool = False
    can_restore: bool = False
    can_take_ownership: bool = False
    is_admin: bool = False
    is_system: bool = False
    
    def __post_init__(self):
        """Compute derived flags from privileges."""
        self._compute_flags()
    
    def _compute_flags(self):
        """Set convenience flags based on privileges."""
        self.can_impersonate = 'SeImpersonatePrivilege' in self.privileges
        self.can_debug = 'SeDebugPrivilege' in self.privileges
        self.can_load_driver = 'SeLoadDriverPrivilege' in self.privileges
        self.can_backup = 'SeBackupPrivilege' in self.privileges
        self.can_restore = 'SeRestorePrivilege' in self.privileges
        self.can_take_ownership = 'SeTakeOwnershipPrivilege' in self.privileges
        self.is_admin = 'Administrators' in self.groups or self.user_type == UserType.ADMIN
        self.is_system = self.integrity == Integrity.SYSTEM or self.user_type == UserType.SYSTEM
    
    def update_privileges(self, privs: Set[str]):
        """Update privileges and recompute flags."""
        self.privileges = privs
        self._compute_flags()
    
    def to_solver_dict(self) -> Dict:
        """Convert to dict format for Z3 solver."""
        return {
            'integrity': self.integrity.value,
            'privileges': list(self.privileges),
            'is_admin': self.is_admin,
            'can_impersonate': self.can_impersonate,
            'can_debug': self.can_debug,
            'modifiable_services': len(self.modifiable_services),
            'injectable_processes': len(self.injectable_processes),
            'av_count': len(self.av_products),
        }
    
    def summary(self) -> str:
        """One-line summary of state."""
        parts = [
            f"{self.integrity.name}",
            f"{'ADMIN' if self.is_admin else 'USER'}",
            f"{len(self.privileges)} privs",
            f"{len(self.av_products)} AVs",
        ]
        return " | ".join(parts)


@dataclass  
class Goal:
    """Represents a goal state we want to reach."""
    
    # Privesc goals
    target_integrity: Optional[Integrity] = None
    target_user: Optional[UserType] = None
    need_privilege: Optional[str] = None
    
    # Evasion goals
    target_loader: Optional[str] = None  # e.g., "WindowsPELoader"
    avoid_interpreters: List[str] = field(default_factory=list)  # e.g., ["Defender", "ESET"]
    
    @classmethod
    def system(cls) -> 'Goal':
        """Goal: become SYSTEM."""
        return cls(target_integrity=Integrity.SYSTEM, target_user=UserType.SYSTEM)
    
    @classmethod
    def admin(cls) -> 'Goal':
        """Goal: become admin."""
        return cls(target_integrity=Integrity.HIGH)
    
    @classmethod
    def evade(cls, avoid: List[str]) -> 'Goal':
        """Goal: evade specific AVs."""
        return cls(target_loader="WindowsPELoader", avoid_interpreters=avoid)


@dataclass
class Operation:
    """A single operation that transforms state."""
    name: str
    description: str
    
    # Preconditions (what we need)
    requires_integrity: Optional[Integrity] = None
    requires_privileges: Set[str] = field(default_factory=set)
    requires_admin: bool = False
    requires_service: Optional[str] = None
    requires_process: Optional[str] = None
    
    # Effects (what we get)
    grants_integrity: Optional[Integrity] = None
    grants_privileges: Set[str] = field(default_factory=set)
    grants_user: Optional[UserType] = None
    
    # Metadata
    technique_id: str = ""  # MITRE ATT&CK
    risk_level: int = 1  # 1-5
    
    def can_execute(self, state: SystemState) -> bool:
        """Check if operation can execute given current state."""
        # Check integrity requirement
        if self.requires_integrity and state.integrity.value < self.requires_integrity.value:
            return False
        
        # Check privilege requirements
        if self.requires_privileges and not self.requires_privileges.issubset(state.privileges):
            return False
        
        # Check admin requirement
        if self.requires_admin and not state.is_admin:
            return False
        
        # Check service requirement
        if self.requires_service:
            service_names = [s.get('name') for s in state.modifiable_services]
            if self.requires_service not in service_names:
                return False
        
        return True
    
    def apply(self, state: SystemState) -> SystemState:
        """Apply operation to state, return new state."""
        # This would be used for simulation/planning
        # For now, just return state with effects applied
        import copy
        new_state = copy.deepcopy(state)
        
        if self.grants_integrity:
            new_state.integrity = self.grants_integrity
        if self.grants_privileges:
            new_state.privileges.update(self.grants_privileges)
        if self.grants_user:
            new_state.user_type = self.grants_user
        
        new_state._compute_flags()
        return new_state
