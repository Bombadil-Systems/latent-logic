"""
Latent Logic - Knowledge Base

Contains:
  - Scanner behavioral categories (from empirical static analysis testing)
  - Privesc operations (Windows techniques)
  - Interpreter models (for format evasion)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from .state import Operation, Integrity, UserType


# =============================================================================
# SCANNER BEHAVIORAL CATEGORIES - Aggregate data from static scanner testing
# =============================================================================
#
# Scanner behavior is categorized by which file regions are inspected during
# static analysis. Categories are derived from empirical testing across 24
# static analysis engines. No individual products are named or attributed.
#
# These observations reflect static scanning behavior only. Full endpoint
# products with behavioral, heuristic, or cloud-based analysis may detect
# differently at runtime.
#

SCANNER_CATEGORIES = {
    # Category A: Start-only scanners (67% of engines tested)
    # Inspect file entry point / first bytes only
    "start_only": {
        "scans_start": True, "scans_middle": False, "scans_end": False,
        "scans_overlay": False, "scans_header": False,
        "unscanned_regions": ['end', 'middle', 'overlay', 'header'],
        "prevalence": 0.67,
    },
    # Category B: Start + overlay scanners (17% of engines tested)
    # Also inspect PE overlay region
    "start_overlay": {
        "scans_start": True, "scans_middle": False, "scans_end": False,
        "scans_overlay": True, "scans_header": False,
        "unscanned_regions": ['end', 'middle', 'header'],
        "prevalence": 0.17,
    },
    # Category C: Broad scanners (12% of engines tested)
    # Inspect start, middle, and end but not overlay or header
    "broad": {
        "scans_start": True, "scans_middle": True, "scans_end": True,
        "scans_overlay": False, "scans_header": False,
        "unscanned_regions": ['overlay', 'header'],
        "prevalence": 0.12,
    },
    # Category D: Header-aware scanners (4% of engines tested)
    # One of very few that inspect PE header region
    "header_aware": {
        "scans_start": True, "scans_middle": False, "scans_end": False,
        "scans_overlay": False, "scans_header": True,
        "unscanned_regions": ['end', 'middle', 'overlay'],
        "prevalence": 0.04,
    },
}

# Aggregate: percentage of tested scanners that did NOT flag each region
REGION_MISS_RATES = {
    'overlay': 0.79,   # 79% of scanners did not inspect
    'header':  0.96,   # 96% did not inspect
    'end':     0.83,   # 83% did not inspect
    'middle':  0.83,   # 83% did not inspect
}

# Map detected security products to scanner categories.
# This maps the product name (as detected by process enumeration)
# to a behavioral category based on how similar static engines
# performed in testing. This is an approximation — endpoint behavior
# may differ from static scanner behavior.
PRODUCT_CATEGORY_MAP = {
    'Windows Defender':   'start_only',
    'Kaspersky':          'start_only',
    'ESET NOD32':         'start_only',
    'Sophos':             'start_only',
    'SentinelOne':        'start_only',
    'CrowdStrike Falcon': 'start_only',
    'BitDefender':        'start_only',
    'Avast':              'start_only',
    'AVG':                'start_only',
    'Norton':             'start_only',
    'Symantec':           'start_only',
    'F-Secure':           'start_only',
    'Dr.Web':             'start_only',
    'Malwarebytes':       'start_only',
    'Emsisoft':           'start_only',
    'Fortinet':           'start_only',
    'TrendMicro':         'start_overlay',
    'Elastic':            'start_overlay',
    'Carbon Black':       'start_only',
    'Tanium':             'start_only',
}

# Legacy compatibility — AV_PROFILES and AV_NAME_MAP are used throughout
# the codebase. These map to the category system above.
AV_PROFILES = {}
for _cat_name, _cat_data in SCANNER_CATEGORIES.items():
    AV_PROFILES[_cat_name] = _cat_data
# Also register each product name directly for lookup
for _product, _cat in PRODUCT_CATEGORY_MAP.items():
    AV_PROFILES[_product] = SCANNER_CATEGORIES[_cat]

AV_NAME_MAP = {name: name for name in PRODUCT_CATEGORY_MAP}


def get_av_profile(av_name: str) -> Optional[Dict]:
    """Get scanner category profile by product name or category name."""
    if av_name in AV_PROFILES:
        return AV_PROFILES[av_name]
    # Try category map
    cat = PRODUCT_CATEGORY_MAP.get(av_name)
    if cat and cat in SCANNER_CATEGORIES:
        return SCANNER_CATEGORIES[cat]
    # Default: assume most common category
    return SCANNER_CATEGORIES['start_only']


def get_common_blind_spots(av_names: List[str]) -> Set[str]:
    """Find unscanned regions common to ALL specified scanner categories."""
    if not av_names:
        return set()

    common = None
    for av in av_names:
        profile = get_av_profile(av)
        if profile:
            unscanned = set(profile.get('unscanned_regions',
                            profile.get('blind_to', [])))
            if common is None:
                common = unscanned
            else:
                common = common.intersection(unscanned)

    return common or set()


# =============================================================================
# PRIVESC OPERATIONS - Windows techniques modeled for Z3
# =============================================================================

PRIVESC_OPERATIONS = [
    # =========================================================================
    # TOKEN/IMPERSONATION ATTACKS
    # =========================================================================
    Operation(
        name="potato_godpotato",
        description="GodPotato - abuse SeImpersonate via DCOM/RPCSS (works on modern Windows)",
        requires_privileges={'SeImpersonatePrivilege'},
        grants_integrity=Integrity.SYSTEM,
        grants_user=UserType.SYSTEM,
        technique_id="T1134.001",
        risk_level=2,
    ),
    Operation(
        name="potato_sweetpotato",
        description="SweetPotato - SeImpersonate abuse via multiple vectors",
        requires_privileges={'SeImpersonatePrivilege'},
        grants_integrity=Integrity.SYSTEM,
        grants_user=UserType.SYSTEM,
        technique_id="T1134.001",
        risk_level=2,
    ),
    Operation(
        name="potato_printspoofer",
        description="PrintSpoofer - SeImpersonate via print spooler named pipe",
        requires_privileges={'SeImpersonatePrivilege'},
        grants_integrity=Integrity.SYSTEM,
        grants_user=UserType.SYSTEM,
        technique_id="T1134.001",
        risk_level=2,
    ),
    Operation(
        name="token_theft_winlogon",
        description="Steal token from winlogon.exe (always runs as SYSTEM)",
        requires_integrity=Integrity.HIGH,
        requires_admin=True,
        grants_integrity=Integrity.SYSTEM,
        grants_user=UserType.SYSTEM,
        technique_id="T1134.001",
        risk_level=2,
    ),
    Operation(
        name="token_theft_lsass",
        description="Steal token from lsass.exe",
        requires_integrity=Integrity.HIGH,
        requires_admin=True,
        grants_integrity=Integrity.SYSTEM,
        grants_user=UserType.SYSTEM,
        technique_id="T1134.001",
        risk_level=3,
    ),
    Operation(
        name="named_pipe_impersonation",
        description="Create named pipe, trick SYSTEM process to connect, impersonate",
        requires_privileges={'SeImpersonatePrivilege'},
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1134.001",
        risk_level=3,
    ),
    
    # =========================================================================
    # PRIVILEGE ABUSE
    # =========================================================================
    Operation(
        name="debug_injection",
        description="Inject shellcode into SYSTEM process via SeDebugPrivilege",
        requires_privileges={'SeDebugPrivilege'},
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1055.001",
        risk_level=3,
    ),
    Operation(
        name="debug_lsass_dump",
        description="Dump LSASS memory for credentials via SeDebugPrivilege",
        requires_privileges={'SeDebugPrivilege'},
        technique_id="T1003.001",
        risk_level=4,
    ),
    Operation(
        name="backup_sam_dump",
        description="Read SAM/SYSTEM/SECURITY hives via SeBackupPrivilege",
        requires_privileges={'SeBackupPrivilege'},
        technique_id="T1003.002",
        risk_level=2,
    ),
    Operation(
        name="backup_ntds_dump",
        description="Read NTDS.dit from domain controller via SeBackupPrivilege",
        requires_privileges={'SeBackupPrivilege'},
        technique_id="T1003.003",
        risk_level=3,
    ),
    Operation(
        name="restore_dll_overwrite",
        description="Overwrite system DLL via SeRestorePrivilege, get code exec on reboot/service restart",
        requires_privileges={'SeRestorePrivilege'},
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1574.001",
        risk_level=4,
    ),
    Operation(
        name="restore_sethc_backdoor",
        description="Replace sethc.exe (sticky keys) with cmd.exe via SeRestorePrivilege",
        requires_privileges={'SeRestorePrivilege'},
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1546.008",
        risk_level=3,
    ),
    Operation(
        name="driver_load_vuln",
        description="Load vulnerable signed driver (e.g., RTCore64.sys) for kernel R/W",
        requires_privileges={'SeLoadDriverPrivilege'},
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1068",
        risk_level=5,
    ),
    Operation(
        name="take_ownership_sam",
        description="Take ownership of SAM hive, grant read access, extract hashes",
        requires_privileges={'SeTakeOwnershipPrivilege'},
        technique_id="T1003.002",
        risk_level=3,
    ),
    Operation(
        name="assignprimarytoken_createprocess",
        description="Create process with SYSTEM token via SeAssignPrimaryTokenPrivilege",
        requires_privileges={'SeAssignPrimaryTokenPrivilege', 'SeImpersonatePrivilege'},
        grants_integrity=Integrity.SYSTEM,
        grants_user=UserType.SYSTEM,
        technique_id="T1134.002",
        risk_level=3,
    ),
    
    # =========================================================================
    # UAC BYPASS (Medium -> High)
    # =========================================================================
    Operation(
        name="uac_fodhelper",
        description="Bypass UAC via fodhelper.exe registry hijack (HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command)",
        requires_integrity=Integrity.MEDIUM,
        requires_admin=True,
        grants_integrity=Integrity.HIGH,
        technique_id="T1548.002",
        risk_level=2,
    ),
    Operation(
        name="uac_eventvwr",
        description="Bypass UAC via eventvwr.exe registry hijack (mscfile\\shell\\open\\command)",
        requires_integrity=Integrity.MEDIUM,
        requires_admin=True,
        grants_integrity=Integrity.HIGH,
        technique_id="T1548.002",
        risk_level=2,
    ),
    Operation(
        name="uac_computerdefaults",
        description="Bypass UAC via computerdefaults.exe registry hijack",
        requires_integrity=Integrity.MEDIUM,
        requires_admin=True,
        grants_integrity=Integrity.HIGH,
        technique_id="T1548.002",
        risk_level=2,
    ),
    Operation(
        name="uac_sdclt",
        description="Bypass UAC via sdclt.exe (Windows Backup) registry hijack",
        requires_integrity=Integrity.MEDIUM,
        requires_admin=True,
        grants_integrity=Integrity.HIGH,
        technique_id="T1548.002",
        risk_level=2,
    ),
    Operation(
        name="uac_silentcleanup",
        description="Bypass UAC via SilentCleanup scheduled task (Environment variable injection)",
        requires_integrity=Integrity.MEDIUM,
        requires_admin=True,
        grants_integrity=Integrity.HIGH,
        technique_id="T1548.002",
        risk_level=2,
    ),
    Operation(
        name="uac_cmstp",
        description="Bypass UAC via cmstp.exe INF file execution",
        requires_integrity=Integrity.MEDIUM,
        requires_admin=True,
        grants_integrity=Integrity.HIGH,
        technique_id="T1548.002",
        risk_level=3,
    ),
    Operation(
        name="uac_wsreset",
        description="Bypass UAC via wsreset.exe (Windows Store Reset)",
        requires_integrity=Integrity.MEDIUM,
        requires_admin=True,
        grants_integrity=Integrity.HIGH,
        technique_id="T1548.002",
        risk_level=2,
    ),
    Operation(
        name="uac_mock_trusted_directory",
        description="Bypass UAC by creating mock trusted directory (e.g., 'C:\\Windows \\System32')",
        requires_integrity=Integrity.MEDIUM,
        requires_admin=True,
        grants_integrity=Integrity.HIGH,
        technique_id="T1548.002",
        risk_level=3,
    ),
    
    # =========================================================================
    # SERVICE ABUSE
    # =========================================================================
    Operation(
        name="service_binary_overwrite",
        description="Overwrite service binary with payload (requires write access to binary path)",
        requires_service="writable_binary",
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1574.010",
        risk_level=3,
    ),
    Operation(
        name="service_config_modify",
        description="Modify service ImagePath to point to payload (requires SERVICE_CHANGE_CONFIG)",
        requires_service="modifiable",
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1543.003",
        risk_level=3,
    ),
    Operation(
        name="service_dll_hijack",
        description="Place malicious DLL in path searched by SYSTEM service",
        requires_service="hijackable_dll",
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1574.001",
        risk_level=3,
    ),
    Operation(
        name="service_unquoted_path",
        description="Exploit unquoted service path by placing exe at space boundary",
        requires_service="unquoted_path",
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1574.009",
        risk_level=3,
    ),
    Operation(
        name="service_registry_modify",
        description="Modify service registry key (HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>)",
        requires_service="writable_registry",
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1543.003",
        risk_level=3,
    ),
    
    # =========================================================================
    # SCHEDULED TASK ABUSE
    # =========================================================================
    Operation(
        name="schtask_binary_overwrite",
        description="Overwrite binary executed by SYSTEM scheduled task",
        requires_service="writable_task_binary",
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1053.005",
        risk_level=3,
    ),
    Operation(
        name="schtask_create_elevated",
        description="Create scheduled task to run as SYSTEM (requires admin)",
        requires_integrity=Integrity.HIGH,
        requires_admin=True,
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1053.005",
        risk_level=2,
    ),
    
    # =========================================================================
    # DLL HIJACKING
    # =========================================================================
    Operation(
        name="dll_hijack_path",
        description="Place malicious DLL in writable PATH directory searched before system32",
        requires_service="writable_path_dir",
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1574.001",
        risk_level=3,
    ),
    Operation(
        name="dll_hijack_missing",
        description="Supply missing DLL that SYSTEM process tries to load",
        requires_service="missing_dll",
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1574.001",
        risk_level=3,
    ),
    Operation(
        name="dll_hijack_knoyndll",
        description="Exploit KnownDLLs bypass - place DLL in application directory",
        requires_service="app_dir_writable",
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1574.001",
        risk_level=3,
    ),
    
    # =========================================================================
    # REGISTRY ABUSE
    # =========================================================================
    Operation(
        name="registry_alwaysinstallelevated",
        description="Abuse AlwaysInstallElevated - install MSI as SYSTEM",
        requires_service="always_install_elevated",
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1548.002",
        risk_level=2,
    ),
    Operation(
        name="registry_autorun_hijack",
        description="Hijack writable autorun registry entry (Run, RunOnce, etc.)",
        requires_service="writable_autorun",
        technique_id="T1547.001",
        risk_level=3,
    ),
    Operation(
        name="registry_appinitdlls",
        description="Set AppInit_DLLs to load malicious DLL into every GUI process",
        requires_integrity=Integrity.HIGH,
        requires_admin=True,
        technique_id="T1546.010",
        risk_level=4,
    ),
    Operation(
        name="registry_image_file_execution",
        description="Set Image File Execution Options debugger for target process",
        requires_integrity=Integrity.HIGH,
        requires_admin=True,
        technique_id="T1546.012",
        risk_level=3,
    ),
    
    # =========================================================================
    # CREDENTIAL ACCESS
    # =========================================================================
    Operation(
        name="cred_lsass_minidump",
        description="Create minidump of LSASS via comsvcs.dll",
        requires_integrity=Integrity.HIGH,
        requires_admin=True,
        technique_id="T1003.001",
        risk_level=4,
    ),
    Operation(
        name="cred_procdump",
        description="Dump LSASS with procdump.exe (signed Microsoft tool)",
        requires_privileges={'SeDebugPrivilege'},
        technique_id="T1003.001",
        risk_level=4,
    ),
    Operation(
        name="cred_registry_secrets",
        description="Extract LSA secrets from registry",
        requires_integrity=Integrity.SYSTEM,
        technique_id="T1003.004",
        risk_level=3,
    ),
    Operation(
        name="cred_dpapi_masterkeys",
        description="Extract DPAPI master keys for credential decryption",
        requires_integrity=Integrity.SYSTEM,
        technique_id="T1555.004",
        risk_level=3,
    ),
    Operation(
        name="cred_vault_enumerate",
        description="Enumerate Windows Credential Vault",
        requires_integrity=Integrity.MEDIUM,
        technique_id="T1555.004",
        risk_level=2,
    ),
    
    # =========================================================================
    # PERSISTENCE (Not privesc but useful to model)
    # =========================================================================
    Operation(
        name="persist_registry_run",
        description="Add payload to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        requires_integrity=Integrity.MEDIUM,
        technique_id="T1547.001",
        risk_level=2,
    ),
    Operation(
        name="persist_schtask_user",
        description="Create scheduled task running as current user",
        requires_integrity=Integrity.MEDIUM,
        technique_id="T1053.005",
        risk_level=2,
    ),
    Operation(
        name="persist_startup_folder",
        description="Drop payload in user startup folder",
        requires_integrity=Integrity.MEDIUM,
        technique_id="T1547.001",
        risk_level=1,
    ),
    Operation(
        name="persist_wmi_subscription",
        description="Create WMI event subscription for persistence",
        requires_integrity=Integrity.HIGH,
        requires_admin=True,
        technique_id="T1546.003",
        risk_level=3,
    ),
    
    # =========================================================================
    # AMSI/ETW BYPASS (Enables other attacks)
    # =========================================================================
    Operation(
        name="amsi_patch_memory",
        description="Patch AmsiScanBuffer in memory to disable AMSI",
        requires_integrity=Integrity.MEDIUM,
        technique_id="T1562.001",
        risk_level=2,
    ),
    Operation(
        name="amsi_reflection_bypass",
        description="Use reflection to disable AMSI via amsiInitFailed",
        requires_integrity=Integrity.MEDIUM,
        technique_id="T1562.001",
        risk_level=2,
    ),
    Operation(
        name="etw_patch_nttracevent",
        description="Patch NtTraceEvent to blind ETW consumers",
        requires_integrity=Integrity.MEDIUM,
        technique_id="T1562.001",
        risk_level=3,
    ),
    
    # =========================================================================
    # NAMED PIPE / COM ABUSE
    # =========================================================================
    Operation(
        name="printspooler_nightmare",
        description="PrintNightmare - load DLL via print spooler (CVE-2021-34527)",
        requires_integrity=Integrity.MEDIUM,
        grants_integrity=Integrity.SYSTEM,
        technique_id="T1068",
        risk_level=4,
    ),
    Operation(
        name="coercedauth_petitpotam",
        description="PetitPotam - coerce SYSTEM auth via EFSRPC",
        requires_integrity=Integrity.MEDIUM,
        technique_id="T1187",
        risk_level=3,
    ),
    Operation(
        name="coercedauth_dfscoerce",
        description="DFSCoerce - coerce SYSTEM auth via DFS",
        requires_integrity=Integrity.MEDIUM,
        technique_id="T1187",
        risk_level=3,
    ),
    
    # =========================================================================
    # LEGACY (kept for completeness)
    # =========================================================================
    Operation(
        name="uac_eventvwr_legacy",
        description="Bypass UAC via eventvwr.exe registry hijack (mscfile\\shell\\open\\command)",
        requires_integrity=Integrity.MEDIUM,
        requires_admin=True,
        grants_integrity=Integrity.HIGH,
        technique_id="T1548.002",
        risk_level=2,
    ),
    
    # === Credential Access ===
    Operation(
        name="lsass_dump",
        description="Dump LSASS for credentials",
        requires_privileges={'SeDebugPrivilege'},
        technique_id="T1003.001",
        risk_level=4,
    ),
]


def get_available_operations(state) -> List[Operation]:
    """Get operations available from current state."""
    return [op for op in PRIVESC_OPERATIONS if op.can_execute(state)]


# =============================================================================
# EVASION PRIMITIVES - File manipulation techniques
# =============================================================================

@dataclass
class EvasionPrimitive:
    """A file manipulation technique for AV evasion."""
    name: str
    description: str
    target_region: str  # 'overlay', 'header', 'end', 'middle'
    effectiveness: float  # 0-1, based on empirical testing
    complexity: int  # 1-5
    

EVASION_PRIMITIVES = [
    EvasionPrimitive(
        name="pe_overlay",
        description="Place payload in PE overlay (after sections)",
        target_region="overlay",
        effectiveness=0.93,  # undetected by 66/71 static scanners tested
        complexity=2,
    ),
    EvasionPrimitive(
        name="pe_header",
        description="Place payload in DOS stub / PE header",
        target_region="header",
        effectiveness=0.99,  # undetected by 70/71 static scanners tested
        complexity=3,
    ),
    EvasionPrimitive(
        name="file_end",
        description="Place payload at end of file",
        target_region="end",
        effectiveness=0.96,  # undetected by all static scanners tested in testing
        complexity=1,
    ),
    EvasionPrimitive(
        name="file_middle",
        description="Place payload in middle of file",
        target_region="middle",
        effectiveness=0.95,
        complexity=1,
    ),
]


def get_evasion_for_avs(av_names: List[str]) -> List[EvasionPrimitive]:
    """Get evasion primitives effective against all specified AVs."""
    blind_spots = get_common_blind_spots(av_names)
    
    effective = []
    for prim in EVASION_PRIMITIVES:
        if prim.target_region in blind_spots:
            effective.append(prim)
    
    return sorted(effective, key=lambda p: -p.effectiveness)


class KnowledgeBase:
    """Unified access to all knowledge."""
    
    def __init__(self):
        self.av_profiles = AV_PROFILES
        self.operations = PRIVESC_OPERATIONS
        self.evasion_primitives = EVASION_PRIMITIVES
    
    def get_av_profile(self, name: str) -> Optional[Dict]:
        return get_av_profile(name)
    
    def get_available_ops(self, state) -> List[Operation]:
        return get_available_operations(state)
    
    def get_evasion(self, av_names: List[str]) -> List[EvasionPrimitive]:
        return get_evasion_for_avs(av_names)
    
    def get_common_blind_spots(self, av_names: List[str]) -> Set[str]:
        return get_common_blind_spots(av_names)
