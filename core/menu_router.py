# file: core/menu_router.py
"""
Menu Router for ShadowTrace-IR.
Handles navigation between different modules and features.
"""

from pathlib import Path
from typing import Optional

from core.ui import UI
from core.config_manager import ConfigManager
from modules.hashing import HashingModule
from modules.metadata import MetadataModule
from modules.strings import StringsModule
from modules.pe_inspection import PEInspectionModule
from modules.yara_scan import YARAScanModule
from modules.osint_vt import VirusTotalModule
from modules.osint_ha import HybridAnalysisModule
from modules.osint_otx import AlienVaultOTXModule
from modules.ioc_extractor import IOCExtractorModule
from reports.report_builder import ReportBuilder


class MenuRouter:
    """Main menu router and application controller."""
    
    def __init__(self, ui: UI, config_manager: ConfigManager):
        """Initialize menu router."""
        self.ui = ui
        self.config = config_manager
        self.current_file: Optional[Path] = None
        self.analysis_data = {}
        
        # Initialize modules
        self.hashing = HashingModule()
        self.metadata = MetadataModule()
        self.strings = StringsModule(self.config)
        self.pe_inspection = PEInspectionModule()
        self.yara_scan = YARAScanModule(self.config)
        self.vt = VirusTotalModule(self.config)
        self.ha = HybridAnalysisModule(self.config)
        self.otx = AlienVaultOTXModule(self.config)
        self.ioc_extractor = IOCExtractorModule()
        self.report_builder = ReportBuilder(self.config)
    
    def run(self):
        """Main application loop."""
        while True:
            choice = self.ui.display_menu(
                "ShadowTrace-IR Main Menu",
                [
                    "Select Target File",
                    "File Analysis & Hashing",
                    "Extract Metadata",
                    "String Extraction & IOC Discovery",
                    "PE/Executable Inspection",
                    "YARA Rule Scanning",
                    "OSINT Hash Lookup",
                    "Generate Forensic Report",
                    "Settings & API Keys",
                    "Exit"
                ]
            )
            
            if choice == "1":
                self._select_file()
            elif choice == "2":
                self._file_analysis()
            elif choice == "3":
                self._extract_metadata()
            elif choice == "4":
                self._string_extraction()
            elif choice == "5":
                self._pe_inspection()
            elif choice == "6":
                self._yara_scanning()
            elif choice == "7":
                self._osint_lookup()
            elif choice == "8":
                self._generate_report()
            elif choice == "9":
                self._settings_menu()
            elif choice == "10" or choice == "0":
                self.ui.show_info("Exiting ShadowTrace-IR. Stay secure!")
                break
    
    def _select_file(self):
        """Select target file for analysis."""
        file_path = self.ui.prompt_input("Enter file path to analyze")
        
        if not file_path:
            self.ui.show_warning("No file path provided.")
            self.ui.pause()
            return
        
        target = Path(file_path)
        
        if not target.exists():
            self.ui.show_error(f"File not found: {file_path}")
            self.ui.pause()
            return
        
        if not target.is_file():
            self.ui.show_error(f"Path is not a file: {file_path}")
            self.ui.pause()
            return
        
        self.current_file = target
        self.analysis_data = {'file_path': str(target)}
        self.ui.show_success(f"Target file set: {target.name}")
        self.ui.pause()
    
    def _file_analysis(self):
        """Perform file hashing and basic analysis."""
        if not self._check_file_selected():
            return
        
        with self.ui.show_progress("Computing file hashes...") as progress:
            task = progress.add_task("Analyzing...", total=None)
            result = self.hashing.analyze_file(self.current_file)
        
        if result:
            self.analysis_data.update(result)
            self.ui.display_data_table("File Analysis Results", result)
            self.ui.show_success("File analysis complete.")
        else:
            self.ui.show_error("Failed to analyze file.")
        
        self.ui.pause()
    
    def _extract_metadata(self):
        """Extract file metadata."""
        if not self._check_file_selected():
            return
        
        with self.ui.show_progress("Extracting metadata...") as progress:
            task = progress.add_task("Processing...", total=None)
            result = self.metadata.extract_metadata(self.current_file)
        
        if result:
            self.analysis_data['metadata'] = result
            self.ui.display_data_table("File Metadata", result)
            self.ui.show_success("Metadata extraction complete.")
        else:
            self.ui.show_warning("No metadata extracted.")
        
        self.ui.pause()
    
    def _string_extraction(self):
        """Extract strings and IOCs from file."""
        if not self._check_file_selected():
            return
        
        with self.ui.show_progress("Extracting strings...") as progress:
            task = progress.add_task("Processing...", total=None)
            strings = self.strings.extract_strings(self.current_file)
        
        self.ui.show_info(f"Extracted {len(strings)} strings.")
        
        with self.ui.show_progress("Extracting IOCs...") as progress:
            task = progress.add_task("Analyzing...", total=None)
            iocs = self.ioc_extractor.extract_iocs('\n'.join(strings))
        
        self.analysis_data['strings_count'] = len(strings)
        self.analysis_data['iocs'] = iocs
        
        # Display IOCs
        total_iocs = sum(len(v) for v in iocs.values())
        self.ui.show_success(f"Found {total_iocs} potential IOCs.")
        
        if iocs.get('domains'):
            self.ui.show_info(f"Domains: {len(iocs['domains'])}")
            for domain in list(iocs['domains'])[:10]:
                self.ui.console.print(f"  • {domain}", style="yellow")
        
        if iocs.get('ips'):
            self.ui.show_info(f"IP Addresses: {len(iocs['ips'])}")
            for ip in list(iocs['ips'])[:10]:
                self.ui.console.print(f"  • {ip}", style="yellow")
        
        if iocs.get('urls'):
            self.ui.show_info(f"URLs: {len(iocs['urls'])}")
            for url in list(iocs['urls'])[:10]:
                self.ui.console.print(f"  • {url}", style="yellow")
        
        if iocs.get('emails'):
            self.ui.show_info(f"Email Addresses: {len(iocs['emails'])}")
            for email in list(iocs['emails'])[:10]:
                self.ui.console.print(f"  • {email}", style="yellow")
        
        self.ui.pause()
    
    def _pe_inspection(self):
        """Inspect PE/executable file structure."""
        if not self._check_file_selected():
            return
        
        with self.ui.show_progress("Inspecting PE structure...") as progress:
            task = progress.add_task("Analyzing...", total=None)
            result = self.pe_inspection.inspect_pe(self.current_file)
        
        if result:
            self.analysis_data['pe_info'] = result
            
            # Display basic info
            basic_info = {k: v for k, v in result.items() if k not in ['imports', 'sections']}
            self.ui.display_data_table("PE File Information", basic_info)
            
            # Display sections
            if 'sections' in result:
                headers = ["Name", "Virtual Size", "Raw Size", "Entropy"]
                rows = [
                    [s['name'], s['virtual_size'], s['raw_size'], f"{s['entropy']:.2f}"]
                    for s in result['sections']
                ]
                self.ui.display_list_table("PE Sections", headers, rows)
            
            # Display imports (truncated)
            if 'imports' in result:
                self.ui.show_info(f"Total imported DLLs: {len(result['imports'])}")
                for dll, funcs in list(result['imports'].items())[:5]:
                    self.ui.console.print(f"  [cyan]{dll}[/cyan]: {len(funcs)} functions")
            
            self.ui.show_success("PE inspection complete.")
        else:
            self.ui.show_error("Failed to inspect PE file (may not be a valid PE).")
        
        self.ui.pause()
    
    def _yara_scanning(self):
        """Run YARA rules against file."""
        if not self._check_file_selected():
            return
        
        rules_path = self.ui.prompt_input("Enter YARA rules file path")
        
        if not rules_path:
            self.ui.show_warning("No rules file provided.")
            self.ui.pause()
            return
        
        with self.ui.show_progress("Scanning with YARA rules...") as progress:
            task = progress.add_task("Scanning...", total=None)
            matches = self.yara_scan.scan_file(self.current_file, rules_path)
        
        if matches:
            self.analysis_data['yara_matches'] = matches
            self.ui.show_warning(f"YARA matched {len(matches)} rule(s)!")
            
            for match in matches:
                self.ui.console.print(f"  [red]• {match['rule']}[/red]")
                if match.get('tags'):
                    self.ui.console.print(f"    Tags: {', '.join(match['tags'])}", style="yellow")
        else:
            self.ui.show_success("No YARA rules matched.")
        
        self.ui.pause()
    
    def _osint_lookup(self):
        """Perform OSINT hash lookups."""
        if not self._check_file_selected():
            return
        
        if 'sha256' not in self.analysis_data:
            self.ui.show_warning("Please run File Analysis first to compute hashes.")
            self.ui.pause()
            return
        
        sha256 = self.analysis_data['sha256']
        
        choice = self.ui.display_menu(
            "OSINT Hash Lookup",
            [
                "VirusTotal Lookup",
                "HybridAnalysis Lookup",
                "AlienVault OTX Lookup",
                "All Services",
                "Back"
            ]
        )
        
        if choice == "1":
            self._vt_lookup(sha256)
        elif choice == "2":
            self._ha_lookup(sha256)
        elif choice == "3":
            self._otx_lookup(sha256)
        elif choice == "4":
            self._vt_lookup(sha256)
            self._ha_lookup(sha256)
            self._otx_lookup(sha256)
        elif choice == "5" or choice == "0":
            return
        
        self.ui.pause()
    
    def _vt_lookup(self, file_hash: str):
        """Lookup hash on VirusTotal."""
        with self.ui.show_progress("Querying VirusTotal...") as progress:
            task = progress.add_task("Searching...", total=None)
            result = self.vt.lookup_hash(file_hash)
        
        if result:
            self.analysis_data['virustotal'] = result
            self.ui.display_data_table("VirusTotal Results", result)
        else:
            self.ui.show_warning("No results from VirusTotal or API key not configured.")
    
    def _ha_lookup(self, file_hash: str):
        """Lookup hash on HybridAnalysis."""
        with self.ui.show_progress("Querying HybridAnalysis...") as progress:
            task = progress.add_task("Searching...", total=None)
            result = self.ha.lookup_hash(file_hash)
        
        if result:
            self.analysis_data['hybridanalysis'] = result
            self.ui.display_data_table("HybridAnalysis Results", result)
        else:
            self.ui.show_warning("No results from HybridAnalysis or API key not configured.")
    
    def _otx_lookup(self, file_hash: str):
        """Lookup hash on AlienVault OTX."""
        with self.ui.show_progress("Querying AlienVault OTX...") as progress:
            task = progress.add_task("Searching...", total=None)
            result = self.otx.lookup_hash(file_hash)
        
        if result:
            self.analysis_data['alienvault_otx'] = result
            self.ui.display_data_table("AlienVault OTX Results", result)
        else:
            self.ui.show_warning("No results from AlienVault OTX or API key not configured.")
    
    def _generate_report(self):
        """Generate forensic analysis report."""
        if not self.analysis_data:
            self.ui.show_warning("No analysis data available. Please run some analysis first.")
            self.ui.pause()
            return
        
        choice = self.ui.display_menu(
            "Select Report Format",
            [
                "JSON Report",
                "Markdown Report",
                "Plain Text Report",
                "Back"
            ]
        )
        
        format_map = {
            "1": "json",
            "2": "markdown",
            "3": "text"
        }
        
        if choice in format_map:
            report_format = format_map[choice]
            output_file = self.ui.prompt_input(
                f"Enter output filename",
                default=f"report.{report_format if report_format != 'text' else 'txt'}"
            )
            
            with self.ui.show_progress("Generating report...") as progress:
                task = progress.add_task("Writing...", total=None)
                success = self.report_builder.generate_report(
                    self.analysis_data,
                    output_file,
                    report_format
                )
            
            if success:
                self.ui.show_success(f"Report saved to: {output_file}")
            else:
                self.ui.show_error("Failed to generate report.")
            
            self.ui.pause()
    
    def _settings_menu(self):
        """Settings and API key management menu."""
        while True:
            choice = self.ui.display_menu(
                "Settings & API Keys",
                [
                    "View API Key Status",
                    "Add/Update API Key",
                    "Remove API Key",
                    "View Settings",
                    "Back"
                ]
            )
            
            if choice == "1":
                self._view_api_keys()
            elif choice == "2":
                self._add_api_key()
            elif choice == "3":
                self._remove_api_key()
            elif choice == "4":
                self._view_settings()
            elif choice == "5" or choice == "0":
                break
    
    def _view_api_keys(self):
        """View configured API keys status."""
        keys_status = self.config.list_api_keys()
        
        data = {
            service: "✓ Configured" if configured else "✗ Not configured"
            for service, configured in keys_status.items()
        }
        
        self.ui.display_data_table("API Keys Status", data)
        self.ui.pause()
    
    def _add_api_key(self):
        """Add or update an API key."""
        services = ["virustotal", "hybridanalysis", "alienvault_otx"]
        
        self.ui.console.print("\n[cyan]Available services:[/cyan]")
        for i, service in enumerate(services, 1):
            self.ui.console.print(f"  [{i}] {service}")
        
        choice = self.ui.prompt_input("Select service (1-3)")
        
        try:
            service_idx = int(choice) - 1
            if 0 <= service_idx < len(services):
                service = services[service_idx]
                api_key = self.ui.prompt_input(f"Enter API key for {service}")
                
                if api_key:
                    self.config.set_api_key(service, api_key)
                    self.ui.show_success(f"API key for {service} saved successfully.")
                else:
                    self.ui.show_warning("No API key provided.")
            else:
                self.ui.show_error("Invalid selection.")
        except ValueError:
            self.ui.show_error("Invalid input.")
        
        self.ui.pause()
    
    def _remove_api_key(self):
        """Remove an API key."""
        services = ["virustotal", "hybridanalysis", "alienvault_otx"]
        
        self.ui.console.print("\n[cyan]Available services:[/cyan]")
        for i, service in enumerate(services, 1):
            self.ui.console.print(f"  [{i}] {service}")
        
        choice = self.ui.prompt_input("Select service (1-3)")
        
        try:
            service_idx = int(choice) - 1
            if 0 <= service_idx < len(services):
                service = services[service_idx]
                if self.ui.prompt_confirm(f"Remove API key for {service}?"):
                    self.config.remove_api_key(service)
                    self.ui.show_success(f"API key for {service} removed.")
            else:
                self.ui.show_error("Invalid selection.")
        except ValueError:
            self.ui.show_error("Invalid input.")
        
        self.ui.pause()
    
    def _view_settings(self):
        """View current settings."""
        settings = self.config.config.get('settings', {})
        self.ui.display_data_table("Current Settings", settings)
        self.ui.pause()
    
    def _check_file_selected(self) -> bool:
        """Check if a target file has been selected."""
        if not self.current_file:
            self.ui.show_warning("No target file selected. Please select a file first.")
            self.ui.pause()
            return False
        return True