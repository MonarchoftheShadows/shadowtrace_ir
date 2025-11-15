# file: reports/report_builder.py
"""
Report builder for ShadowTrace-IR.
Generates forensic analysis reports in JSON, Markdown, and plain text formats.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict


class ReportBuilder:
    """Handles forensic report generation."""
    
    def __init__(self, config_manager):
        """Initialize report builder."""
        self.config = config_manager
    
    def generate_report(self, analysis_data: Dict, output_file: str, format: str = 'json') -> bool:
        """
        Generate forensic analysis report.
        
        Args:
            analysis_data: Dictionary containing all analysis results
            output_file: Path to output file
            format: Report format ('json', 'markdown', 'text')
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if format == 'json':
                return self._generate_json_report(analysis_data, output_file)
            elif format == 'markdown':
                return self._generate_markdown_report(analysis_data, output_file)
            elif format == 'text':
                return self._generate_text_report(analysis_data, output_file)
            else:
                return False
        except Exception as e:
            return False
    
    def _generate_json_report(self, data: Dict, output_file: str) -> bool:
        """Generate JSON format report."""
        try:
            report = {
                'report_metadata': {
                    'tool': 'ShadowTrace-IR',
                    'version': '1.0.0',
                    'generated': datetime.now().isoformat(),
                    'purpose': 'Digital Forensics & Incident Response Analysis'
                },
                'analysis_results': data
            }
            
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            return True
        except Exception:
            return False
    
    def _generate_markdown_report(self, data: Dict, output_file: str) -> bool:
        """Generate Markdown format report."""
        try:
            lines = []
            lines.append("# ShadowTrace-IR Forensic Analysis Report\n")
            lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            lines.append(f"**Tool Version:** 1.0.0\n")
            lines.append("---\n\n")
            
            # File Information
            if 'file_path' in data:
                lines.append("## File Information\n\n")
                lines.append(f"- **File Path:** `{data.get('file_path', 'N/A')}`\n")
                lines.append(f"- **File Name:** `{data.get('filename', 'N/A')}`\n")
                lines.append(f"- **File Size:** {data.get('file_size_human', data.get('file_size', 'N/A'))}\n")
                lines.append(f"- **MIME Type:** {data.get('mime_type', 'N/A')}\n\n")
            
            # Hashes
            if any(k in data for k in ['md5', 'sha1', 'sha256']):
                lines.append("## Cryptographic Hashes\n\n")
                lines.append("```\n")
                if 'md5' in data:
                    lines.append(f"MD5:    {data['md5']}\n")
                if 'sha1' in data:
                    lines.append(f"SHA1:   {data['sha1']}\n")
                if 'sha256' in data:
                    lines.append(f"SHA256: {data['sha256']}\n")
                lines.append("```\n\n")
            
            # Timestamps
            if any(k in data for k in ['created', 'modified', 'accessed']):
                lines.append("## Timestamps\n\n")
                if 'created' in data:
                    lines.append(f"- **Created:** {data['created']}\n")
                if 'modified' in data:
                    lines.append(f"- **Modified:** {data['modified']}\n")
                if 'accessed' in data:
                    lines.append(f"- **Accessed:** {data['accessed']}\n")
                lines.append("\n")
            
            # PE Information
            if 'pe_info' in data:
                lines.append("## PE Executable Analysis\n\n")
                pe = data['pe_info']
                lines.append(f"- **Machine Type:** {pe.get('machine_type', 'N/A')}\n")
                lines.append(f"- **Subsystem:** {pe.get('subsystem', 'N/A')}\n")
                lines.append(f"- **Entry Point:** {pe.get('entry_point', 'N/A')}\n")
                
                if 'characteristics' in pe:
                    lines.append("\n### Security Features\n\n")
                    chars = pe['characteristics']
                    lines.append(f"- **ASLR:** {'Enabled' if chars.get('aslr_enabled') else 'Disabled'}\n")
                    lines.append(f"- **DEP:** {'Enabled' if chars.get('dep_enabled') else 'Disabled'}\n")
                
                if 'sections' in pe and pe['sections']:
                    lines.append("\n### PE Sections\n\n")
                    lines.append("| Name | Virtual Size | Raw Size | Entropy |\n")
                    lines.append("|------|--------------|----------|----------|\n")
                    for section in pe['sections']:
                        lines.append(f"| {section['name']} | {section['virtual_size']} | "
                                   f"{section['raw_size']} | {section['entropy']:.2f} |\n")
                    lines.append("\n")
            
            # IOCs
            if 'iocs' in data:
                lines.append("## Indicators of Compromise (IOCs)\n\n")
                iocs = data['iocs']
                
                if iocs.get('domains'):
                    lines.append(f"### Domains ({len(iocs['domains'])})\n\n")
                    for domain in list(iocs['domains'])[:20]:
                        lines.append(f"- `{domain}`\n")
                    lines.append("\n")
                
                if iocs.get('ips'):
                    lines.append(f"### IP Addresses ({len(iocs['ips'])})\n\n")
                    for ip in list(iocs['ips'])[:20]:
                        lines.append(f"- `{ip}`\n")
                    lines.append("\n")
                
                if iocs.get('urls'):
                    lines.append(f"### URLs ({len(iocs['urls'])})\n\n")
                    for url in list(iocs['urls'])[:20]:
                        lines.append(f"- `{url}`\n")
                    lines.append("\n")
                
                if iocs.get('emails'):
                    lines.append(f"### Email Addresses ({len(iocs['emails'])})\n\n")
                    for email in list(iocs['emails'])[:20]:
                        lines.append(f"- `{email}`\n")
                    lines.append("\n")
            
            # YARA Matches
            if 'yara_matches' in data and data['yara_matches']:
                lines.append("## YARA Rule Matches\n\n")
                lines.append("⚠️ **WARNING: File matched one or more YARA rules**\n\n")
                for match in data['yara_matches']:
                    lines.append(f"### Rule: {match['rule']}\n\n")
                    if match.get('tags'):
                        lines.append(f"- **Tags:** {', '.join(match['tags'])}\n")
                    lines.append("\n")
            
            # OSINT Results
            if 'virustotal' in data:
                lines.append("## VirusTotal Analysis\n\n")
                vt = data['virustotal']
                if 'malicious' in vt:
                    lines.append(f"- **Malicious:** {vt.get('malicious', 0)}\n")
                    lines.append(f"- **Suspicious:** {vt.get('suspicious', 0)}\n")
                    lines.append(f"- **Undetected:** {vt.get('undetected', 0)}\n")
                    lines.append(f"- **Harmless:** {vt.get('harmless', 0)}\n")
                else:
                    lines.append(f"- **Status:** {vt.get('status', 'N/A')}\n")
                lines.append("\n")
            
            if 'hybridanalysis' in data:
                lines.append("## HybridAnalysis Results\n\n")
                ha = data['hybridanalysis']
                lines.append(f"- **Verdict:** {ha.get('verdict', 'N/A')}\n")
                lines.append(f"- **Threat Score:** {ha.get('threat_score', 'N/A')}\n")
                lines.append(f"- **VX Family:** {ha.get('vx_family', 'N/A')}\n\n")
            
            if 'alienvault_otx' in data:
                lines.append("## AlienVault OTX Intelligence\n\n")
                otx = data['alienvault_otx']
                lines.append(f"- **Pulse Count:** {otx.get('pulse_count', 0)}\n")
                if 'recent_pulses' in otx:
                    lines.append("\n### Recent Threat Pulses\n\n")
                    for pulse in otx['recent_pulses']:
                        lines.append(f"- **{pulse['name']}** ({pulse.get('created', 'N/A')})\n")
                lines.append("\n")
            
            # Footer
            lines.append("---\n\n")
            lines.append("*Report generated by ShadowTrace-IR - For legitimate defensive cybersecurity use only*\n")
            
            with open(output_file, 'w') as f:
                f.writelines(lines)
            
            return True
        except Exception:
            return False
    
    def _generate_text_report(self, data: Dict, output_file: str) -> bool:
        """Generate plain text format report."""
        try:
            lines = []
            lines.append("=" * 80 + "\n")
            lines.append("SHADOWTRACE-IR FORENSIC ANALYSIS REPORT\n")
            lines.append("=" * 80 + "\n\n")
            lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            lines.append(f"Tool Version: 1.0.0\n")
            lines.append(f"Purpose: Digital Forensics & Incident Response Analysis\n")
            lines.append("\n" + "-" * 80 + "\n\n")
            
            # File Information
            if 'file_path' in data:
                lines.append("FILE INFORMATION\n")
                lines.append("-" * 80 + "\n")
                lines.append(f"File Path:     {data.get('file_path', 'N/A')}\n")
                lines.append(f"File Name:     {data.get('filename', 'N/A')}\n")
                lines.append(f"File Size:     {data.get('file_size_human', data.get('file_size', 'N/A'))}\n")
                lines.append(f"MIME Type:     {data.get('mime_type', 'N/A')}\n")
                lines.append("\n")
            
            # Hashes
            if any(k in data for k in ['md5', 'sha1', 'sha256']):
                lines.append("CRYPTOGRAPHIC HASHES\n")
                lines.append("-" * 80 + "\n")
                if 'md5' in data:
                    lines.append(f"MD5:           {data['md5']}\n")
                if 'sha1' in data:
                    lines.append(f"SHA1:          {data['sha1']}\n")
                if 'sha256' in data:
                    lines.append(f"SHA256:        {data['sha256']}\n")
                lines.append("\n")
            
            # Timestamps
            if any(k in data for k in ['created', 'modified', 'accessed']):
                lines.append("TIMESTAMPS\n")
                lines.append("-" * 80 + "\n")
                if 'created' in data:
                    lines.append(f"Created:       {data['created']}\n")
                if 'modified' in data:
                    lines.append(f"Modified:      {data['modified']}\n")
                if 'accessed' in data:
                    lines.append(f"Accessed:      {data['accessed']}\n")
                lines.append("\n")
            
            # PE Information
            if 'pe_info' in data:
                lines.append("PE EXECUTABLE ANALYSIS\n")
                lines.append("-" * 80 + "\n")
                pe = data['pe_info']
                lines.append(f"Machine Type:  {pe.get('machine_type', 'N/A')}\n")
                lines.append(f"Subsystem:     {pe.get('subsystem', 'N/A')}\n")
                lines.append(f"Entry Point:   {pe.get('entry_point', 'N/A')}\n")
                
                if 'characteristics' in pe:
                    chars = pe['characteristics']
                    lines.append(f"ASLR:          {'Enabled' if chars.get('aslr_enabled') else 'Disabled'}\n")
                    lines.append(f"DEP:           {'Enabled' if chars.get('dep_enabled') else 'Disabled'}\n")
                lines.append("\n")
                
                if 'sections' in pe and pe['sections']:
                    lines.append("PE Sections:\n")
                    for section in pe['sections']:
                        lines.append(f"  {section['name']:12} VirtSize: {section['virtual_size']:8}  "
                                   f"RawSize: {section['raw_size']:8}  Entropy: {section['entropy']:.2f}\n")
                    lines.append("\n")
            
            # IOCs
            if 'iocs' in data:
                lines.append("INDICATORS OF COMPROMISE (IOCs)\n")
                lines.append("-" * 80 + "\n")
                iocs = data['iocs']
                
                if iocs.get('domains'):
                    lines.append(f"\nDomains ({len(iocs['domains'])}):\n")
                    for domain in list(iocs['domains'])[:20]:
                        lines.append(f"  - {domain}\n")
                
                if iocs.get('ips'):
                    lines.append(f"\nIP Addresses ({len(iocs['ips'])}):\n")
                    for ip in list(iocs['ips'])[:20]:
                        lines.append(f"  - {ip}\n")
                
                if iocs.get('urls'):
                    lines.append(f"\nURLs ({len(iocs['urls'])}):\n")
                    for url in list(iocs['urls'])[:20]:
                        lines.append(f"  - {url}\n")
                
                if iocs.get('emails'):
                    lines.append(f"\nEmail Addresses ({len(iocs['emails'])}):\n")
                    for email in list(iocs['emails'])[:20]:
                        lines.append(f"  - {email}\n")
                lines.append("\n")
            
            # YARA Matches
            if 'yara_matches' in data and data['yara_matches']:
                lines.append("YARA RULE MATCHES\n")
                lines.append("-" * 80 + "\n")
                lines.append("WARNING: File matched one or more YARA rules\n\n")
                for match in data['yara_matches']:
                    lines.append(f"Rule: {match['rule']}\n")
                    if match.get('tags'):
                        lines.append(f"Tags: {', '.join(match['tags'])}\n")
                    lines.append("\n")
            
            # OSINT Results
            if 'virustotal' in data:
                lines.append("VIRUSTOTAL ANALYSIS\n")
                lines.append("-" * 80 + "\n")
                vt = data['virustotal']
                if 'malicious' in vt:
                    lines.append(f"Malicious:     {vt.get('malicious', 0)}\n")
                    lines.append(f"Suspicious:    {vt.get('suspicious', 0)}\n")
                    lines.append(f"Undetected:    {vt.get('undetected', 0)}\n")
                    lines.append(f"Harmless:      {vt.get('harmless', 0)}\n")
                else:
                    lines.append(f"Status:        {vt.get('status', 'N/A')}\n")
                lines.append("\n")
            
            if 'hybridanalysis' in data:
                lines.append("HYBRIDANALYSIS RESULTS\n")
                lines.append("-" * 80 + "\n")
                ha = data['hybridanalysis']
                lines.append(f"Verdict:       {ha.get('verdict', 'N/A')}\n")
                lines.append(f"Threat Score:  {ha.get('threat_score', 'N/A')}\n")
                lines.append(f"VX Family:     {ha.get('vx_family', 'N/A')}\n")
                lines.append("\n")
            
            if 'alienvault_otx' in data:
                lines.append("ALIENVAULT OTX INTELLIGENCE\n")
                lines.append("-" * 80 + "\n")
                otx = data['alienvault_otx']
                lines.append(f"Pulse Count:   {otx.get('pulse_count', 0)}\n")
                if 'recent_pulses' in otx and otx['recent_pulses']:
                    lines.append("\nRecent Threat Pulses:\n")
                    for pulse in otx['recent_pulses']:
                        lines.append(f"  - {pulse['name']} ({pulse.get('created', 'N/A')})\n")
                lines.append("\n")
            
            # Footer
            lines.append("=" * 80 + "\n")
            lines.append("Report generated by ShadowTrace-IR\n")
            lines.append("For legitimate defensive cybersecurity use only\n")
            lines.append("=" * 80 + "\n")
            
            with open(output_file, 'w') as f:
                f.writelines(lines)
            
            return True
        except Exception:
            return False