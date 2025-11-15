# file: modules/yara_scan.py
"""
YARA scanning module for ShadowTrace-IR.
Scans files against YARA rules for malware detection and classification.
"""

from pathlib import Path
from typing import List, Dict, Optional


class YARAScanModule:
    """Handles YARA rule scanning."""
    
    def __init__(self, config_manager):
        """Initialize YARA scanning module."""
        self.config = config_manager
        self.yara_available = self._check_yara()
    
    def _check_yara(self) -> bool:
        """Check if yara-python is available."""
        try:
            import yara
            return True
        except ImportError:
            return False
    
    def scan_file(self, file_path: Path, rules_path: str) -> List[Dict]:
        """
        Scan a file with YARA rules.
        
        Args:
            file_path: Path to file to scan
            rules_path: Path to YARA rules file
        
        Returns:
            List of matches with rule information
        """
        if not self.yara_available:
            return []
        
        try:
            import yara
            
            rules = yara.compile(filepath=rules_path)
            matches = rules.match(str(file_path))
            
            results = []
            for match in matches:
                result = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }
                
                # Add matched strings (limited for display)
                for string_match in match.strings[:10]:
                    result['strings'].append({
                        'offset': string_match[0],
                        'identifier': string_match[1],
                        'data': string_match[2][:100]  # Truncate long strings
                    })
                
                results.append(result)
            
            return results
        except Exception as e:
            return []
    
    def compile_rules(self, rules_directory: Path) -> bool:
        """
        Compile all YARA rules in a directory.
        
        Args:
            rules_directory: Directory containing YARA rule files
        
        Returns:
            True if successful, False otherwise
        """
        if not self.yara_available:
            return False
        
        try:
            import yara
            
            rules_files = {}
            for rule_file in rules_directory.glob('*.yar'):
                rules_files[rule_file.stem] = str(rule_file)
            
            if rules_files:
                rules = yara.compile(filepaths=rules_files)
                return True
            
            return False
        except Exception:
            return False