# file: modules/strings.py
"""
String extraction module for ShadowTrace-IR.
Extracts ASCII and Unicode strings from binary files for analysis.
"""

from pathlib import Path
from typing import List
import re


class StringsModule:
    """Handles string extraction from binary files."""
    
    def __init__(self, config_manager):
        """Initialize strings module."""
        self.config = config_manager
        self.min_length = config_manager.get_setting('min_string_length', 4)
        self.max_length = config_manager.get_setting('max_string_length', 10000)
    
    def extract_strings(self, file_path: Path, encoding: str = 'ascii') -> List[str]:
        """
        Extract printable strings from a file.
        
        Args:
            file_path: Path to the file
            encoding: String encoding ('ascii' or 'utf-16')
        
        Returns:
            List of extracted strings
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if encoding == 'ascii':
                return self._extract_ascii_strings(data)
            elif encoding == 'utf-16':
                return self._extract_unicode_strings(data)
            else:
                return []
        except Exception as e:
            return []
    
    def _extract_ascii_strings(self, data: bytes) -> List[str]:
        """
        Extract ASCII strings from binary data.
        
        Args:
            data: Binary data
        
        Returns:
            List of ASCII strings
        """
        # ASCII printable characters: 32-126
        pattern = b'[\x20-\x7E]{' + str(self.min_length).encode() + b',}'
        matches = re.findall(pattern, data)
        
        strings = []
        for match in matches:
            try:
                s = match.decode('ascii')
                if len(s) <= self.max_length:
                    strings.append(s)
            except:
                pass
        
        return strings
    
    def _extract_unicode_strings(self, data: bytes) -> List[str]:
        """
        Extract UTF-16 strings from binary data.
        
        Args:
            data: Binary data
        
        Returns:
            List of UTF-16 strings
        """
        strings = []
        
        # Look for UTF-16LE patterns
        pattern = b'(?:[\x20-\x7E]\x00){' + str(self.min_length).encode() + b',}'
        matches = re.findall(pattern, data)
        
        for match in matches:
            try:
                s = match.decode('utf-16le')
                if len(s) <= self.max_length:
                    strings.append(s)
            except:
                pass
        
        return strings