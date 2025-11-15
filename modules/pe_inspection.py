# file: modules/pe_inspection.py
"""
PE (Portable Executable) inspection module for ShadowTrace-IR.
Performs READ-ONLY structural analysis of PE files for defensive purposes.

This module is for:
- Malware family classification
- Forensic transparency and audit
- Understanding executable structure
- Identifying compiler and build information

NOT for reverse engineering, evasion, or offensive purposes.
"""

from pathlib import Path
from typing import Dict, Optional
import math


class PEInspectionModule:
    """Handles PE file structure inspection."""
    
    def __init__(self):
        """Initialize PE inspection module."""
        pass
    
    def inspect_pe(self, file_path: Path) -> Optional[Dict]:
        """
        Inspect PE file structure and extract metadata.
        
        Args:
            file_path: Path to the PE file
        
        Returns:
            Dictionary containing PE information or None if not a valid PE
        """
        try:
            import pefile
            
            pe = pefile.PE(str(file_path))
            
            result = {
                'machine_type': self._get_machine_type(pe.FILE_HEADER.Machine),
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'subsystem': self._get_subsystem(pe.OPTIONAL_HEADER.Subsystem),
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
            }
            
            # Extract sections
            result['sections'] = self._extract_sections(pe)
            
            # Extract imports
            result['imports'] = self._extract_imports(pe)
            
            # Check for suspicious characteristics
            result['characteristics'] = self._analyze_characteristics(pe)
            
            pe.close()
            return result
            
        except Exception as e:
            return None
    
    def _get_machine_type(self, machine: int) -> str:
        """Get human-readable machine type."""
        machine_types = {
            0x14c: 'I386 (x86)',
            0x8664: 'AMD64 (x64)',
            0x1c0: 'ARM',
            0xaa64: 'ARM64',
        }
        return machine_types.get(machine, f'Unknown (0x{machine:x})')
    
    def _get_subsystem(self, subsystem: int) -> str:
        """Get human-readable subsystem."""
        subsystems = {
            1: 'Native',
            2: 'Windows GUI',
            3: 'Windows CUI (Console)',
            9: 'Windows CE GUI',
        }
        return subsystems.get(subsystem, f'Unknown ({subsystem})')
    
    def _extract_sections(self, pe) -> list:
        """Extract section information."""
        sections = []
        
        for section in pe.sections:
            section_data = {
                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': self._calculate_entropy(section.get_data()),
            }
            sections.append(section_data)
        
        return sections
    
    def _extract_imports(self, pe) -> Dict:
        """Extract imported DLLs and functions."""
        imports = {}
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    functions = []
                    
                    for imp in entry.imports:
                        if imp.name:
                            functions.append(imp.name.decode('utf-8', errors='ignore'))
                    
                    imports[dll_name] = functions
        except Exception:
            pass
        
        return imports
    
    def _analyze_characteristics(self, pe) -> Dict:
        """Analyze PE characteristics for forensic insights."""
        characteristics = {}
        
        # Check if DLL
        characteristics['is_dll'] = bool(pe.is_dll())
        
        # Check if executable
        characteristics['is_exe'] = bool(pe.is_exe())
        
        # Check if driver
        characteristics['is_driver'] = bool(pe.is_driver())
        
        # Check ASLR
        characteristics['aslr_enabled'] = bool(
            pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040
        )
        
        # Check DEP
        characteristics['dep_enabled'] = bool(
            pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100
        )
        
        return characteristics
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        High entropy may indicate encryption or compression.
        """
        if not data:
            return 0.0
        
        entropy = 0
        length = len(data)
        
        # Count byte frequencies
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        
        # Calculate entropy
        for freq in frequencies:
            if freq > 0:
                probability = freq / length
                entropy -= probability * math.log2(probability)
        
        return entropy