# file: modules/metadata.py
"""
Metadata extraction module for ShadowTrace-IR.
Extracts metadata from various file types for forensic analysis.
"""

import subprocess
from pathlib import Path
from typing import Dict, Optional
import json


class MetadataModule:
    """Handles metadata extraction from files."""
    
    def __init__(self):
        """Initialize metadata module."""
        self.exiftool_available = self._check_exiftool()
    
    def _check_exiftool(self) -> bool:
        """Check if exiftool is available on the system."""
        try:
            subprocess.run(
                ['exiftool', '-ver'],
                capture_output=True,
                timeout=5
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def extract_metadata(self, file_path: Path) -> Dict:
        """
        Extract metadata from a file.
        
        Args:
            file_path: Path to the file
        
        Returns:
            Dictionary containing metadata
        """
        if not self.exiftool_available:
            return self._basic_metadata(file_path)
        
        try:
            result = subprocess.run(
                ['exiftool', '-json', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                metadata_list = json.loads(result.stdout)
                if metadata_list:
                    # Clean up metadata for display
                    metadata = metadata_list[0]
                    # Remove technical fields
                    exclude_fields = ['SourceFile', 'ExifToolVersion', 'Directory']
                    return {k: v for k, v in metadata.items() if k not in exclude_fields}
            
            return self._basic_metadata(file_path)
        except Exception as e:
            return self._basic_metadata(file_path)
    
    def _basic_metadata(self, file_path: Path) -> Dict:
        """
        Extract basic metadata without exiftool.
        
        Args:
            file_path: Path to the file
        
        Returns:
            Dictionary with basic metadata
        """
        import os
        from datetime import datetime
        
        try:
            stats = os.stat(file_path)
            return {
                'Filename': file_path.name,
                'File Extension': file_path.suffix,
                'File Size': stats.st_size,
                'Created': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                'Modified': datetime.fromtimestamp(stats.st_mtime).isoformat(),
                'Note': 'Limited metadata (exiftool not available)'
            }
        except Exception as e:
            return {'Error': str(e)}