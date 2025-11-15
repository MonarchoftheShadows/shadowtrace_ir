# file: modules/hashing.py
"""
File hashing module for ShadowTrace-IR.
Computes cryptographic hashes for file identification and integrity verification.
"""

import hashlib
from pathlib import Path
from typing import Dict, Optional
import os
from datetime import datetime


class HashingModule:
    """Handles file hashing and basic file information."""
    
    def __init__(self):
        """Initialize hashing module."""
        pass
    
    def compute_hash(self, file_path: Path, algorithm: str = 'sha256') -> Optional[str]:
        """
        Compute hash of a file using specified algorithm.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm (md5, sha1, sha256)
        
        Returns:
            Hex digest of the hash or None on error
        """
        try:
            hash_obj = hashlib.new(algorithm)
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
        except Exception as e:
            return None
    
    def analyze_file(self, file_path: Path) -> Dict:
        """
        Perform comprehensive file analysis including multiple hashes.
        
        Args:
            file_path: Path to the file to analyze
        
        Returns:
            Dictionary containing file information and hashes
        """
        try:
            stats = os.stat(file_path)
            
            result = {
                'filename': file_path.name,
                'file_path': str(file_path.absolute()),
                'file_size': stats.st_size,
                'file_size_human': self._human_readable_size(stats.st_size),
                'created': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stats.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stats.st_atime).isoformat(),
            }
            
            # Compute multiple hashes
            result['md5'] = self.compute_hash(file_path, 'md5')
            result['sha1'] = self.compute_hash(file_path, 'sha1')
            result['sha256'] = self.compute_hash(file_path, 'sha256')
            
            # Try to detect MIME type
            try:
                import magic
                result['mime_type'] = magic.from_file(str(file_path), mime=True)
            except:
                result['mime_type'] = 'unknown'
            
            return result
        except Exception as e:
            return {}
    
    def _human_readable_size(self, size: int) -> str:
        """Convert bytes to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"