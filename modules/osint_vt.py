# file: modules/osint_vt.py
"""
VirusTotal OSINT module for ShadowTrace-IR.
Performs hash lookups against VirusTotal API for threat intelligence.

IMPORTANT: This module ONLY looks up file hashes, never uploads files.
"""

import requests
from typing import Dict, Optional


class VirusTotalModule:
    """Handles VirusTotal hash lookups."""
    
    def __init__(self, config_manager):
        """Initialize VirusTotal module."""
        self.config = config_manager
        self.api_key = config_manager.get_api_key('virustotal')
        self.base_url = 'https://www.virustotal.com/api/v3'
    
    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Lookup a file hash on VirusTotal.
        
        Args:
            file_hash: SHA256, SHA1, or MD5 hash
        
        Returns:
            Dictionary with lookup results or None
        """
        if not self.api_key:
            return None
        
        try:
            headers = {
                'x-apikey': self.api_key
            }
            
            response = requests.get(
                f'{self.base_url}/files/{file_hash}',
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                result = {
                    'hash': file_hash,
                    'sha256': attributes.get('sha256', 'N/A'),
                    'md5': attributes.get('md5', 'N/A'),
                    'file_type': attributes.get('type_description', 'Unknown'),
                    'size': attributes.get('size', 0),
                    'first_seen': attributes.get('first_submission_date', 'Unknown'),
                    'last_analysis': attributes.get('last_analysis_date', 'Unknown'),
                }
                
                # Analysis stats
                stats = attributes.get('last_analysis_stats', {})
                result['malicious'] = stats.get('malicious', 0)
                result['suspicious'] = stats.get('suspicious', 0)
                result['undetected'] = stats.get('undetected', 0)
                result['harmless'] = stats.get('harmless', 0)
                
                return result
            elif response.status_code == 404:
                return {'status': 'Hash not found in VirusTotal database'}
            else:
                return None
        except Exception as e:
            return None