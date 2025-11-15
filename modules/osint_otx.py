# file: modules/osint_otx.py
"""
AlienVault OTX OSINT module for ShadowTrace-IR.
Performs hash lookups against AlienVault OTX API for threat intelligence.
"""

import requests
from typing import Dict, Optional


class AlienVaultOTXModule:
    """Handles AlienVault OTX hash lookups."""
    
    def __init__(self, config_manager):
        """Initialize AlienVault OTX module."""
        self.config = config_manager
        self.api_key = config_manager.get_api_key('alienvault_otx')
        self.base_url = 'https://otx.alienvault.com/api/v1'
    
    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Lookup a file hash on AlienVault OTX.
        
        Args:
            file_hash: SHA256, SHA1, or MD5 hash
        
        Returns:
            Dictionary with lookup results or None
        """
        if not self.api_key:
            return None
        
        try:
            headers = {
                'X-OTX-API-KEY': self.api_key
            }
            
            # Determine hash type
            hash_type = 'sha256' if len(file_hash) == 64 else 'sha1' if len(file_hash) == 40 else 'md5'
            
            response = requests.get(
                f'{self.base_url}/indicators/file/{file_hash}/general',
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                result = {
                    'hash': file_hash,
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'file_type': data.get('type', 'Unknown'),
                    'file_class': data.get('file_class', 'Unknown'),
                }
                
                # Get pulse information
                pulses = data.get('pulse_info', {}).get('pulses', [])
                if pulses:
                    result['recent_pulses'] = []
                    for pulse in pulses[:5]:  # Limit to 5 most recent
                        result['recent_pulses'].append({
                            'name': pulse.get('name', 'Unknown'),
                            'created': pulse.get('created', 'Unknown'),
                            'tags': pulse.get('tags', [])
                        })
                
                return result
            elif response.status_code == 404:
                return {'status': 'Hash not found in AlienVault OTX database'}
            else:
                return None
        except Exception as e:
            return None