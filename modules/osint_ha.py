# file: modules/osint_ha.py
"""
HybridAnalysis OSINT module for ShadowTrace-IR.
Performs hash lookups against HybridAnalysis API for threat intelligence.
"""

import requests
from typing import Dict, Optional


class HybridAnalysisModule:
    """Handles HybridAnalysis hash lookups."""
    
    def __init__(self, config_manager):
        """Initialize HybridAnalysis module."""
        self.config = config_manager
        self.api_key = config_manager.get_api_key('hybridanalysis')
        self.base_url = 'https://www.hybrid-analysis.com/api/v2'
    
    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Lookup a file hash on HybridAnalysis.
        
        Args:
            file_hash: SHA256, SHA1, or MD5 hash
        
        Returns:
            Dictionary with lookup results or None
        """
        if not self.api_key:
            return None
        
        try:
            headers = {
                'api-key': self.api_key,
                'User-Agent': 'ShadowTrace-IR',
                'accept': 'application/json'
            }
            
            response = requests.post(
                f'{self.base_url}/search/hash',
                headers=headers,
                data={'hash': file_hash},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list) and len(data) > 0:
                    item = data[0]
                    
                    result = {
                        'hash': file_hash,
                        'verdict': item.get('verdict', 'Unknown'),
                        'threat_score': item.get('threat_score', 0),
                        'av_detect': item.get('av_detect', 0),
                        'vx_family': item.get('vx_family', 'None'),
                        'environment': item.get('environment_description', 'Unknown'),
                        'submit_name': item.get('submit_name', 'Unknown'),
                        'analysis_date': item.get('analysis_start_time', 'Unknown'),
                    }
                    
                    return result
                else:
                    return {'status': 'Hash not found in HybridAnalysis database'}
            else:
                return None
        except Exception as e:
            return None