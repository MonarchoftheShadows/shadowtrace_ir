# file: modules/ioc_extractor.py
"""
IOC (Indicators of Compromise) extractor for ShadowTrace-IR.
Extracts potential IOCs from strings for threat intelligence.
"""

import re
from typing import Dict, Set


class IOCExtractorModule:
    """Extracts IOCs from text/strings."""
    
    def __init__(self):
        """Initialize IOC extractor with regex patterns."""
        # IP address pattern (IPv4)
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # Domain pattern
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        
        # URL pattern
        self.url_pattern = re.compile(
            r'(?:http|https|ftp)://[a-zA-Z0-9\-\.]+(?:\:[0-9]+)?(?:/[^\s]*)?'
        )
        
        # Email pattern
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        # Common false positives to filter
        self.false_positives = {
            'localhost', 'example.com', 'test.com', 'example.org',
            '0.0.0.0', '127.0.0.1', '255.255.255.255'
        }
    
    def extract_iocs(self, text: str) -> Dict[str, Set[str]]:
        """
        Extract IOCs from text.
        
        Args:
            text: Text to extract IOCs from
        
        Returns:
            Dictionary containing sets of different IOC types
        """
        iocs = {
            'ips': set(),
            'domains': set(),
            'urls': set(),
            'emails': set()
        }
        
        # Extract IPs
        ips = self.ip_pattern.findall(text)
        iocs['ips'] = {ip for ip in ips if ip not in self.false_positives}
        
        # Extract URLs
        urls = self.url_pattern.findall(text)
        iocs['urls'] = {url for url in urls if not any(fp in url for fp in self.false_positives)}
        
        # Extract domains
        domains = self.domain_pattern.findall(text)
        iocs['domains'] = {
            domain for domain in domains 
            if domain not in self.false_positives 
            and domain not in iocs['ips']
            and not domain.endswith('.dll')
            and not domain.endswith('.exe')
        }
        
        # Extract emails
        emails = self.email_pattern.findall(text)
        iocs['emails'] = {email for email in emails if email not in self.false_positives}
        
        return iocs