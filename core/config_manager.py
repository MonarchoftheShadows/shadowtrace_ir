# file: core/config_manager.py
"""
Configuration Manager for ShadowTrace-IR.
Handles loading, saving, and managing API keys and settings.
"""

import yaml
from pathlib import Path
from typing import Dict, Optional


class ConfigManager:
    """Manages application configuration and API keys."""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize configuration manager."""
        self.config_path = Path(config_path)
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            # Create default config
            default_config = {
                'api_keys': {
                    'virustotal': '',
                    'hybridanalysis': '',
                    'alienvault_otx': ''
                },
                'settings': {
                    'max_string_length': 10000,
                    'min_string_length': 4,
                    'default_report_format': 'json',
                    'yara_rules_directory': './yara_rules'
                }
            }
            self._save_config(default_config)
            return default_config
        
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _save_config(self, config: Dict):
        """Save configuration to YAML file."""
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Retrieve API key for a specific service."""
        key = self.config.get('api_keys', {}).get(service, '')
        return key if key else None
    
    def set_api_key(self, service: str, key: str):
        """Set API key for a specific service."""
        if 'api_keys' not in self.config:
            self.config['api_keys'] = {}
        
        self.config['api_keys'][service] = key
        self._save_config(self.config)
    
    def remove_api_key(self, service: str):
        """Remove API key for a specific service."""
        if service in self.config.get('api_keys', {}):
            self.config['api_keys'][service] = ''
            self._save_config(self.config)
    
    def get_setting(self, key: str, default=None):
        """Retrieve a configuration setting."""
        return self.config.get('settings', {}).get(key, default)
    
    def set_setting(self, key: str, value):
        """Set a configuration setting."""
        if 'settings' not in self.config:
            self.config['settings'] = {}
        
        self.config['settings'][key] = value
        self._save_config(self.config)
    
    def list_api_keys(self) -> Dict[str, bool]:
        """List all configured API keys and their status."""
        api_keys = self.config.get('api_keys', {})
        return {service: bool(key) for service, key in api_keys.items()}