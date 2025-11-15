# file: run.py
"""
ShadowTrace-IR - Digital Forensics & Incident Response Console
Main entry point for the application.

Purpose: Legitimate defensive cybersecurity, malware triage, and post-incident analysis.
NOT for offensive use, evasion, or malicious activity.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.ui import UI
from core.menu_router import MenuRouter
from core.config_manager import ConfigManager


def main():
    """Main application entry point."""
    try:
        # Initialize configuration manager
        config_manager = ConfigManager()
        
        # Initialize UI
        ui = UI()
        
        # Display banner
        ui.display_banner()
        
        # Initialize menu router
        router = MenuRouter(ui, config_manager)
        
        # Start main menu loop
        router.run()
        
    except KeyboardInterrupt:
        ui.console.print("\n[yellow]Session interrupted by user. Exiting safely...[/yellow]")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()