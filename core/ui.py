# file: core/ui.py
"""
User Interface module for ShadowTrace-IR.
Handles all terminal UI rendering using rich library.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.tree import Tree
from typing import List, Dict, Optional


class UI:
    """Terminal user interface handler."""
    
    def __init__(self):
        """Initialize UI with rich console."""
        self.console = Console()
    
    def display_banner(self):
        """Display application banner."""
        banner = """
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗████████╗██████╗  █████╗  ██████╗███████╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║   ██║   ██████╔╝███████║██║     █████╗  
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
                                    -IR (Incident Response Edition)
        """
        self.console.print(banner, style="bold cyan")
        self.console.print(
            Panel(
                "[bold white]Digital Forensics & Incident Response Console[/bold white]\n"
                "[yellow]For legitimate defensive cybersecurity, malware triage, and post-incident analysis[/yellow]\n"
                "[dim]Version 1.0.0 | Defensive Use Only[/dim]",
                border_style="cyan"
            )
        )
        self.console.print()
    
    def display_menu(self, title: str, options: List[str]) -> str:
        """Display a menu and get user selection."""
        self.console.print(Panel(f"[bold cyan]{title}[/bold cyan]", border_style="cyan"))
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Option", style="cyan")
        table.add_column("Description", style="white")
        
        for i, option in enumerate(options, 1):
            table.add_row(f"[{i}]", option)
        
        self.console.print(table)
        self.console.print()
        
        choice = Prompt.ask(
            "[bold cyan]Select an option[/bold cyan]",
            choices=[str(i) for i in range(1, len(options) + 1)] + ["0"],
            default="0"
        )
        
        return choice
    
    def prompt_input(self, prompt: str, default: str = "") -> str:
        """Prompt user for text input."""
        return Prompt.ask(f"[cyan]{prompt}[/cyan]", default=default)
    
    def prompt_confirm(self, prompt: str) -> bool:
        """Prompt user for yes/no confirmation."""
        return Confirm.ask(f"[cyan]{prompt}[/cyan]")
    
    def show_success(self, message: str):
        """Display success message."""
        self.console.print(f"[bold green]✓[/bold green] {message}")
    
    def show_error(self, message: str):
        """Display error message."""
        self.console.print(f"[bold red]✗[/bold red] {message}")
    
    def show_warning(self, message: str):
        """Display warning message."""
        self.console.print(f"[bold yellow]⚠[/bold yellow] {message}")
    
    def show_info(self, message: str):
        """Display info message."""
        self.console.print(f"[bold blue]ℹ[/bold blue] {message}")
    
    def display_data_table(self, title: str, data: Dict):
        """Display key-value data in a table."""
        table = Table(title=title, show_header=True, header_style="bold cyan")
        table.add_column("Property", style="cyan", width=30)
        table.add_column("Value", style="white")
        
        for key, value in data.items():
            table.add_row(str(key), str(value))
        
        self.console.print(table)
    
    def display_list_table(self, title: str, headers: List[str], rows: List[List]):
        """Display list data in a table."""
        table = Table(title=title, show_header=True, header_style="bold cyan")
        
        for header in headers:
            table.add_column(header, style="white")
        
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        
        self.console.print(table)
    
    def show_progress(self, description: str):
        """Create and return a progress context manager."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        )
    
    def display_code(self, code: str, language: str = "python"):
        """Display syntax-highlighted code."""
        syntax = Syntax(code, language, theme="monokai", line_numbers=True)
        self.console.print(syntax)
    
    def clear_screen(self):
        """Clear the terminal screen."""
        self.console.clear()
    
    def pause(self):
        """Pause and wait for user to press Enter."""
        Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")