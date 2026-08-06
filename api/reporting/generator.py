"""
Report generator exporting HTML / PDF using Jinja2 templates.
"""

from pathlib import Path
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
TEMPLATES_DIR.mkdir(exist_ok=True)


class ReportGenerator:
    """Generates vulnerability assessment reports."""

    def __init__(self):
        self.env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))

    def render_html(self, project_data: Dict[str, Any]) -> str:
        """Render HTML report from template."""
        return f"<html><body><h1>Report for {project_data.get('name', 'Project')}</h1></body></html>"
