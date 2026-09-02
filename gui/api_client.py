"""
API Client wrapper for SentryPack REST endpoints and WebSocket subscriptions.
"""

from typing import Any, Dict, Optional

import requests


class SentryPackAPIClient:
    """REST API and WebSocket client wrapper for SentryPack GUI."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip("/")

    # ------------------------------------------------------------------
    # Modules
    # ------------------------------------------------------------------

    def get_modules(self) -> Dict[str, Any]:
        """Fetch available modules."""
        response = requests.get(f"{self.base_url}/api/modules/")
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # Projects
    # ------------------------------------------------------------------

    def get_projects(self) -> Dict[str, Any]:
        """Fetch all projects."""
        response = requests.get(f"{self.base_url}/api/projects/")
        response.raise_for_status()
        return response.json()

    def get_project(self, project_id: int) -> Dict[str, Any]:
        """Fetch a single project by ID."""
        response = requests.get(
            f"{self.base_url}/api/projects/{project_id}"
        )
        response.raise_for_status()
        return response.json()

    def create_project(
        self,
        name: str,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new project."""
        payload = {
            "name": name,
            "description": description,
        }

        response = requests.post(
            f"{self.base_url}/api/projects/",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    def update_project(
        self,
        project_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update an existing project."""
        payload: Dict[str, Any] = {}

        if name is not None:
            payload["name"] = name

        if description is not None:
            payload["description"] = description

        response = requests.put(
            f"{self.base_url}/api/projects/{project_id}",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    def delete_project(self, project_id: int) -> Dict[str, Any]:
        """Delete a project by ID."""
        response = requests.delete(
            f"{self.base_url}/api/projects/{project_id}"
        )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    def get_targets(self) -> Dict[str, Any]:
        """Fetch all targets."""
        response = requests.get(f"{self.base_url}/api/targets/")
        response.raise_for_status()
        return response.json()

    def get_target(self, target_id: int) -> Dict[str, Any]:
        """Fetch a single target by ID."""
        response = requests.get(
            f"{self.base_url}/api/targets/{target_id}"
        )
        response.raise_for_status()
        return response.json()

    # def create_target(
    #     self,
    #     project_id: int,
    #     name: str,
    #     ip_address: str,
    # ) -> Dict[str, Any]:
    #     """Create a new target."""
    #     params = {
    #         "project_id": project_id,
    #         "name": name,
    #         "ip_address": ip_address,
    #     }

    #     response = requests.post(
    #         f"{self.base_url}/api/targets/",
    #         params=params,
    #     )
    #     response.raise_for_status()
    #     return response.json()
    def create_target(
        self,
        project_id: int,
        name: str,
        ip_address: str,
    ) -> Dict[str, Any]:
        """Create a new target."""
        payload = {
            "project_id": project_id,
            "name": name,
            "ip_address": ip_address,
        }

        response = requests.post(
            f"{self.base_url}/api/targets/",
            json=payload,
        )
        response.raise_for_status()
        return response.json()
    def update_target(
        self,
        target_id: int,
        name: Optional[str] = None,
        ip_address: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update an existing target."""
        payload: Dict[str, Any] = {}

        if name is not None:
            payload["name"] = name

        if ip_address is not None:
            payload["ip_address"] = ip_address

        if status is not None:
            payload["status"] = status

        response = requests.put(
            f"{self.base_url}/api/targets/{target_id}",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    def delete_target(self, target_id: int) -> Dict[str, Any]:
        """Delete a target by ID."""
        response = requests.delete(
            f"{self.base_url}/api/targets/{target_id}"
        )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    def get_target_recommendations(
        self,
        target_id: int,
    ) -> Dict[str, Any]:
        """Fetch module recommendations for a target."""
        response = requests.get(
            f"{self.base_url}/api/targets/{target_id}/recommendations"
        )
        response.raise_for_status()
        return response.json()
    
    


    def get_target_findings(
        self,
        target_id: int,
    ) -> Dict[str, Any]:
        """Fetch findings for a target."""
        response = requests.get(
            f"{self.base_url}/api/targets/{target_id}/findings"
        )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # Module Execution & Runs
    # ------------------------------------------------------------------

    def run_module(
        self,
        target_id: int,
        module_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Trigger execution of a module against a target."""
        payload = {
            "module_id": module_id,
            "options": options or {},
        }
        response = requests.post(
            f"{self.base_url}/api/targets/{target_id}/run",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    def get_run_status(self, run_id: str) -> Dict[str, Any]:
        """Poll the status of an ongoing or completed module run."""
        response = requests.get(f"{self.base_url}/api/runs/{run_id}/status")
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # C2 Sessions & Interactive Tasks
    # ------------------------------------------------------------------

    def get_c2_sessions(self, status: Optional[str] = None) -> Dict[str, Any]:
        """Fetch all C2 sessions, optionally filtered by status."""
        url = f"{self.base_url}/api/sessions/"
        params = {"status": status} if status else {}
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def get_c2_session(self, session_id: str) -> Dict[str, Any]:
        """Fetch a single C2 session by ID."""
        response = requests.get(f"{self.base_url}/api/sessions/{session_id}")
        response.raise_for_status()
        return response.json()

    def create_session_task(self, session_id: str, command: str) -> Dict[str, Any]:
        """Enqueue a command task on an active C2 session."""
        response = requests.post(
            f"{self.base_url}/api/sessions/{session_id}/tasks",
            json={"command": command},
        )
        response.raise_for_status()
        return response.json()

    def get_session_tasks(self, session_id: str) -> Dict[str, Any]:
        """List tasks for a C2 session."""
        response = requests.get(f"{self.base_url}/api/sessions/{session_id}/tasks")
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # Global Findings Aggregation
    # ------------------------------------------------------------------

    def get_all_findings(self, project_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetch all findings across targets, optionally scoped to a project."""
        all_findings: List[Dict[str, Any]] = []
        targets_resp = self.get_targets()
        targets = targets_resp.get("targets", [])

        if project_id is not None:
            targets = [t for t in targets if t.get("project_id") == project_id]

        for target in targets:
            tid = target.get("id")
            if tid is not None:
                try:
                    f_resp = self.get_target_findings(tid)
                    for f in f_resp.get("findings", []):
                        f["target_name"] = target.get("name", "Unknown")
                        f["target_ip"] = target.get("ip_address", "Unknown")
                        all_findings.append(f)
                except Exception:
                    continue

        return all_findings