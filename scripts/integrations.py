#!/usr/bin/env python3
"""
Phishing Email Forensics — Integrations Module
=================================================
Connecteurs bidirectionnels pour RTIR, TheHive et JIRA.
Chaque connecteur expose la meme interface:
  - test_connection()   → bool
  - get_users()         → list[dict]
  - get_queues()        → list[dict]
  - create_ticket(data) → dict
  - update_ticket(id, data) → dict
  - get_ticket(id)      → dict
  - add_comment(id, text, author) → dict
  - list_tickets(filters) → list[dict]
"""

import json
import os
import urllib.request
import urllib.error
import urllib.parse
import ssl
from base64 import b64encode
from datetime import datetime


# ══════════════════════════════════════════════════
# BASE CONNECTOR
# ══════════════════════════════════════════════════

class BaseConnector:
    """Interface commune pour tous les connecteurs."""

    name = "base"
    display_name = "Base"

    def __init__(self, config: dict):
        self.config = config
        self.base_url = config.get("url", "").rstrip("/")
        self._ctx = ssl.create_default_context()
        if config.get("verify_ssl") is False:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, data=None, headers=None) -> dict:
        url = f"{self.base_url}{path}"
        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")

        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            hdrs.update(headers)

        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)

        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=15) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            body_err = e.read().decode("utf-8", errors="replace")[:500]
            return {"error": f"HTTP {e.code}: {body_err}"}
        except urllib.error.URLError as e:
            return {"error": f"Connection failed: {str(e.reason)}"}
        except Exception as e:
            return {"error": str(e)}

    def test_connection(self) -> dict:
        raise NotImplementedError

    def get_users(self) -> list:
        raise NotImplementedError

    def get_queues(self) -> list:
        raise NotImplementedError

    def create_ticket(self, data: dict) -> dict:
        raise NotImplementedError

    def update_ticket(self, ticket_id: str, data: dict) -> dict:
        raise NotImplementedError

    def get_ticket(self, ticket_id: str) -> dict:
        raise NotImplementedError

    def add_comment(self, ticket_id: str, text: str, author: str = "") -> dict:
        raise NotImplementedError

    def list_tickets(self, filters: dict = None) -> list:
        raise NotImplementedError


# ══════════════════════════════════════════════════
# RTIR CONNECTOR (Request Tracker for Incident Response)
# ══════════════════════════════════════════════════

class RTIRConnector(BaseConnector):
    """
    Connecteur RTIR via RT REST2 API.
    Config requise: url, token (ou user/password)
    """

    name = "rtir"
    display_name = "RTIR (Request Tracker)"

    def __init__(self, config: dict):
        super().__init__(config)
        self.token = config.get("token", "")
        self.user = config.get("user", "")
        self.password = config.get("password", "")

    def _auth_headers(self) -> dict:
        if self.token:
            return {"Authorization": f"token {self.token}"}
        elif self.user and self.password:
            creds = b64encode(f"{self.user}:{self.password}".encode()).decode()
            return {"Authorization": f"Basic {creds}"}
        return {}

    def _request(self, method, path, data=None, headers=None):
        hdrs = self._auth_headers()
        if headers:
            hdrs.update(headers)
        return super()._request(method, path, data, hdrs)

    def test_connection(self) -> dict:
        result = self._request("GET", "/REST/2.0/")
        if "error" in result:
            return {"connected": False, "error": result["error"]}
        return {"connected": True, "version": result.get("Version", "unknown")}

    def get_users(self) -> list:
        result = self._request("GET", "/REST/2.0/users?per_page=100")
        if "error" in result:
            return []
        items = result.get("items", [])
        return [{"id": u.get("id", ""), "name": u.get("id", ""),
                 "email": u.get("id", "")} for u in items]

    def get_queues(self) -> list:
        result = self._request("GET", "/REST/2.0/queues?per_page=50")
        if "error" in result:
            return []
        items = result.get("items", [])
        return [{"id": q.get("id", ""), "name": q.get("id", "")} for q in items]

    def create_ticket(self, data: dict) -> dict:
        payload = {
            "Queue": data.get("queue", "Incident Reports"),
            "Subject": data.get("title", "New Incident"),
            "Priority": self._map_priority(data.get("priority", "medium")),
            "Owner": data.get("assignee", "Nobody"),
            "Content": data.get("description", ""),
            "ContentType": "text/plain",
        }
        if data.get("custom_fields"):
            payload["CustomFields"] = data["custom_fields"]

        result = self._request("POST", "/REST/2.0/ticket", payload)
        if "error" in result:
            return result
        return {
            "id": str(result.get("id", "")),
            "url": f"{self.base_url}/Ticket/Display.html?id={result.get('id', '')}",
            "status": "created"
        }

    def update_ticket(self, ticket_id: str, data: dict) -> dict:
        payload = {}
        if "status" in data:
            status_map = {"open": "new", "in_progress": "open", "closed": "resolved"}
            payload["Status"] = status_map.get(data["status"], data["status"])
        if "priority" in data:
            payload["Priority"] = self._map_priority(data["priority"])
        if "assignee" in data:
            payload["Owner"] = data["assignee"]
        if "title" in data:
            payload["Subject"] = data["title"]

        result = self._request("PUT", f"/REST/2.0/ticket/{ticket_id}", payload)
        return result if "error" in result else {"status": "updated"}

    def get_ticket(self, ticket_id: str) -> dict:
        result = self._request("GET", f"/REST/2.0/ticket/{ticket_id}")
        if "error" in result:
            return result
        return {
            "id": str(result.get("id", "")),
            "title": result.get("Subject", ""),
            "status": result.get("Status", ""),
            "priority": result.get("Priority", ""),
            "assignee": result.get("Owner", ""),
            "created": result.get("Created", ""),
            "updated": result.get("LastUpdated", ""),
        }

    def add_comment(self, ticket_id: str, text: str, author: str = "") -> dict:
        payload = {
            "Content": f"[{author}] {text}" if author else text,
            "ContentType": "text/plain",
        }
        result = self._request("POST", f"/REST/2.0/ticket/{ticket_id}/comment", payload)
        return result if "error" in result else {"status": "comment_added"}

    def list_tickets(self, filters: dict = None) -> list:
        query_parts = []
        if filters:
            if filters.get("status"):
                query_parts.append(f"Status='{filters['status']}'")
            if filters.get("queue"):
                query_parts.append(f"Queue='{filters['queue']}'")
        query = " AND ".join(query_parts) if query_parts else "Status!='deleted'"

        result = self._request("GET",
            f"/REST/2.0/tickets?query={urllib.parse.quote(query)}&per_page=50&orderby=-Created")
        if "error" in result:
            return []
        items = result.get("items", [])
        return [{"id": t.get("id", ""), "title": t.get("id", "")} for t in items]

    @staticmethod
    def _map_priority(p: str) -> int:
        return {"critical": 90, "high": 70, "medium": 50, "low": 20}.get(p, 50)


# ══════════════════════════════════════════════════
# THEHIVE CONNECTOR
# ══════════════════════════════════════════════════

class TheHiveConnector(BaseConnector):
    """
    Connecteur TheHive 5.x via API REST.
    Config requise: url, api_key
    """

    name = "thehive"
    display_name = "TheHive"

    def __init__(self, config: dict):
        super().__init__(config)
        self.api_key = config.get("api_key", "")

    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    def _request(self, method, path, data=None, headers=None):
        hdrs = self._auth_headers()
        if headers:
            hdrs.update(headers)
        return super()._request(method, path, data, hdrs)

    def test_connection(self) -> dict:
        result = self._request("GET", "/api/v1/status")
        if "error" in result:
            return {"connected": False, "error": result["error"]}
        return {"connected": True, "version": result.get("versions", {}).get("TheHive", "unknown")}

    def get_users(self) -> list:
        result = self._request("POST", "/api/v1/query", {
            "query": [{"_name": "listUser"}]
        })
        if isinstance(result, dict) and "error" in result:
            return []
        if isinstance(result, list):
            return [{"id": u.get("_id", ""), "name": u.get("name", ""),
                     "email": u.get("login", "")} for u in result]
        return []

    def get_queues(self) -> list:
        result = self._request("POST", "/api/v1/query", {
            "query": [{"_name": "listOrganisation"}]
        })
        if isinstance(result, dict) and "error" in result:
            return []
        if isinstance(result, list):
            return [{"id": o.get("_id", ""), "name": o.get("name", "")} for o in result]
        return []

    def create_ticket(self, data: dict) -> dict:
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        tlp_map = {"critical": 3, "high": 2, "medium": 2, "low": 1}

        payload = {
            "title": data.get("title", "New Alert"),
            "description": data.get("description", ""),
            "severity": severity_map.get(data.get("priority", "medium"), 2),
            "tlp": tlp_map.get(data.get("priority", "medium"), 2),
            "type": "phishing",
            "source": "Phishing Email Forensics",
            "sourceRef": f"PEF-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "tags": data.get("tags", ["phishing", "email-forensics"]),
        }

        if data.get("assignee"):
            payload["assignee"] = data["assignee"]

        # Create as alert first (TheHive workflow)
        result = self._request("POST", "/api/v1/alert", payload)
        if "error" in result:
            return result
        return {
            "id": result.get("_id", ""),
            "url": f"{self.base_url}/alerts/{result.get('_id', '')}/details",
            "status": "created",
            "type": "alert"
        }

    def update_ticket(self, ticket_id: str, data: dict) -> dict:
        payload = {}
        if "status" in data:
            status_map = {"open": "New", "in_progress": "InProgress", "closed": "Resolved"}
            payload["status"] = status_map.get(data["status"], data["status"])
        if "priority" in data:
            severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            payload["severity"] = severity_map.get(data["priority"], 2)
        if "assignee" in data:
            payload["assignee"] = data["assignee"]
        if "title" in data:
            payload["title"] = data["title"]

        result = self._request("PATCH", f"/api/v1/alert/{ticket_id}", payload)
        return result if "error" in result else {"status": "updated"}

    def get_ticket(self, ticket_id: str) -> dict:
        result = self._request("GET", f"/api/v1/alert/{ticket_id}")
        if "error" in result:
            return result
        severity_rev = {4: "critical", 3: "high", 2: "medium", 1: "low"}
        return {
            "id": result.get("_id", ""),
            "title": result.get("title", ""),
            "status": result.get("status", ""),
            "priority": severity_rev.get(result.get("severity", 2), "medium"),
            "assignee": result.get("assignee", ""),
            "created": result.get("_createdAt", ""),
            "updated": result.get("_updatedAt", ""),
        }

    def add_comment(self, ticket_id: str, text: str, author: str = "") -> dict:
        # TheHive uses task logs for comments
        msg = f"[{author}] {text}" if author else text
        # For alerts, we update the description (append)
        current = self._request("GET", f"/api/v1/alert/{ticket_id}")
        if "error" in current:
            return current
        desc = current.get("description", "")
        new_desc = f"{desc}\n\n---\n**{author or 'Analyst'}** ({datetime.now().strftime('%d/%m/%Y %H:%M')}):\n{text}"
        result = self._request("PATCH", f"/api/v1/alert/{ticket_id}", {"description": new_desc})
        return result if "error" in result else {"status": "comment_added"}

    def list_tickets(self, filters: dict = None) -> list:
        query = {"query": [
            {"_name": "listAlert"},
            {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
            {"_name": "page", "from": 0, "to": 50}
        ]}
        result = self._request("POST", "/api/v1/query", query)
        if isinstance(result, dict) and "error" in result:
            return []
        if isinstance(result, list):
            severity_rev = {4: "critical", 3: "high", 2: "medium", 1: "low"}
            return [{
                "id": a.get("_id", ""),
                "title": a.get("title", ""),
                "status": a.get("status", ""),
                "priority": severity_rev.get(a.get("severity", 2), "medium"),
                "assignee": a.get("assignee", ""),
                "created": a.get("_createdAt", ""),
            } for a in result]
        return []


# ══════════════════════════════════════════════════
# JIRA CONNECTOR
# ══════════════════════════════════════════════════

class JIRAConnector(BaseConnector):
    """
    Connecteur JIRA Cloud/Server via REST API v2.
    Config requise: url, user, api_token, project_key
    """

    name = "jira"
    display_name = "JIRA"

    def __init__(self, config: dict):
        super().__init__(config)
        self.user = config.get("user", "")
        self.api_token = config.get("api_token", "")
        self.project_key = config.get("project_key", "SEC")

    def _auth_headers(self) -> dict:
        creds = b64encode(f"{self.user}:{self.api_token}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}

    def _request(self, method, path, data=None, headers=None):
        hdrs = self._auth_headers()
        if headers:
            hdrs.update(headers)
        return super()._request(method, path, data, hdrs)

    def test_connection(self) -> dict:
        result = self._request("GET", "/rest/api/2/myself")
        if "error" in result:
            return {"connected": False, "error": result["error"]}
        return {
            "connected": True,
            "user": result.get("displayName", ""),
            "email": result.get("emailAddress", "")
        }

    def get_users(self) -> list:
        result = self._request("GET",
            f"/rest/api/2/user/assignable/search?project={self.project_key}&maxResults=100")
        if isinstance(result, dict) and "error" in result:
            return []
        if isinstance(result, list):
            return [{"id": u.get("accountId", u.get("key", "")),
                     "name": u.get("displayName", ""),
                     "email": u.get("emailAddress", "")} for u in result]
        return []

    def get_queues(self) -> list:
        result = self._request("GET", "/rest/api/2/project")
        if isinstance(result, dict) and "error" in result:
            return []
        if isinstance(result, list):
            return [{"id": p.get("key", ""), "name": p.get("name", "")} for p in result]
        return []

    def create_ticket(self, data: dict) -> dict:
        priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}
        payload = {
            "fields": {
                "project": {"key": data.get("project_key", self.project_key)},
                "summary": data.get("title", "Security Incident"),
                "description": data.get("description", ""),
                "issuetype": {"name": data.get("issue_type", "Bug")},
                "priority": {"name": priority_map.get(data.get("priority", "medium"), "Medium")},
            }
        }
        if data.get("assignee"):
            payload["fields"]["assignee"] = {"accountId": data["assignee"]}
        if data.get("labels"):
            payload["fields"]["labels"] = data["labels"]
        else:
            payload["fields"]["labels"] = ["phishing", "security-incident"]

        result = self._request("POST", "/rest/api/2/issue", payload)
        if "error" in result:
            return result
        return {
            "id": result.get("key", result.get("id", "")),
            "url": f"{self.base_url}/browse/{result.get('key', '')}",
            "status": "created"
        }

    def update_ticket(self, ticket_id: str, data: dict) -> dict:
        payload = {"fields": {}}
        if "title" in data:
            payload["fields"]["summary"] = data["title"]
        if "priority" in data:
            priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}
            payload["fields"]["priority"] = {"name": priority_map.get(data["priority"], "Medium")}
        if "assignee" in data:
            payload["fields"]["assignee"] = {"accountId": data["assignee"]}

        result = self._request("PUT", f"/rest/api/2/issue/{ticket_id}", payload)

        # Handle status transitions separately
        if "status" in data:
            self._transition_ticket(ticket_id, data["status"])

        return result if (isinstance(result, dict) and "error" in result) else {"status": "updated"}

    def _transition_ticket(self, ticket_id: str, status: str):
        """JIRA uses transitions for status changes."""
        transitions = self._request("GET", f"/rest/api/2/issue/{ticket_id}/transitions")
        if "error" in transitions:
            return
        status_map = {"open": "To Do", "in_progress": "In Progress", "closed": "Done"}
        target = status_map.get(status, status)
        for t in transitions.get("transitions", []):
            if t.get("name", "").lower() == target.lower():
                self._request("POST", f"/rest/api/2/issue/{ticket_id}/transitions",
                            {"transition": {"id": t["id"]}})
                break

    def get_ticket(self, ticket_id: str) -> dict:
        result = self._request("GET", f"/rest/api/2/issue/{ticket_id}")
        if "error" in result:
            return result
        fields = result.get("fields", {})
        priority_rev = {"Highest": "critical", "High": "high", "Medium": "medium", "Low": "low"}
        return {
            "id": result.get("key", ""),
            "title": fields.get("summary", ""),
            "status": (fields.get("status", {}) or {}).get("name", ""),
            "priority": priority_rev.get((fields.get("priority", {}) or {}).get("name", ""), "medium"),
            "assignee": (fields.get("assignee", {}) or {}).get("displayName", ""),
            "created": fields.get("created", ""),
            "updated": fields.get("updated", ""),
        }

    def add_comment(self, ticket_id: str, text: str, author: str = "") -> dict:
        body = f"*{author}*: {text}" if author else text
        result = self._request("POST", f"/rest/api/2/issue/{ticket_id}/comment",
                             {"body": body})
        return result if "error" in result else {"status": "comment_added"}

    def list_tickets(self, filters: dict = None) -> list:
        jql_parts = [f"project={self.project_key}"]
        if filters:
            if filters.get("status"):
                jql_parts.append(f"status='{filters['status']}'")
            if filters.get("assignee"):
                jql_parts.append(f"assignee='{filters['assignee']}'")
        jql = " AND ".join(jql_parts) + " ORDER BY created DESC"

        result = self._request("GET",
            f"/rest/api/2/search?jql={urllib.parse.quote(jql)}&maxResults=50")
        if "error" in result:
            return []
        issues = result.get("issues", [])
        priority_rev = {"Highest": "critical", "High": "high", "Medium": "medium", "Low": "low"}
        return [{
            "id": i.get("key", ""),
            "title": i.get("fields", {}).get("summary", ""),
            "status": (i.get("fields", {}).get("status", {}) or {}).get("name", ""),
            "priority": priority_rev.get(
                (i.get("fields", {}).get("priority", {}) or {}).get("name", ""), "medium"),
            "assignee": (i.get("fields", {}).get("assignee", {}) or {}).get("displayName", ""),
            "created": i.get("fields", {}).get("created", ""),
        } for i in issues]


# ══════════════════════════════════════════════════
# CONNECTOR FACTORY
# ══════════════════════════════════════════════════

CONNECTORS = {
    "rtir": RTIRConnector,
    "thehive": TheHiveConnector,
    "jira": JIRAConnector,
}


def get_connector(name: str, config: dict) -> BaseConnector:
    """Retourne un connecteur instancie par nom."""
    cls = CONNECTORS.get(name)
    if not cls:
        raise ValueError(f"Connecteur inconnu: {name}. Disponibles: {list(CONNECTORS.keys())}")
    return cls(config)


def list_available_connectors() -> list:
    """Liste les connecteurs disponibles."""
    return [{"name": k, "display_name": v.display_name} for k, v in CONNECTORS.items()]
