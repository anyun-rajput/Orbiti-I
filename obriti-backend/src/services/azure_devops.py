import os
import base64
from typing import Dict, Any, List, Optional
import requests
from datetime import datetime, timedelta, timezone
from urllib.parse import quote


class AzureDevOpsConfigError(Exception):
    pass


def _get_config() -> Dict[str, str]:
    organization = "Fareportal"
    project = "Engineering"
    pat = '7RON8p3JzxdBFAF96ZmWa0MUHPPimi68lGlguJUse6CVOHuOhCyzJQQJ99BEACAAAAAmbwgbAAASAZDO2Ka3'
    if not organization or not project or not pat:
        raise AzureDevOpsConfigError(
            "Missing Azure DevOps configuration. Please set AZDO_ORG, AZDO_PROJECT, and AZDO_PAT environment variables."
        )
    return {"organization": organization, "project": project, "pat": pat}


def _auth_headers(pat: str) -> Dict[str, str]:
    # Azure DevOps uses Basic auth with PAT as password; username can be empty string
    token = base64.b64encode(f":{pat}".encode("utf-8")).decode("utf-8")
    return {
        "Authorization": f"Basic {token}",
        "Accept": "application/json",
    }


# Simple in-memory cache for users to reduce repeated full scans
USERS_CACHE_TTL_SECONDS = 600  # 10 minutes
MAX_SEARCH_RESULTS = 100
_USERS_CACHE: Dict[str, Any] = {"fetched_at": None, "normalized": None}
_SCOPE_DESCRIPTOR_CACHE: Dict[str, Any] = {"descriptor": None, "fetched_at": None}

# Reuse a single session to speed up repeated calls (connection pooling)
AZDO_SESSION = requests.Session()


def _subject_query_users(organization: str, headers: Dict[str, str], search: str) -> List[Dict[str, Any]]:
    url = f"https://vssps.dev.azure.com/{organization}/_apis/graph/subjectquery"
    # Subject Query is only available on preview versions historically
    params = {"api-version": "7.1-preview.1"}
    body = {
        "query": search,
        "subjectKind": ["User"],
    }
    try:
        resp = requests.post(url, headers=headers, params=params, json=body, timeout=10)
        if resp.status_code == 400:
            # Fallback to list approach handled by caller
            return []
        resp.raise_for_status()
        data = resp.json()
        items = data.get("value", []) or data.get("results", []) or []
        normalized: List[Dict[str, Any]] = []
        for u in items:
            normalized.append(
                {
                    "descriptor": u.get("descriptor"),
                    "principalName": u.get("principalName") or u.get("mailAddress"),
                    "displayName": u.get("displayName"),
                    "mailAddress": u.get("mailAddress"),
                }
            )
        return normalized[:MAX_SEARCH_RESULTS]
    except Exception:
        return []


def _get_project_scope_descriptor(organization: str, project: str, headers: Dict[str, str]) -> Optional[str]:
    # Cached for a long time as project descriptor rarely changes
    cached_descriptor = _SCOPE_DESCRIPTOR_CACHE.get("descriptor")
    cached_at = _SCOPE_DESCRIPTOR_CACHE.get("fetched_at")
    if cached_descriptor and cached_at and (datetime.utcnow() - cached_at) < timedelta(hours=12):
        return cached_descriptor  # type: ignore[return-value]

    try:
        # 1) Resolve project to GUID id
        prj_resp = requests.get(
            f"https://dev.azure.com/{organization}/_apis/projects/{project}",
            params={"api-version": "7.0"},
            headers=headers,
            timeout=10,
        )
        prj_resp.raise_for_status()
        prj_id = prj_resp.json().get("id")
        if not prj_id:
            return None
        # 2) Convert GUID to graph descriptor
        desc_resp = requests.get(
            f"https://vssps.dev.azure.com/{organization}/_apis/graph/descriptors/{prj_id}",
            params={"api-version": "7.0"},
            headers=headers,
            timeout=10,
        )
        desc_resp.raise_for_status()
        descriptor = desc_resp.json().get("value")
        if descriptor:
            _SCOPE_DESCRIPTOR_CACHE["descriptor"] = descriptor
            _SCOPE_DESCRIPTOR_CACHE["fetched_at"] = datetime.utcnow()
        return descriptor
    except Exception:
        return None


def _get_current_iteration_path_by_date(org: str, project: str, team: str, headers: Dict[str, str]) -> Optional[str]:
    try:
        team_safe = quote(team, safe="")
        resp = AZDO_SESSION.get(
            f"https://dev.azure.com/{org}/{project}/{team_safe}/_apis/work/teamsettings/iterations",
            params={"api-version": "7.0"},
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        values = resp.json().get("value") or []
        if not values:
            return None

        def parse_iso_to_date(dt_str: Optional[str]) -> Optional[datetime.date]:
            if not dt_str:
                return None
            try:
                if dt_str.endswith("Z"):
                    dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                else:
                    dt = datetime.fromisoformat(dt_str)
                return dt.date()
            except Exception:
                return None

        today = datetime.now().date()
        current_item = None
        closest_future = None
        latest_past = None

        for item in values:
            attrs = item.get("attributes") or {}
            start_d = parse_iso_to_date(attrs.get("startDate"))
            finish_d = parse_iso_to_date(attrs.get("finishDate"))
            if start_d and finish_d:
                if start_d <= today <= finish_d:
                    current_item = item
                    break
                if finish_d < today:
                    if not latest_past or parse_iso_to_date(latest_past.get("attributes", {}).get("finishDate")) < finish_d:
                        latest_past = item
                if start_d > today:
                    if not closest_future or parse_iso_to_date(closest_future.get("attributes", {}).get("startDate")) > start_d:
                        closest_future = item

        chosen = current_item or closest_future or latest_past or (values[0] if values else None)
        if chosen:
            return chosen.get("path") or chosen.get("name")
        return None
    except Exception:
        return None

def _get_default_team_name(org: str, project: str, headers: Dict[str, str]) -> Optional[str]:
    try:
        resp = AZDO_SESSION.get(
            f"https://dev.azure.com/{org}/_apis/projects/{project}",
            params={"api-version": "7.0"},
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        default_team = resp.json().get("defaultTeam") or {}
        return default_team.get("name")
    except Exception:
        return None


def _get_current_iteration_path(org: str, project: str, team: str, headers: Dict[str, str]) -> Optional[str]:
    try:
        team_safe = quote(team, safe="")
        resp = AZDO_SESSION.get(
            f"https://dev.azure.com/{org}/{project}/{team_safe}/_apis/work/teamsettings/iterations",
            params={"api-version": "7.0"},
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        values = resp.json().get("value") or []
        if not values:
            return None

        def parse_iso(dt_str: Optional[str]) -> Optional[datetime]:
            if not dt_str:
                return None
            try:
                if dt_str.endswith("Z"):
                    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                return datetime.fromisoformat(dt_str)
            except Exception:
                return None

        now_utc = datetime.now(timezone.utc)
        current_item = None
        closest_future = None
        latest_past = None

        for item in values:
            attrs = item.get("attributes") or {}
            start = parse_iso(attrs.get("startDate"))
            finish = parse_iso(attrs.get("finishDate"))
            if start and finish:
                if start <= now_utc <= finish:
                    current_item = item
                    break
                if finish < now_utc:
                    if not latest_past or parse_iso(latest_past.get("attributes", {}).get("finishDate")) < finish:
                        latest_past = item
                if start > now_utc:
                    if not closest_future or parse_iso(closest_future.get("attributes", {}).get("startDate")) > start:
                        closest_future = item

        chosen = current_item or closest_future or latest_past or (values[0] if values else None)
        if chosen:
            return chosen.get("path") or chosen.get("name")
        return None
    except Exception:
        return None


def _get_current_iteration_via_team(org: str, project: str, team: str, headers: Dict[str, str]) -> Optional[str]:
    try:
        team_safe = quote(team, safe="")
        resp = AZDO_SESSION.get(
            f"https://dev.azure.com/{org}/{project}/{team_safe}/_apis/work/teamsettings/iterations",
            params={"api-version": "7.0", "timeframe": "current"},
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        values = resp.json().get("value") or []
        if values:
            current = values[0]
            return current.get("path") or current.get("name")
        return None
    except Exception:
        return None


def _get_current_iteration_via_classification(org: str, project: str, headers: Dict[str, str]) -> Optional[str]:
    try:
        resp = AZDO_SESSION.get(
            f"https://dev.azure.com/{org}/{project}/_apis/wit/classificationnodes/iterations",
            params={"api-version": "7.0", "$depth": "10"},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        tree = resp.json()

        offset_min = int(os.environ.get("AZDO_TZ_OFFSET_MINUTES", "0"))
        today = (datetime.utcnow() + timedelta(minutes=offset_min)).date()

        def parse_date(d: Optional[str]) -> Optional[datetime.date]:
            if not d:
                return None
            try:
                if d.endswith("Z"):
                    return datetime.fromisoformat(d.replace("Z", "+00:00")).date()
                return datetime.fromisoformat(d).date()
            except Exception:
                return None

        def dfs(node: Dict[str, Any], current_path: List[str]) -> Optional[str]:
            name = node.get("name")
            path = node.get("path")
            attrs = node.get("attributes") or {}
            start = parse_date(attrs.get("startDate"))
            finish = parse_date(attrs.get("finishDate"))
            if start and finish and start <= today <= finish:
                return path or "\\".join(current_path + [name]) if name else path
            for child in node.get("children", []) or []:
                found = dfs(child, (current_path + [name]) if name else current_path)
                if found:
                    return found
            return None

        return dfs(tree, [])
    except Exception:
        return None


def list_users(search: Optional[str] = None) -> List[Dict[str, Any]]:
    cfg = _get_config()
    headers = _auth_headers(cfg["pat"])  # type: ignore[arg-type]
    url = f"https://vssps.dev.azure.com/{cfg['organization']}/_apis/graph/users"

    # Fast path for search: use server-side subject query
    if search:
        quick = _subject_query_users(cfg["organization"], headers, search)
        if quick:
            return quick

    # Try API 7.0 first; if not supported for Graph Users, fall back to 7.1-preview.1
    api_versions = ["7.0", "7.1-preview.1"]
    users: List[Dict[str, Any]] = []
    last_error: Optional[Exception] = None

    # Serve from cache if available and not expired
    now = datetime.utcnow()
    cached_at: Optional[datetime] = _USERS_CACHE.get("fetched_at")  # type: ignore[assignment]
    cached_normalized: Optional[List[Dict[str, Any]]] = _USERS_CACHE.get("normalized")  # type: ignore[assignment]
    if cached_at and cached_normalized and (now - cached_at) < timedelta(seconds=USERS_CACHE_TTL_SECONDS):
        if search:
            s = search.lower()
            filtered = [
                u for u in cached_normalized
                if ((u.get("displayName") or "").lower().find(s) != -1)
                or ((u.get("principalName") or "").lower().find(s) != -1)
                or ((u.get("mailAddress") or "").lower().find(s) != -1)
            ]
            return filtered[:MAX_SEARCH_RESULTS]
        return cached_normalized

    for api_version in api_versions:
        try:
            collected: List[Dict[str, Any]] = []
            # If search provided, collect only up to MAX_SEARCH_RESULTS for speed
            matched: List[Dict[str, Any]] = []
            continuation_token: Optional[str] = None
            fetched_all_pages = True
            while True:
                params: Dict[str, str] = {"api-version": api_version}
                # Prefer AAD users and larger page sizes to reduce round-trips
                params["subjectTypes"] = "aad"
                params["$top"] = "1000"
                # If possible, scope to the specific project to reduce the universe drastically
                scope_descriptor = _get_project_scope_descriptor(cfg["organization"], cfg["project"], headers)
                if scope_descriptor:
                    params["scopeDescriptor"] = scope_descriptor
                if continuation_token:
                    params["continuationToken"] = continuation_token

                resp = requests.get(url, headers=headers, params=params, timeout=20)

                # Some orgs return 400 for non-supported versions; try next version
                if resp.status_code == 400 and api_version == "7.0":
                    break

                resp.raise_for_status()
                data = resp.json()
                page_users = data.get("value", [])
                # Normalize this page
                page_normalized: List[Dict[str, Any]] = []
                for u in page_users:
                    page_normalized.append(
                        {
                            "descriptor": u.get("descriptor"),
                            "principalName": u.get("principalName") or u.get("mailAddress"),
                            "displayName": u.get("displayName"),
                            "mailAddress": u.get("mailAddress"),
                        }
                    )

                collected.extend(page_normalized)

                # If searching, filter on-the-fly and early-exit when enough
                if search:
                    s = search.lower()
                    for u in page_normalized:
                        if (
                            (u.get("displayName") or "").lower().find(s) != -1
                            or (u.get("principalName") or "").lower().find(s) != -1
                            or (u.get("mailAddress") or "").lower().find(s) != -1
                        ):
                            matched.append(u)
                            if len(matched) >= MAX_SEARCH_RESULTS:
                                fetched_all_pages = False
                                break
                    if len(matched) >= MAX_SEARCH_RESULTS:
                        break

                continuation_header = resp.headers.get("x-ms-continuationtoken")
                if continuation_header:
                    continuation_token = continuation_header.split(",")[0].strip()
                else:
                    break

            if collected:
                users = matched if search else collected
                # Cache only if we fetched the full set (no early exit)
                if not search and fetched_all_pages:
                    _USERS_CACHE["fetched_at"] = datetime.utcnow()
                    _USERS_CACHE["normalized"] = collected
                break
        except Exception as e:  # pragma: no cover - network/remote errors
            last_error = e
            continue
    if not users and last_error:
        # If both versions failed, re-raise the last error
        raise last_error
    # Normalize to a minimal shape we need on the frontend
    return users


def create_work_item(
    title: str,
    description_markdown: str,
    assigned_to: Optional[str] = None,
    work_item_type: str = "Issue",
) -> Dict[str, Any]:
    cfg = _get_config()
    headers = _auth_headers(cfg["pat"])  # type: ignore[arg-type]
    headers.update({"Content-Type": "application/json-patch+json"})

    url = (
        f"https://dev.azure.com/{cfg['organization']}/{cfg['project']}"
        f"/_apis/wit/workitems/${work_item_type}"
    )

    body: List[Dict[str, Any]] = [
        {"op": "add", "path": "/fields/System.Title", "from": None, "value": title},
        {
            "op": "add",
            "path": "/fields/System.Description",
            "from": None,
            "value": description_markdown,
        },
    ]
    # Set requested Area Path
    body.append(
        {
            "op": "add",
            "path": "/fields/System.AreaPath",
            "from": None,
            "value": "Engineering\\InfoSec\\DevSecOps",
        }
    )

    # Determine current iteration path via the most reliable resolvers
    team_name = _get_default_team_name(cfg["organization"], cfg["project"], headers) or cfg["project"]
    iteration_path = None
    if not iteration_path:
        iteration_path = _get_current_iteration_via_team(cfg["organization"], cfg["project"], team_name, headers)
    if not iteration_path:
        iteration_path = _get_current_iteration_via_classification(cfg["organization"], cfg["project"], headers)
    if not iteration_path:
        iteration_path = _get_current_iteration_path_by_date(cfg["organization"], cfg["project"], team_name, headers)
    if iteration_path:
        body.append(
            {
                "op": "add",
                "path": "/fields/System.IterationPath",
                "from": None,
                "value": iteration_path,
            }
        )
    if assigned_to:
        body.append(
            {
                "op": "add",
                "path": "/fields/System.AssignedTo",
                "from": None,
                "value": assigned_to,
            }
        )

    # Try fast path first; fallback permutations to avoid server-side 500s
    def _attempt_create(bypass_rules: bool, suppress_notifications: bool) -> requests.Response:
        params = {"api-version": "7.0"}
        if suppress_notifications:
            params["suppressNotifications"] = "true"
        if bypass_rules:
            params["bypassRules"] = "true"
        # Azure DevOps expects PATCH for JSON Patch documents
        last_exc: Optional[Exception] = None
        # Retry twice on read timeout with increasing read timeouts
        for connect_timeout, read_timeout in [(5, 35), (5, 60)]:
            try:
                return AZDO_SESSION.patch(
                    url, headers=headers, params=params, json=body, timeout=(connect_timeout, read_timeout)
                )
            except requests.exceptions.ReadTimeout as e:
                last_exc = e
                continue
        if last_exc:
            raise last_exc
        # Fallback return
        return AZDO_SESSION.patch(url, headers=headers, params=params, json=body, timeout=(5, 35))

    resp = _attempt_create(bypass_rules=True, suppress_notifications=True)
    if resp.status_code >= 500 or resp.status_code in (400, 401, 403):
        resp = _attempt_create(bypass_rules=False, suppress_notifications=True)
        if resp.status_code >= 500 or resp.status_code in (400, 401, 403):
            resp = _attempt_create(bypass_rules=False, suppress_notifications=False)
    resp.raise_for_status()
    item = resp.json()
    work_item_id = item.get("id")
    web_url = (
        f"https://dev.azure.com/{cfg['organization']}/{cfg['project']}/_workitems/edit/{work_item_id}"
        if work_item_id is not None
        else None
    )
    return {"id": work_item_id, "url": item.get("url"), "webUrl": web_url, "item": item}


