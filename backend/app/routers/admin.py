import os
import subprocess
import shutil
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse

from app.database import get_db
from app.helpers import require_admin, now_iso, logger

router = APIRouter(prefix="/admin", tags=["admin"])

CRONICLE_TITLE_PREFIX = "Disk-Monitor - "

CRONICLE_JOBS = [
    {
        "key": "docker_prune",
        "title": "Nettoyage Docker complet",
        "description": "Supprime les images inutilisées, volumes orphelins et build cache.",
        "schedule": "Tous les dimanches à 03:00",
        "command": 'curl -sf -X POST https://stat.it-sefako.com/disks/cleanup/execute/cron -H "Content-Type: application/json" -H "X-Internal-Token: c287fbf8fc89988b602bbad5ce828c18e537f96eb4c912b927fc40757779f7ea" -d \'{"action":"docker_prune"}\'',
        "timing": {"hours": [3], "minutes": [0]},
    },
    {
        "key": "log_rotation",
        "title": "Rotation des logs",
        "description": "Vacuum journalctl et suppression des logs anciens.",
        "schedule": "Tous les jours à 02:00",
        "command": 'curl -sf -X POST https://stat.it-sefako.com/disks/cleanup/execute/cron -H "Content-Type: application/json" -H "X-Internal-Token: c287fbf8fc89988b602bbad5ce828c18e537f96eb4c912b927fc40757779f7ea" -d \'{"action":"logs"}\'',
        "timing": {"hours": [2], "minutes": [0]},
    },
    {
        "key": "tmp_cleanup",
        "title": "Nettoyage /tmp",
        "description": "Supprime les fichiers temporaires de plus de 7 jours.",
        "schedule": "Tous les jours à 04:00",
        "command": 'curl -sf -X POST https://stat.it-sefako.com/disks/cleanup/execute/cron -H "Content-Type: application/json" -H "X-Internal-Token: c287fbf8fc89988b602bbad5ce828c18e537f96eb4c912b927fc40757779f7ea" -d \'{"action":"tmp"}\'',
        "timing": {"hours": [4], "minutes": [0]},
    },
    {
        "key": "pnpm_cache",
        "title": "Nettoyage cache pnpm",
        "description": "Purge le store pnpm si > 500MB.",
        "schedule": "Tous les lundis à 05:00",
        "command": 'curl -sf -X POST https://stat.it-sefako.com/disks/cleanup/execute/cron -H "Content-Type: application/json" -H "X-Internal-Token: c287fbf8fc89988b602bbad5ce828c18e537f96eb4c912b927fc40757779f7ea" -d \'{"action":"pnpm"}\'',
        "timing": {"hours": [5], "minutes": [0]},
    },
]


def _get_cronicle_config():
    db = get_db()
    row = db.execute("SELECT url, api_key FROM cronicle_config WHERE id = 1").fetchone()
    if row:
        return {"url": row["url"], "api_key": row["api_key"]}
    return {"url": "", "api_key": ""}


def normalize_cronicle_url(url: str) -> str:
    url = (url or "").strip()
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")
    if url.endswith("/api"):
        url = url[:-4].rstrip("/")
    return url


def mask_secret(value: Optional[str]) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) <= 12:
        return "•" * len(value)
    return value[:8] + "•" * (len(value) - 12) + value[-4:]


def cronicle_payload(job: dict) -> dict:
    return {
        "enabled": 1,
        "title": CRONICLE_TITLE_PREFIX + job["title"],
        "timezone": "Africa/Lome",
        "category": "general",
        "target": "allgrp",
        "algo": "prefer_first",
        "plugin": "shellplug",
        "params": {
            "script": "#!/bin/bash\n" + job["command"],
            "annotate": 1,
            "json": 1,
        },
        "timing": job["timing"],
        "max_children": 1,
        "timeout": 0,
        "retries": 0,
        "queue": 0,
        "queue_max": 0,
        "catch_up": 0,
        "detached": 0,
        "notes": job["description"],
    }


@router.get("/cronicle/config")
async def get_cronicle_config(admin: dict = Depends(require_admin)):
    cfg = _get_cronicle_config()
    return {
        "url": cfg["url"],
        "api_key_set": bool(cfg["api_key"]),
        "api_key_masked": mask_secret(cfg["api_key"]),
        "jobs": CRONICLE_JOBS,
    }


@router.post("/cronicle/save")
async def save_cronicle_config(data: dict, admin: dict = Depends(require_admin)):
    """Save Cronicle config without testing connectivity."""
    url = (data.get("url") or "").strip().rstrip("/")
    api_key = (data.get("api_key") or "").strip()
    if not url or not api_key:
        raise HTTPException(status_code=400, detail="URL et clé API requis")

    db = get_db()
    db.execute("DELETE FROM cronicle_config")
    db.execute(
        "INSERT INTO cronicle_config (id, url, api_key, updated_at) VALUES (1, ?, ?, ?)",
        (url, api_key, now_iso()),
    )
    db.commit()
    logger.info(f"Cronicle config saved: {url}")
    return {"ok": True, "url": url}


@router.post("/cronicle/import")
async def import_cronicle_config(data: dict, admin: dict = Depends(require_admin)):
    url = (data.get("url") or "").strip().rstrip("/")
    api_key = (data.get("api_key") or "").strip()
    if not url or not api_key:
        raise HTTPException(status_code=400, detail="URL et API key requis")

    # Test connectivity
    try:
        async with httpx.AsyncClient(timeout=10.0) as hc:
            r = await hc.get(f"{url}/api/app/get_schedule", params={"api_key": api_key, "limit": 1})
            if r.status_code != 200:
                raise HTTPException(status_code=400, detail=f"Cronicle unreachable: HTTP {r.status_code}")
    except httpx.HTTPError as e:
        raise HTTPException(status_code=400, detail=f"Erreur de connexion Cronicle: {e}")

    db = get_db()
    db.execute("DELETE FROM cronicle_config")
    db.execute(
        "INSERT INTO cronicle_config (id, url, api_key, updated_at) VALUES (1, ?, ?, ?)",
        (url, api_key, now_iso()),
    )
    db.commit()
    logger.info(f"Cronicle config imported: {url}")
    return {"ok": True, "url": url}


@router.post("/cronicle/redeploy")
async def redeploy_cronicle_jobs(admin: dict = Depends(require_admin)):
    cfg = _get_cronicle_config()
    if not cfg["url"] or not cfg["api_key"]:
        raise HTTPException(status_code=400, detail="Cronicle non configuré")

    cronicle_url = normalize_cronicle_url(cfg["url"])
    api_key = cfg["api_key"]
    deleted = []
    created = []
    errors = []

    try:
        async with httpx.AsyncClient(timeout=30.0) as hc:
            schedule_r = await hc.get(
                f"{cronicle_url}/api/app/get_schedule",
                params={"api_key": api_key, "offset": 0, "limit": 500},
            )
            schedule_r.raise_for_status()
            rows = schedule_r.json().get("rows", [])
            for row in rows:
                title = row.get("title") or ""
                event_id = row.get("id")
                if not event_id or not title.startswith(CRONICLE_TITLE_PREFIX):
                    continue
                del_r = await hc.post(
                    f"{cronicle_url}/api/app/delete_event",
                    params={"api_key": api_key},
                    json={"id": event_id},
                )
                if 200 <= del_r.status_code < 300:
                    deleted.append({"id": event_id, "title": title})
                else:
                    errors.append({"action": "delete", "title": title, "status": del_r.status_code})

            for job in CRONICLE_JOBS:
                payload = cronicle_payload(job)
                create_r = await hc.post(
                    f"{cronicle_url}/api/app/create_event",
                    params={"api_key": api_key},
                    json=payload,
                )
                if 200 <= create_r.status_code < 300:
                    data = create_r.json() if create_r.content else {}
                    created.append({"title": payload["title"], "id": data.get("id")})
                else:
                    errors.append({"action": "create", "title": payload["title"], "status": create_r.status_code})
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Erreur Cronicle: {e}")
    except Exception as e:
        logger.exception("Cronicle redeploy failed")
        raise HTTPException(status_code=500, detail=f"Erreur: {e}")

    db = get_db()
    db.execute(
        "INSERT INTO cleanup_history (action, status, details, created_at) VALUES (?, ?, ?, ?)",
        ("cronicle_redeploy", "ok" if not errors else "partial",
         f"deleted={len(deleted)} created={len(created)} errors={len(errors)}", now_iso()),
    )
    db.commit()
    return {"deleted": deleted, "created": created, "errors": errors}


@router.get("/cleanup/history")
async def cleanup_history(admin: dict = Depends(require_admin), limit: int = 50):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM cleanup_history ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]
