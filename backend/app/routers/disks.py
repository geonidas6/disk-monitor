import os
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app.database import get_db
from app.helpers import require_admin, now_iso, logger, verify_internal_token
from app.models import CleanupAction

router = APIRouter(prefix="/disks", tags=["disks"])


def run_cmd(cmd: str, timeout: int = 30) -> tuple:
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "Timeout"
    except Exception as e:
        return 1, "", str(e)


def _parse_size(size_str: str) -> int:
    """Parse docker size string like '9.63GB' to bytes."""
    size_str = size_str.strip().upper()
    multipliers = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
    for unit, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if size_str.endswith(unit):
            try:
                return int(float(size_str[: -len(unit)].strip()) * mult)
            except ValueError:
                return 0
    try:
        return int(float(size_str))
    except ValueError:
        return 0


def format_bytes(b: int) -> str:
    if not b:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def get_disk_stats() -> Dict[str, Any]:
    try:
        rc, out, _ = run_cmd("df -B1 / 2>/dev/null")
        total = used = free = 0
        use_percent = 0.0
        if rc == 0:
            lines = [l for l in out.splitlines() if not l.startswith("Filesystem")]
            if lines:
                parts = lines[0].split()
                if len(parts) >= 3:
                    total = int(parts[1])
                    used = int(parts[2])
                    free = total - used
                    use_percent = round((used / total) * 100, 1) if total > 0 else 0

        docker_images_count = 0
        docker_containers_count = 0
        docker_volumes_count = 0
        docker_total_bytes = 0
        docker_reclaimable_bytes = 0

        rc2, out2, _ = run_cmd("docker system df --format '{{.Type}}\t{{.Size}}\t{{.Reclaimable}}' 2>/dev/null")
        if rc2 == 0:
            for line in out2.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    dtype = parts[0].strip()
                    size_str = parts[1].strip()
                    reclaim_str = parts[2].strip()
                    if dtype == "Images":
                        docker_images_count = _parse_size(size_str)
                    if dtype == "Volumes":
                        docker_volumes_count = _parse_size(size_str)
                    if reclaim_str and reclaim_str != "-":
                        docker_reclaimable_bytes += _parse_size(reclaim_str)

        rc3, out3, _ = run_cmd("docker ps -q 2>/dev/null")
        if rc3 == 0:
            docker_containers_count = len([x for x in out3.strip().split("\n") if x])

        return {
            "total": total,
            "used": used,
            "free": free,
            "use_percent": use_percent,
            "docker_images_count": docker_images_count,
            "docker_containers_count": docker_containers_count,
            "docker_volumes_count": docker_volumes_count,
            "docker_build_cache": 0,
            "docker_total": docker_total_bytes,
            "reclaimable": docker_reclaimable_bytes,
        }
    except Exception as e:
        logger.error(f"Disk stats error: {e}")
        return {"total": 0, "used": 0, "free": 0, "use_percent": 0, "error": str(e)}


@router.get("/stats")
async def disk_stats(admin: dict = Depends(require_admin)):
    stats = get_disk_stats()
    stats["total_str"] = format_bytes(stats["total"])
    stats["used_str"] = format_bytes(stats["used"])
    stats["free_str"] = format_bytes(stats["free"])
    stats["reclaimable_str"] = format_bytes(stats.get("reclaimable", 0))

    db = get_db()
    db.execute(
        """INSERT INTO disk_snapshots (total_bytes, used_bytes, free_bytes, use_percent,
           docker_images_count, docker_containers_count, docker_volumes_count, docker_build_cache_bytes, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            stats["total"], stats["used"], stats["free"], stats["use_percent"],
            stats.get("docker_images_count", 0), stats.get("docker_containers_count", 0),
            stats.get("docker_volumes_count", 0), 0, now_iso(),
        ),
    )
    db.commit()
    return stats


@router.post("/cleanup/execute")
async def execute_cleanup(action: CleanupAction, admin: dict = Depends(require_admin)):
    db = get_db()
    before_bytes = get_disk_stats()["free"]

    try:
        if action.action == "docker_prune":
            rc, out, err = run_cmd("docker system prune -a --volumes -f", timeout=120)
        elif action.action == "docker_images":
            rc, out, err = run_cmd("docker image prune -a -f", timeout=60)
        elif action.action == "docker_containers":
            rc, out, err = run_cmd("docker container prune -f", timeout=60)
        elif action.action == "docker_volumes":
            rc, out, err = run_cmd("docker volume prune -f", timeout=60)
        elif action.action == "docker_builder":
            rc, out, err = run_cmd("docker builder prune -a -f", timeout=60)
        elif action.action == "logs":
            rc, out, err = run_cmd("journalctl --vacuum-size=50M", timeout=30)
        elif action.action == "tmp":
            rc, out, err = run_cmd("rm -rf /tmp/* /var/tmp/*", timeout=30)
        elif action.action == "pnpm":
            rc, out, err = run_cmd("rm -rf /root/.local/share/pnpm/store", timeout=30)
        elif action.action == "npm":
            rc, out, err = run_cmd("npm cache clean --force", timeout=30)
        else:
            raise HTTPException(status_code=400, detail=f"Action inconnue: {action.action}")

        after_bytes = get_disk_stats()["free"]
        freed = max(0, (after_bytes or 0) - (before_bytes or 0))
        details = f"rc={rc} freed={format_bytes(freed)}"
        status_str = "ok" if rc == 0 else "error"

        db.execute(
            "INSERT INTO cleanup_history (action, status, space_freed_bytes, details, created_at) VALUES (?, ?, ?, ?, ?)",
            (action.action, status_str, freed, details, now_iso()),
        )
        db.commit()
        logger.info(f"Cleanup {action.action}: {status_str} - {details}")
        return {"ok": True, "action": action.action, "status": status_str, "details": details}

    except Exception as e:
        db.execute(
            "INSERT INTO cleanup_history (action, status, details, created_at) VALUES (?, ?, ?, ?)",
            (action.action, "error", str(e), now_iso()),
        )
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cleanup/execute/cron")
async def execute_cleanup_cron(action: CleanupAction, request: Request):
    """Endpoint public appelé par Cronicle (token interne requis)."""
    token = request.headers.get("X-Internal-Token", "")
    if not verify_internal_token(token):
        raise HTTPException(status_code=401, detail="Token invalide")
    db = get_db()
    before_bytes = get_disk_stats()["free"]
    try:
        if action.action == "docker_prune":
            rc, out, err = run_cmd("docker system prune -a --volumes -f", timeout=120)
        elif action.action == "docker_images":
            rc, out, err = run_cmd("docker image prune -a -f", timeout=60)
        elif action.action == "docker_containers":
            rc, out, err = run_cmd("docker container prune -f", timeout=60)
        elif action.action == "docker_volumes":
            rc, out, err = run_cmd("docker volume prune -f", timeout=60)
        elif action.action == "docker_builder":
            rc, out, err = run_cmd("docker builder prune -a -f", timeout=60)
        elif action.action == "logs":
            rc, out, err = run_cmd("journalctl --vacuum-size=50M", timeout=30)
        elif action.action == "tmp":
            rc, out, err = run_cmd("rm -rf /tmp/* /var/tmp/*", timeout=30)
        elif action.action == "pnpm":
            rc, out, err = run_cmd("rm -rf /root/.local/share/pnpm/store", timeout=30)
        elif action.action == "npm":
            rc, out, err = run_cmd("npm cache clean --force", timeout=30)
        else:
            raise HTTPException(status_code=400, detail=f"Action inconnue: {action.action}")
        after_bytes = get_disk_stats()["free"]
        freed = max(0, (after_bytes or 0) - (before_bytes or 0))
        details = f"rc={rc} freed={format_bytes(freed)}"
        status_str = "ok" if rc == 0 else "error"
        db.execute(
            "INSERT INTO cleanup_history (action, status, space_freed_bytes, details, created_at) VALUES (?, ?, ?, ?, ?)",
            (action.action, status_str, freed, details, now_iso()),
        )
        db.commit()
        logger.info(f"Cron cleanup {action.action}: {status_str} - {details}")
        return {"ok": True, "action": action.action, "status": status_str, "details": details}
    except Exception as e:
        db.execute(
            "INSERT INTO cleanup_history (action, status, details, created_at) VALUES (?, ?, ?, ?)",
            (action.action, "error", str(e), now_iso()),
        )
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def cleanup_history(admin: dict = Depends(require_admin), limit: int = 50):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM cleanup_history ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


@router.get("/snapshots")
async def disk_snapshots(admin: dict = Depends(require_admin), days: int = 30):
    db = get_db()
    since = (datetime.now(timezone.utc) - __import__("datetime").timedelta(days=days)).isoformat()
    rows = db.execute(
        "SELECT * FROM disk_snapshots WHERE created_at >= ? ORDER BY created_at DESC LIMIT 100",
        (since,),
    ).fetchall()
    result = [dict(r) for r in rows]
    for r in result:
        r["total_str"] = format_bytes(r["total_bytes"])
        r["used_str"] = format_bytes(r["used_bytes"])
        r["free_str"] = format_bytes(r["free_bytes"])
    return result
