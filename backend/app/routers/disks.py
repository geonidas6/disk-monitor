"""Host disk inventory and deliberately scoped cleanup actions."""

import os
import shutil
import subprocess
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app.database import get_db
from app.helpers import logger, now_iso, require_admin, verify_internal_token
from app.models import CleanupAction

router = APIRouter(prefix="/disks", tags=["disks"])

# The compose file bind-mounts the VPS root here.  Never use a host path
# directly: without this prefix a cleanup would only affect this container.
HOST_ROOT = os.environ.get("HOST_ROOT", "/host").rstrip("/") or "/host"
TEMP_MAX_AGE_SECONDS = 7 * 24 * 60 * 60

CLEANUP_CATALOG = {
    "docker_prune": {
        "title": "Docker inutilisé (sans volumes)",
        "risk": "safe",
        "description": "Conteneurs arrêtés, images non référencées et cache de build inutilisé. Les volumes sont conservés.",
    },
    "docker_builder": {
        "title": "Cache de construction Docker",
        "risk": "safe",
        "description": "Caches BuildKit non utilisés. Une future construction pourra être plus lente.",
    },
    "docker_images": {
        "title": "Images Docker inutilisées",
        "risk": "safe",
        "description": "Images qui ne servent à aucun conteneur. Elles seront retéléchargées ou reconstruites au besoin.",
    },
    "docker_containers": {
        "title": "Conteneurs Docker arrêtés",
        "risk": "safe",
        "description": "Ne touche pas aux conteneurs en cours d'exécution.",
    },
    "docker_volumes": {
        "title": "Volumes Docker orphelins",
        "risk": "danger",
        "description": "Peut supprimer des données d'applications arrêtées. À utiliser seulement après vérification.",
    },
    "logs": {
        "title": "Journal système ancien",
        "risk": "caution",
        "description": "Conserve les 200 Mo les plus récents des journaux persistants.",
    },
    "tmp": {
        "title": "Fichiers temporaires anciens",
        "risk": "safe",
        "description": "Supprime uniquement les éléments de /tmp et /var/tmp âgés de plus de 7 jours.",
    },
    "pnpm": {
        "title": "Cache pnpm",
        "risk": "safe",
        "description": "Supprime le store de paquets pnpm ; les dépendances seront téléchargées à nouveau si besoin.",
    },
    "npm": {
        "title": "Cache npm",
        "risk": "safe",
        "description": "Supprime uniquement le cache npm, jamais les projets ni node_modules.",
    },
    "vscode_server": {
        "title": "Versions et extensions VS Code Server",
        "risk": "caution",
        "description": "Supprime ~/.vscode-server. VS Code devra réinstaller son serveur et ses extensions.",
    },
    "nvm": {
        "title": "Versions Node gérées par nvm",
        "risk": "danger",
        "description": "Supprime ~/.nvm et toutes ses versions Node. Vérifiez les projets qui l'utilisent avant de lancer cette action.",
    },
}


def host_path(path: str) -> str:
    """Map an absolute VPS path to its path inside the monitor container."""
    if not path.startswith("/"):
        raise ValueError("A host path must be absolute")
    return os.path.join(HOST_ROOT, path.lstrip("/"))


def run_cmd(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "Délai dépassé"
    except OSError as exc:
        return 1, "", str(exc)


def _parse_size(size_str: str) -> int:
    size_str = (size_str or "").strip().upper().split("(", 1)[0].strip()
    multipliers = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    for unit, multiplier in sorted(multipliers.items(), key=lambda item: -len(item[0])):
        if size_str.endswith(unit):
            try:
                return int(float(size_str[: -len(unit)].strip()) * multiplier)
            except ValueError:
                return 0
    try:
        return int(float(size_str))
    except ValueError:
        return 0


def format_bytes(value: int) -> str:
    if not value:
        return "0 B"
    amount = float(value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if amount < 1024:
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} PB"


def _directory_size(path: str, older_than: float | None = None) -> int:
    """Size without following links; an inaccessible entry does not abort a scan."""
    try:
        if not os.path.lexists(path):
            return 0
        if not os.path.isdir(path) or os.path.islink(path):
            stat = os.lstat(path)
            return stat.st_size if older_than is None or stat.st_mtime < older_than else 0
        total = 0
        for root, dirs, files in os.walk(path, followlinks=False):
            for name in files:
                candidate = os.path.join(root, name)
                try:
                    stat = os.lstat(candidate)
                    if older_than is None or stat.st_mtime < older_than:
                        total += stat.st_size
                except OSError:
                    continue
            for name in dirs:
                candidate = os.path.join(root, name)
                try:
                    if os.path.islink(candidate):
                        total += os.lstat(candidate).st_size
                except OSError:
                    continue
        return total
    except OSError:
        return 0


def _temp_size() -> int:
    cutoff = time.time() - TEMP_MAX_AGE_SECONDS
    return _directory_size(host_path("/tmp"), cutoff) + _directory_size(host_path("/var/tmp"), cutoff)


def _docker_reclaimable() -> dict[str, int]:
    values = {"Images": 0, "Containers": 0, "Local Volumes": 0, "Build Cache": 0}
    rc, output, _ = run_cmd(["docker", "system", "df", "--format", "{{.Type}}\t{{.Reclaimable}}"])
    if rc == 0:
        for line in output.splitlines():
            kind, _, size = line.partition("\t")
            if kind in values:
                values[kind] = _parse_size(size)
    return values


def get_cleanup_estimates() -> dict[str, int]:
    docker = _docker_reclaimable()
    journal = _directory_size(host_path("/var/log/journal"))
    return {
        "docker_prune": docker["Images"] + docker["Containers"] + docker["Build Cache"],
        "docker_images": docker["Images"],
        "docker_containers": docker["Containers"],
        "docker_volumes": docker["Local Volumes"],
        "docker_builder": docker["Build Cache"],
        "logs": max(0, journal - 200 * 1024 * 1024),
        "tmp": _temp_size(),
        "pnpm": _directory_size(host_path("/root/.local/share/pnpm/store")),
        "npm": _directory_size(host_path("/root/.npm/_cacache")),
        "vscode_server": _directory_size(host_path("/root/.vscode-server")),
        "nvm": _directory_size(host_path("/root/.nvm")),
    }


def get_disk_stats() -> dict[str, Any]:
    rc, output, error = run_cmd(["df", "-B1", HOST_ROOT])
    total = used = free = 0
    if rc == 0:
        lines = [line for line in output.splitlines() if not line.startswith("Filesystem")]
        if lines:
            fields = lines[-1].split()
            if len(fields) >= 4:
                total, used, free = (int(fields[1]), int(fields[2]), int(fields[3]))

    image_count = volume_count = container_count = docker_total = reclaimable = 0
    rc_docker, output, _ = run_cmd(
        ["docker", "system", "df", "--format", "{{.Type}}\t{{.Size}}\t{{.Reclaimable}}\t{{.TotalCount}}"]
    )
    if rc_docker == 0:
        for line in output.splitlines():
            fields = line.split("\t")
            if len(fields) < 3:
                continue
            kind, size, reclaim = fields[:3]
            docker_total += _parse_size(size)
            reclaimable += _parse_size(reclaim)
            count = int(fields[3]) if len(fields) >= 4 and fields[3].isdigit() else 0
            if kind == "Images":
                image_count = count
            elif kind == "Local Volumes":
                volume_count = count
    rc_containers, output, _ = run_cmd(["docker", "ps", "-aq"])
    if rc_containers == 0:
        container_count = len([line for line in output.splitlines() if line])

    return {
        "total": total,
        "used": used,
        "free": free,
        "use_percent": round(used * 100 / total, 1) if total else 0,
        "docker_images_count": image_count,
        "docker_containers_count": container_count,
        "docker_volumes_count": volume_count,
        "docker_build_cache": _docker_reclaimable()["Build Cache"],
        "docker_total": docker_total,
        "reclaimable": reclaimable,
        "cleanup_estimates": get_cleanup_estimates(),
        "error": error if rc else None,
    }


def _remove_path(path: str) -> None:
    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)


def _clean_old_temp() -> tuple[int, str, str]:
    """Remove eligible temporary entries and report permission failures.

    A cleanup must never silently claim success when a file could not be
    removed.  This is especially important for /tmp where files are often
    owned by another service.
    """
    cutoff = time.time() - TEMP_MAX_AGE_SECONDS
    removed = 0
    failures: list[str] = []
    for directory in (host_path("/tmp"), host_path("/var/tmp")):
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            failures.append(f"{directory.removeprefix(HOST_ROOT) or '/'}: {exc.strerror or exc}")
            continue
        for entry in entries:
            try:
                if entry.stat(follow_symlinks=False).st_mtime < cutoff:
                    _remove_path(entry.path)
                    removed += 1
            except OSError as exc:
                failures.append(f"{entry.path.removeprefix(HOST_ROOT) or '/'}: {exc.strerror or exc}")
    output = f"{removed} élément(s) temporaire(s) ancien(s) supprimé(s)"
    if failures:
        return 1, output, "; ".join(failures[:5])
    return 0, output, ""


def _cleanup(action: str) -> tuple[int, str, str]:
    commands: dict[str, list[str]] = {
        "docker_prune": ["docker", "system", "prune", "-a", "-f"],
        "docker_images": ["docker", "image", "prune", "-a", "-f"],
        "docker_containers": ["docker", "container", "prune", "-f"],
        "docker_volumes": ["docker", "volume", "prune", "-f"],
        "docker_builder": ["docker", "builder", "prune", "-a", "-f"],
        "logs": ["journalctl", f"--directory={host_path('/var/log/journal')}", "--vacuum-size=200M"],
    }
    if action == "tmp":
        return _clean_old_temp()
    paths = {
        "pnpm": host_path("/root/.local/share/pnpm/store"),
        "npm": host_path("/root/.npm/_cacache"),
        "vscode_server": host_path("/root/.vscode-server"),
        "nvm": host_path("/root/.nvm"),
    }
    if action in paths:
        path = paths[action]
        if not os.path.lexists(path):
            return 0, "Aucun élément à supprimer", ""
        try:
            _remove_path(path)
        except OSError as exc:
            return 1, "", f"Suppression impossible de {path.removeprefix(HOST_ROOT) or '/'} : {exc.strerror or exc}"
        # Verify the actual host mount, rather than merely trusting rmtree.
        if os.path.lexists(path):
            return 1, "", f"La suppression de {path.removeprefix(HOST_ROOT) or '/'} n'a pas été vérifiée"
        return 0, f"Supprimé : {path.removeprefix(HOST_ROOT) or '/'}", ""
    if action not in commands:
        raise HTTPException(status_code=400, detail=f"Action inconnue: {action}")
    if action == "logs" and not os.path.isdir(host_path("/var/log/journal")):
        return 0, "Aucun journal persistant à nettoyer", ""
    return run_cmd(commands[action], timeout=120)


def _execute_and_record(action: str) -> dict[str, Any]:
    if action not in CLEANUP_CATALOG:
        raise HTTPException(status_code=400, detail=f"Action inconnue: {action}")
    before = get_disk_stats()["free"]
    try:
        rc, output, error = _cleanup(action)
    except Exception as exc:
        # Persist unexpected filesystem failures too, so the UI never turns a
        # failed click into an unexplained apparent success.
        logger.exception("Cleanup %s crashed", action)
        rc, output, error = 1, "", str(exc)
    after = get_disk_stats()["free"]
    freed = max(0, after - before)
    status = "ok" if rc == 0 else "error"
    details = f"{output or ('Échec de la suppression' if rc else 'Aucun élément à supprimer')} | libéré={format_bytes(freed)}"
    if error:
        details += f" | erreur={error}"
    db = get_db()
    db.execute(
        "INSERT INTO cleanup_history (action, status, space_freed_bytes, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (action, status, freed, details[:2000], now_iso()),
    )
    db.commit()
    logger.info("Cleanup %s: %s - %s", action, status, details)
    return {"ok": rc == 0, "action": action, "status": status, "freed": freed,
            "freed_str": format_bytes(freed), "details": details, "output": output}


def _top_children(path: str, limit: int = 8) -> list[dict[str, Any]]:
    try:
        entries = list(os.scandir(path))
    except OSError:
        return []
    findings = []
    for entry in entries:
        size = _directory_size(entry.path)
        if size:
            findings.append({"path": entry.path.removeprefix(HOST_ROOT) or "/", "bytes": size})
    return sorted(findings, key=lambda item: item["bytes"], reverse=True)[:limit]


def _du_size(path: str) -> int:
    """Use du for very large overlay trees; Python walking them blocks the UI."""
    rc, output, _ = run_cmd(["du", "-sk", path], timeout=20)
    if rc != 0 or not output:
        return 0
    try:
        return int(output.split()[0]) * 1024
    except (IndexError, ValueError):
        return 0


@router.get("/analysis")
async def disk_analysis(admin: dict = Depends(require_admin)):
    """Heavy paths on the VPS, with an explicit cleanup safety classification."""
    estimates = get_cleanup_estimates()
    actions = [{"action": action, **metadata, "bytes": estimates.get(action, 0),
                "bytes_str": format_bytes(estimates.get(action, 0))}
               for action, metadata in CLEANUP_CATALOG.items()]
    active_snapshots = _du_size(host_path("/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots"))
    findings = []
    for root in ("/root", "/opt"):
        findings.extend(_top_children(host_path(root)))
    return {
        "actions": actions,
        "findings": sorted(findings, key=lambda item: item["bytes"], reverse=True)[:16],
        "protected": {"path": "/var/lib/containerd/.../snapshots", "bytes": active_snapshots,
                      "bytes_str": format_bytes(active_snapshots), "risk": "danger",
                      "description": "Couches de conteneurs et d'images actives : ne jamais supprimer ces fichiers directement. Utilisez les actions Docker ci-dessus."},
    }


@router.get("/stats")
async def disk_stats(admin: dict = Depends(require_admin)):
    stats = get_disk_stats()
    stats.update({"total_str": format_bytes(stats["total"]), "used_str": format_bytes(stats["used"]),
                  "free_str": format_bytes(stats["free"]), "reclaimable_str": format_bytes(stats["reclaimable"])})
    db = get_db()
    db.execute(
        """INSERT INTO disk_snapshots (total_bytes, used_bytes, free_bytes, use_percent,
           docker_images_count, docker_containers_count, docker_volumes_count, docker_build_cache_bytes, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (stats["total"], stats["used"], stats["free"], stats["use_percent"], stats["docker_images_count"],
         stats["docker_containers_count"], stats["docker_volumes_count"], stats["docker_build_cache"], now_iso()),
    )
    db.commit()
    return stats


@router.get("/history")
async def cleanup_history(admin: dict = Depends(require_admin), limit: int = 50):
    """Cleanup activity displayed on both the dashboard and admin page."""
    limit = max(1, min(limit, 100))
    db = get_db()
    rows = db.execute(
        "SELECT * FROM cleanup_history ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(row) for row in rows]


@router.post("/cleanup/execute")
async def execute_cleanup(action: CleanupAction, admin: dict = Depends(require_admin)):
    return _execute_and_record(action.action)


@router.post("/cleanup/execute/cron")
async def execute_cleanup_cron(action: CleanupAction, request: Request):
    if not verify_internal_token(request.headers.get("X-Internal-Token", "")):
        raise HTTPException(status_code=401, detail="Token invalide")
    return _execute_and_record(action.action)
