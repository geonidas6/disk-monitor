from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class LoginRequest(BaseModel):
    email: str
    password: str

class CronicleConfig(BaseModel):
    url: str
    api_key: str

class CleanupAction(BaseModel):
    action: str  # docker_prune, docker_images, docker_containers, docker_volumes, docker_builder, logs, tmp, pnpm, npm, journal

class DiskStats(BaseModel):
    total: int
    used: int
    free: int
    use_percent: float
    docker_images: int
    docker_containers: int
    docker_volumes: int
    docker_build_cache: int
    docker_total: int
    reclaimable: int
