import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager

from app.database import get_db, init_db
from app.routers import auth, admin, disks


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Disk Monitor", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(disks.router)


def _render(template_name: str, **ctx) -> str:
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")))
    template = env.get_template(template_name)
    return template.render(**ctx)


@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(_render("index.html", title="Dashboard", section="dashboard"))


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(_render("login.html", title="Connexion", section="login"))


@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    return HTMLResponse(_render("admin.html", title="Nettoyage", section="admin"))


@app.get("/admin/settings", response_class=HTMLResponse)
async def settings_page():
    return HTMLResponse(_render("settings.html", title="Paramètres", section="settings"))


@app.get("/health")
async def health():
    return {"status": "ok", "service": "disk-monitor"}
