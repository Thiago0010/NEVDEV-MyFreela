"""
NEVDEV-MyFreela — Backend FastAPI
Painel completo para freelancers.
Dados em memória (sem DB).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal, Optional

import httpx
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import sqlite3
import os
import hashlib
import hmac
import secrets

app = FastAPI(title="NEVDEV-MyFreela API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
Status = Literal["ideia", "andamento", "concluido"]


class Project(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    client: str
    status: Status = "ideia"
    value: float = 0.0
    deadline: Optional[str] = None
    description: str = ""
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ProjectIn(BaseModel):
    name: str
    client: str
    status: Status = "ideia"
    value: float = 0.0
    deadline: Optional[str] = None
    description: str = ""


class Transaction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: Literal["receita", "despesa"]
    description: str
    amount: float
    category: str = "geral"
    date: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class TransactionIn(BaseModel):
    type: Literal["receita", "despesa"]
    description: str
    amount: float
    category: str = "geral"
    date: Optional[str] = None


class Note(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    content: str = ""
    color: str = "indigo"
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class NoteIn(BaseModel):
    title: str
    content: str = ""
    color: str = "indigo"


class LoginIn(BaseModel):
    email: str
    password: str


class RegisterIn(BaseModel):
    name: str
    email: str
    password: str


# ---------------------------------------------------------------------------
# In-memory "database" com seed de demonstração
# ---------------------------------------------------------------------------
projects: list[Project] = [
    Project(name="Landing Page — Studio Aurora", client="Studio Aurora",
            status="andamento", value=3800, deadline="2026-07-28",
            description="Redesign completo da landing com foco em conversão."),
    Project(name="App Mobile — FitCoach", client="FitCoach",
            status="ideia", value=12500, deadline="2026-09-15",
            description="MVP do app de acompanhamento de treinos."),
    Project(name="Dashboard SaaS — Nimbus", client="Nimbus Tech",
            status="concluido", value=6200, deadline="2026-06-10",
            description="Painel administrativo com métricas em tempo real."),
    Project(name="Identidade Visual — Café Lume", client="Café Lume",
            status="andamento", value=2400, deadline="2026-07-30",
            description="Rebranding completo + guidelines."),
]

transactions: list[Transaction] = [
    Transaction(type="receita", description="Entrada — Studio Aurora", amount=1900, category="projeto"),
    Transaction(type="receita", description="Final — Nimbus Tech", amount=6200, category="projeto"),
    Transaction(type="despesa", description="Figma Pro", amount=75, category="ferramentas"),
    Transaction(type="despesa", description="Hospedagem", amount=120, category="infra"),
    Transaction(type="receita", description="Consultoria — Café Lume", amount=800, category="consultoria"),
]

notes: list[Note] = [
    Note(title="Ideia — newsletter", content="Publicar templates gratuitos semanais.", color="indigo"),
    Note(title="Follow-up FitCoach", content="Enviar proposta revisada até sexta.", color="rose"),
    Note(title="Estudo", content="Terminar curso de motion design.", color="emerald"),
]


def _find(items, item_id):
    return next((i for i in items if i.id == item_id), None)


# ---------------------------------------------------------------------------
# Autenticação (SQLite + hashing de senha)
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

def get_db():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT,
            email TEXT UNIQUE,
            password_hash TEXT,
            salt TEXT,
            created_at TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT,
            created_at TEXT
        )
    ''')
    conn.commit()
    conn.close()


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100_000)
    return dk.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100_000)
    return hmac.compare_digest(dk.hex(), stored_hash)


def find_user_by_email(email: str):
    conn = get_db(); c = conn.cursor()
    c.execute('SELECT id,name,email,password_hash,salt,created_at FROM users WHERE email=?', (email,))
    row = c.fetchone(); conn.close()
    if not row: return None
    return dict(id=row[0], name=row[1], email=row[2], password_hash=row[3], salt=row[4], created_at=row[5])


def create_user(name: str, email: str, password: str):
    if find_user_by_email(email):
        raise HTTPException(400, 'E-mail já cadastrado')
    uid = str(uuid.uuid4())
    pwd_hash, salt = hash_password(password)
    conn = get_db(); c = conn.cursor()
    c.execute('INSERT INTO users (id,name,email,password_hash,salt,created_at) VALUES (?,?,?,?,?,?)',
              (uid, name, email, pwd_hash, salt, datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return uid


def create_token(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    conn = get_db(); c = conn.cursor()
    c.execute('INSERT INTO tokens (token,user_id,created_at) VALUES (?,?,?)', (token, user_id, datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return token


def get_user_by_token(token: str):
    conn = get_db(); c = conn.cursor()
    c.execute('SELECT user_id FROM tokens WHERE token=?', (token,))
    row = c.fetchone()
    if not row:
        conn.close(); return None
    user_id = row[0]
    c.execute('SELECT id,name,email,created_at FROM users WHERE id=?', (user_id,))
    u = c.fetchone(); conn.close()
    if not u: return None
    return dict(id=u[0], name=u[1], email=u[2], created_at=u[3])


init_db()


@app.post('/auth/register')
def register(data: RegisterIn):
    if not data.email or not data.password or not data.name:
        raise HTTPException(400, 'Dados incompletos')
    uid = create_user(data.name.strip(), data.email.strip().lower(), data.password)
    token = create_token(uid)
    return {'token': token, 'user': {'id': uid, 'name': data.name.strip(), 'email': data.email.strip().lower()}}


@app.post('/auth/login')
def login(data: LoginIn):
    u = find_user_by_email((data.email or '').strip().lower())
    if not u or not verify_password(data.password, u['password_hash'], u['salt']):
        raise HTTPException(401, 'Credenciais inválidas')
    token = create_token(u['id'])
    return {'token': token, 'user': {'id': u['id'], 'name': u['name'], 'email': u['email']}}


@app.get('/auth/me')
def me(authorization: str | None = Header(None)):
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(401, 'Não autorizado')
    token = authorization.split(None, 1)[1]
    u = get_user_by_token(token)
    if not u:
        raise HTTPException(401, 'Token inválido')
    return {'user': u}


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------
@app.get("/projects")
def list_projects():
    return projects


@app.post("/projects")
def create_project(data: ProjectIn):
    p = Project(**data.model_dump())
    projects.append(p)
    return p


@app.put("/projects/{pid}")
def update_project(pid: str, data: ProjectIn):
    p = _find(projects, pid)
    if not p:
        raise HTTPException(404, "Projeto não encontrado")
    for k, v in data.model_dump().items():
        setattr(p, k, v)
    return p


@app.patch("/projects/{pid}/status")
def update_status(pid: str, status: Status):
    p = _find(projects, pid)
    if not p:
        raise HTTPException(404, "Projeto não encontrado")
    p.status = status
    return p


@app.delete("/projects/{pid}")
def delete_project(pid: str):
    global projects
    projects = [p for p in projects if p.id != pid]
    return {"ok": True}


# ---------------------------------------------------------------------------
# Finance
# ---------------------------------------------------------------------------
@app.get("/finance")
def list_finance():
    return transactions


@app.post("/finance")
def add_transaction(data: TransactionIn):
    payload = data.model_dump()
    if not payload.get("date"):
        payload["date"] = datetime.utcnow().isoformat()
    t = Transaction(**payload)
    transactions.append(t)
    return t


@app.delete("/finance/{tid}")
def delete_transaction(tid: str):
    global transactions
    transactions = [t for t in transactions if t.id != tid]
    return {"ok": True}


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------
@app.get("/notes")
def list_notes():
    return notes


@app.post("/notes")
def add_note(data: NoteIn):
    n = Note(**data.model_dump())
    notes.append(n)
    return n


@app.delete("/notes/{nid}")
def delete_note(nid: str):
    global notes
    notes = [n for n in notes if n.id != nid]
    return {"ok": True}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.get("/dashboard")
def dashboard():
    receitas = sum(t.amount for t in transactions if t.type == "receita")
    despesas = sum(t.amount for t in transactions if t.type == "despesa")
    ativos = [p for p in projects if p.status == "andamento"]
    concluidos = [p for p in projects if p.status == "concluido"]
    total = len(projects) or 1
    conversao = round(len(concluidos) / total * 100, 1)
    return {
        "faturamento": receitas,
        "despesas": despesas,
        "lucro": receitas - despesas,
        "projetos_ativos": len(ativos),
        "projetos_total": len(projects),
        "concluidos": len(concluidos),
        "taxa_conversao": conversao,
        "pipeline_valor": sum(p.value for p in ativos),
    }


# ---------------------------------------------------------------------------
# Instagram (scrape público simples, com fallback mockado)
# ---------------------------------------------------------------------------
@app.get("/instagram/{username}")
async def instagram(username: str):
    username = username.strip().lstrip("@")
    url = f"https://www.instagram.com/{username}/?__a=1&__d=dis"
    try:
        async with httpx.AsyncClient(timeout=6, headers={"User-Agent": "Mozilla/5.0"}) as c:
            r = await c.get(f"https://www.instagram.com/{username}/")
            if r.status_code == 200 and "og:description" in r.text:
                import re
                m = re.search(r'<meta property="og:description" content="([^"]+)"', r.text)
                if m:
                    desc = m.group(1)
                    return {"username": username, "raw": desc, "source": "og"}
    except Exception:
        pass
    # fallback determinístico
    seed = sum(ord(c) for c in username)
    return {
        "username": username,
        "followers": 1200 + (seed * 37) % 90000,
        "following": 180 + seed % 400,
        "posts": 60 + seed % 500,
        "engagement": round(1 + (seed % 60) / 10, 2),
        "source": "mock",
    }


@app.get("/")
def root():
    return FileResponse("index.html")
