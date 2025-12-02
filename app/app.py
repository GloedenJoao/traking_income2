"""
Aplicação web construída com FastAPI para acompanhar demonstrativos de
pagamento. Esta implementação utiliza os mesmos conceitos da versão
original em Flask, mas utiliza FastAPI e Starlette para compatibilidade
com o ambiente atual, onde o Flask não está disponível. Futuras
alterações devem seguir as orientações em ``AGENTS.MD`` e atualizar
este arquivo conforme necessário.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from typing import Dict, List, Tuple, Optional

from fastapi import FastAPI, Request, Query
from fastapi.responses import RedirectResponse, HTMLResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from itsdangerous import BadSignature, URLSafeSerializer

import plotly.graph_objs as go
import plotly
import json

from .parse_utils import parse_pdf

# Diretórios base
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(BASE_DIR, 'database.db')

SECRET_KEY = os.environ.get('APP_SECRET_KEY', 'change-me-secret-key')
SESSION_COOKIE_NAME = 'session_token'
SESSION_MAX_AGE = 60 * 60 * 8  # 8 hours

serializer = URLSafeSerializer(SECRET_KEY, salt='session-token')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Extensões permitidas
ALLOWED_EXTENSIONS = {'pdf'}

app = FastAPI()

# Configuração de templates Jinja2
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, 'templates'))


def format_currency_brl(value):
    """Formata valores monetários com prefixo R$, separador de milhar e duas casas.

    Valores nulos retornam um marcador legível para evitar exibições vazias no template.
    """

    if value is None:
        return "N/D"
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return "N/D"
    formatted = f"R$ {amount:,.2f}"
    return formatted.replace(",", "X").replace(".", ",").replace("X", ".")


templates.env.filters["currency_br"] = format_currency_brl


def calculate_percentage(part: Optional[float], total: Optional[float]) -> Optional[float]:
    """Retorna o percentual de ``part`` sobre ``total`` ou ``None`` quando não calculável."""

    if total in (None, 0):
        return None
    if part is None:
        return None
    try:
        part_value = float(part)
        total_value = float(total)
    except (TypeError, ValueError):
        return None
    if total_value == 0:
        return None
    return (part_value / total_value) * 100


def calculate_variation(current: Optional[float], previous: Optional[float]) -> Optional[float]:
    """Calcula a variação percentual entre dois valores, retornando ``None`` quando não calculável."""

    if previous in (None, 0) or current is None:
        return None
    try:
        current_value = float(current)
        previous_value = float(previous)
    except (TypeError, ValueError):
        return None
    if previous_value == 0:
        return None
    return ((current_value - previous_value) / previous_value) * 100

# Monta diretório de uploads como estático para servir PDFs
app.mount("/uploads", StaticFiles(directory=UPLOAD_FOLDER), name="uploads")


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def hash_password(password: str) -> str:
    """Gera hash seguro usando PBKDF2 e um salt aleatório."""

    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
    return f"{salt.hex()}:{hashed.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, hash_hex = stored_hash.split(':', 1)
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    candidate = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
    return hmac.compare_digest(candidate, expected)


def create_session_token(payload: Dict[str, str]) -> str:
    return serializer.dumps(payload)


def decode_session_token(token: str) -> Optional[Dict[str, str]]:
    try:
        return serializer.loads(token)
    except BadSignature:
        return None


def set_session_cookie(response: Response, payload: Dict[str, str]) -> None:
    token = create_session_token(payload)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite='lax',
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(cur: sqlite3.Cursor, table: str, column: str) -> bool:
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cur.fetchall())


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS item_view (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            mes_key TEXT,
            mes_ano TEXT,
            descricao TEXT,
            quantidade TEXT,
            proventos REAL,
            descontos REAL,
            user_id INTEGER REFERENCES users(id),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS monthly_totals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            mes_key TEXT,
            mes_ano TEXT,
            total_proventos REAL,
            total_descontos REAL,
            liquido REAL,
            user_id INTEGER REFERENCES users(id),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        '''
    )
    for table in ('item_view', 'monthly_totals'):
        if not column_exists(cur, table, 'user_id'):
            cur.execute(f'ALTER TABLE {table} ADD COLUMN user_id INTEGER REFERENCES users(id)')
        if not column_exists(cur, table, 'created_at'):
            cur.execute(f'ALTER TABLE {table} ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP')
    conn.commit()
    ensure_default_admin(cur)
    conn.commit()
    conn.close()


def ensure_default_admin(cur: sqlite3.Cursor) -> None:
    cur.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    existing = cur.fetchone()
    if existing:
        return
    default_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
    password_hash = hash_password(default_password)
    cur.execute(
        'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
        ('admin', password_hash, 'admin'),
    )


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cur.fetchone()
    conn.close()
    return user


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cur.fetchone()
    conn.close()
    return user


def validate_credentials(username: str, password: str) -> Optional[sqlite3.Row]:
    user = get_user_by_username(username)
    if not user:
        return None
    if verify_password(password, user['password_hash']):
        return user
    return None


def get_current_user(request: Request) -> Optional[sqlite3.Row]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    data = decode_session_token(token)
    if not data:
        return None
    user_id = data.get('id')
    if user_id is None:
        return None
    user = get_user_by_id(int(user_id))
    return user


def resolve_user_filter(current_user: sqlite3.Row, target_user_id: Optional[int]) -> Optional[int]:
    if current_user['role'] == 'admin':
        return target_user_id
    return current_user['id']


def insert_statement(file_name: str, parsed: dict, user_id: int) -> None:
    mes_key = parsed.get('mes_key')
    mes_ano = parsed.get('mes_ano')
    items = parsed.get('items', [])
    totals = parsed.get('totals', {})
    conn = get_db_connection()
    cur = conn.cursor()
    for item in items:
        cur.execute(
            '''INSERT INTO item_view (file_name, mes_key, mes_ano, descricao, quantidade, proventos, descontos, user_id)
               VALUES (?,?,?,?,?,?,?,?)''',
            (
                file_name,
                mes_key,
                mes_ano,
                item['descricao'],
                item.get('quantidade'),
                item.get('proventos'),
                item.get('descontos'),
                user_id,
            )
        )
    cur.execute(
        '''INSERT INTO monthly_totals (file_name, mes_key, mes_ano, total_proventos, total_descontos, liquido, user_id)
           VALUES (?,?,?,?,?,?,?)''',
        (
            file_name,
            mes_key,
            mes_ano,
            totals.get('total_proventos'),
            totals.get('total_descontos'),
            totals.get('liquido'),
            user_id,
        )
    )
    conn.commit()
    conn.close()


def remove_statement(file_name: str, current_user: sqlite3.Row) -> bool:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT DISTINCT user_id FROM monthly_totals WHERE file_name = ?', (file_name,))
    owners = {row['user_id'] for row in cur.fetchall()}
    if owners and None not in owners and current_user['role'] != 'admin' and current_user['id'] not in owners:
        conn.close()
        return False
    cur.execute('DELETE FROM item_view WHERE file_name = ?', (file_name,))
    cur.execute('DELETE FROM monthly_totals WHERE file_name = ?', (file_name,))
    conn.commit()
    conn.close()
    file_path = os.path.join(UPLOAD_FOLDER, file_name)
    if os.path.exists(file_path):
        os.remove(file_path)
    return True


def user_can_access_file(file_name: str, current_user: sqlite3.Row) -> bool:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT DISTINCT user_id FROM monthly_totals WHERE file_name = ?', (file_name,))
    owners = {row['user_id'] for row in cur.fetchall()}
    conn.close()
    if not owners:
        return current_user['role'] == 'admin'
    if None in owners:
        return current_user['role'] == 'admin'
    return current_user['role'] == 'admin' or current_user['id'] in owners


def get_uploaded_files(current_user: sqlite3.Row, target_user_id: Optional[int] = None) -> List[str]:
    user_filter = resolve_user_filter(current_user, target_user_id)
    conn = get_db_connection()
    cur = conn.cursor()
    query = 'SELECT DISTINCT file_name FROM monthly_totals'
    params: List[int] = []
    if user_filter is not None:
        query += ' WHERE user_id = ?'
        params.append(user_filter)
    query += ' ORDER BY file_name'
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    file_names = [row['file_name'] for row in rows if row['file_name']]
    # Garante que somente arquivos existentes sejam listados
    return [name for name in file_names if name.lower().endswith('.pdf') and os.path.exists(os.path.join(UPLOAD_FOLDER, name))]


def get_files_by_month(mes_key: Optional[str], current_user: sqlite3.Row, target_user_id: Optional[int] = None) -> List[str]:
    """Retorna nomes de arquivos já cadastrados para o mês informado."""

    if not mes_key:
        return []
    user_filter = resolve_user_filter(current_user, target_user_id)
    conn = get_db_connection()
    cur = conn.cursor()
    query = 'SELECT DISTINCT file_name FROM monthly_totals WHERE mes_key = ?'
    params: List[Optional[str]] = [mes_key]
    if user_filter is not None:
        query += ' AND user_id = ?'
        params.append(user_filter)
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return [row['file_name'] for row in rows]


def get_months_available(current_user: sqlite3.Row, target_user_id: Optional[int] = None) -> List[Tuple[str, str]]:
    conn = get_db_connection()
    cur = conn.cursor()
    user_filter = resolve_user_filter(current_user, target_user_id)
    query = 'SELECT DISTINCT mes_key, mes_ano FROM item_view WHERE mes_key IS NOT NULL'
    params: List[int] = []
    if user_filter is not None:
        query += ' AND user_id = ?'
        params.append(user_filter)
    query += ' ORDER BY mes_key'
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return [(row['mes_key'], row['mes_ano']) for row in rows]


def get_items_by_month(mes_key: str, current_user: sqlite3.Row, target_user_id: Optional[int] = None):
    conn = get_db_connection()
    cur = conn.cursor()
    user_filter = resolve_user_filter(current_user, target_user_id)
    query = '''SELECT descricao, quantidade, proventos, descontos, file_name
               FROM item_view WHERE mes_key = ?'''
    params: List[Optional[int]] = [mes_key]
    if user_filter is not None:
        query += ' AND user_id = ?'
        params.append(user_filter)
    query += ' ORDER BY descricao'
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_totals_by_month(mes_key: str, current_user: sqlite3.Row, target_user_id: Optional[int] = None):
    conn = get_db_connection()
    cur = conn.cursor()
    user_filter = resolve_user_filter(current_user, target_user_id)
    query = '''SELECT SUM(total_proventos) AS total_proventos,
                  SUM(total_descontos) AS total_descontos,
                  SUM(liquido) AS liquido
           FROM monthly_totals WHERE mes_key = ?'''
    params: List[Optional[int]] = [mes_key]
    if user_filter is not None:
        query += ' AND user_id = ?'
        params.append(user_filter)
    cur.execute(query, params)
    row = cur.fetchone()
    conn.close()
    return row



def get_aggregated_series(
    start_key: Optional[str] = None,
    end_key: Optional[str] = None,
    current_user: Optional[sqlite3.Row] = None,
    target_user_id: Optional[int] = None,
):
    conn = get_db_connection()
    cur = conn.cursor()

    conditions = ["mes_key IS NOT NULL"]
    params: List[Optional[str]] = []
    if start_key:
        conditions.append("mes_key >= ?")
        params.append(start_key)
    if end_key:
        conditions.append("mes_key <= ?")
        params.append(end_key)
    if current_user:
        user_filter = resolve_user_filter(current_user, target_user_id)
        if user_filter is not None:
            conditions.append("user_id = ?")
            params.append(user_filter)

    where_clause = " AND ".join(conditions)
    query = f'''
        SELECT mes_key, mes_ano,
               SUM(total_proventos) AS total_proventos,
               SUM(total_descontos) AS total_descontos,
               SUM(liquido) AS liquido
        FROM monthly_totals
        WHERE {where_clause}
        GROUP BY mes_key, mes_ano
        ORDER BY mes_key
    '''

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_monthly_totals_by_month(
    mes_key: str, current_user: sqlite3.Row, target_user_id: Optional[int] = None
):
    conn = get_db_connection()
    cur = conn.cursor()
    user_filter = resolve_user_filter(current_user, target_user_id)
    query = '''SELECT file_name, total_proventos, total_descontos, liquido
           FROM monthly_totals
           WHERE mes_key = ?'''
    params: List[Optional[int]] = [mes_key]
    if user_filter is not None:
        query += ' AND user_id = ?'
        params.append(user_filter)
    query += ' ORDER BY file_name'
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def list_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, username, role FROM users ORDER BY username')
    rows = cur.fetchall()
    conn.close()
    return rows


@app.on_event("startup")
def startup_event():
    # Inicializa o banco ao iniciar a aplicação
    init_db()


@app.get("/login", response_class=HTMLResponse)
async def login(
    request: Request, msg: Optional[str] = None, next_url: Optional[str] = Query(default=None, alias='next')
):  # type: ignore[override]
    return templates.TemplateResponse(
        'login.html',
        {"request": request, "msg": msg, "next": next_url, "current_user": get_current_user(request)},
    )


@app.post("/login")
async def login_post(request: Request):
    form = await request.form()
    username = str(form.get('username', '')).strip()
    password = str(form.get('password', ''))
    next_url = str(form.get('next') or '')
    errors: List[str] = []
    if not username or len(username) > 20:
        errors.append('Usuário deve ter entre 1 e 20 caracteres.')
    if len(password) <= 1:
        errors.append('Senha deve ter pelo menos 2 caracteres.')
    user = validate_credentials(username, password) if not errors else None
    if not errors and not user:
        errors.append('Credenciais inválidas.')
    if errors:
        return templates.TemplateResponse(
            'login.html',
            {"request": request, "msg": ' '.join(errors), "next": next_url, "current_user": None},
        )
    response = RedirectResponse(next_url or app.url_path_for('index'), status_code=303)
    set_session_cookie(response, {'id': user['id'], 'username': user['username'], 'role': user['role']})
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse(app.url_path_for('login'), status_code=303)
    clear_session_cookie(response)
    return response


@app.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    msg: Optional[str] = None,
    confirm: Optional[int] = None,
    user_id: Optional[int] = None,
):
    current_user = get_current_user(request)
    if not current_user:
        url = app.url_path_for('login') + '?msg=' + 'Faça login para continuar.'
        return RedirectResponse(url, status_code=303)
    target_user_id = None
    if current_user['role'] == 'admin' and user_id:
        try:
            target_user_id = int(user_id)
        except (TypeError, ValueError):
            target_user_id = None
    files = get_uploaded_files(current_user, target_user_id)
    users = list_users() if current_user['role'] == 'admin' else []
    return templates.TemplateResponse(
        'index.html',
        {
            "request": request,
            "files": files,
            "msg": msg,
            "confirm": confirm,
            "current_user": current_user,
            "users": users,
            "selected_user_id": target_user_id,
        },
    )


@app.post("/upload")
async def upload_file(request: Request):
    """
    Endpoint para upload de PDF. A ausência do pacote python-multipart
    impossibilita o uso do parâmetro File/UploadFile do FastAPI. Por
    isso, este handler lê o corpo da requisição diretamente e faz o
    parsing manual do conteúdo multipart/form-data.
    """
    current_user = get_current_user(request)
    if not current_user:
        url = app.url_path_for('login') + '?msg=' + 'Faça login para continuar.'
        return RedirectResponse(url, status_code=303)
    # Verifica content-type e extrai boundary
    content_type = request.headers.get('content-type', '')
    if 'multipart/form-data' not in content_type:
        url = app.url_path_for('index') + '?msg=' + 'Tipo de conteúdo inválido.'
        return RedirectResponse(url, status_code=303)
    boundary = None
    for part in content_type.split(';'):
        part = part.strip()
        if part.startswith('boundary='):
            boundary = part.split('=', 1)[1]
            break
    if not boundary:
        url = app.url_path_for('index') + '?msg=' + 'Boundary não encontrado.'
        return RedirectResponse(url, status_code=303)
    boundary_bytes = ('--' + boundary).encode()
    body = await request.body()
    # Separa partes pelo boundary
    sections = body.split(boundary_bytes)
    files_data: List[Tuple[str, bytes]] = []
    confirm_flag = False
    for section in sections:
        if not section or section == b'--\r\n':
            continue
        # Remove prefix/suffix newlines
        part = section.strip(b'\r\n')
        # Parte final contém apenas '--'
        if part == b'--':
            continue
        # Se a parte contém Content-Disposition com filename
        header_end = part.find(b'\r\n\r\n')
        if header_end == -1:
            continue
        header_bytes = part[:header_end].decode(errors='ignore')
        content = part[header_end + 4:]
        disposition = header_bytes.split('\r\n')[0]
        field_name = None
        filename = None
        for attr in disposition.split(';'):
            attr = attr.strip()
            if attr.startswith('name='):
                field_name = attr.split('=', 1)[1].strip().strip('"')
            if attr.startswith('filename='):
                filename = attr.split('=', 1)[1].strip().strip('"')
        if filename:
            files_data.append((filename, content.rstrip(b'\r\n')))
        elif field_name == 'confirm':
            value = content.rstrip(b'\r\n').decode(errors='ignore')
            confirm_flag = value.strip() == '1'
    if not files_data:
        url = app.url_path_for('index') + '?msg=' + 'Nenhum arquivo encontrado no upload.'
        return RedirectResponse(url, status_code=303)

    messages: List[str] = []
    reconfirm_needed = False

    for file_name, file_content in files_data:
        if not allowed_file(file_name):
            messages.append(f'Extensão de arquivo não permitida para {file_name}.')
            continue

        secure_name = file_name.replace('/', '_')
        save_path = os.path.join(UPLOAD_FOLDER, secure_name)
        temp_path = save_path + '.upload'
        with open(temp_path, 'wb') as f:
            f.write(file_content)
        try:
            parsed = parse_pdf(temp_path)
        except Exception as e:
            os.remove(temp_path)
            messages.append(f'Falha ao processar {secure_name}: {e}')
            continue

        mes_key = parsed.get('mes_key')
        existing_month_files = get_files_by_month(mes_key, current_user, current_user['id'])
        duplicate_name = os.path.exists(save_path)
        duplicate_month = bool(existing_month_files)

        if (duplicate_name or duplicate_month) and not confirm_flag:
            os.remove(temp_path)
            details = []
            if duplicate_name:
                details.append(f'O arquivo {secure_name} já existe.')
            if duplicate_month:
                details.append(
                    f'O mês {parsed.get("mes_ano", mes_key)} já está cadastrado (arquivos: {", ".join(existing_month_files)}).'
                )
            messages.append(' '.join(details) + ' Confirme a substituição marcando a opção no formulário e envie novamente.')
            reconfirm_needed = True
            continue

        if duplicate_name:
            remove_statement(secure_name, current_user)
        if duplicate_month:
            for fname in existing_month_files:
                if fname != secure_name:
                    remove_statement(fname, current_user)

        os.replace(temp_path, save_path)
        insert_statement(secure_name, parsed, current_user['id'])
        messages.append(f'Arquivo {secure_name} carregado com sucesso.')

    if not messages:
        messages.append('Nenhum arquivo foi processado.')

    msg_param = '; '.join(messages)
    url = app.url_path_for('index') + '?msg=' + msg_param
    if reconfirm_needed:
        url += '&confirm=1'
    return RedirectResponse(url, status_code=303)


@app.post("/delete/{filename:path}")
async def delete_file(request: Request, filename: str):
    current_user = get_current_user(request)
    if not current_user:
        url = app.url_path_for('login') + '?msg=' + 'Faça login para continuar.'
        return RedirectResponse(url, status_code=303)
    removed = remove_statement(filename, current_user)
    msg = f'Arquivo {filename} removido.' if removed else 'Você não tem permissão para remover este arquivo.'
    url = app.url_path_for('index') + '?msg=' + msg
    return RedirectResponse(url, status_code=303)


@app.get("/consulta", response_class=HTMLResponse)
async def consulta_get(request: Request):
    """Renderiza a página de consulta. Aceita mes_key via query string."""
    current_user = get_current_user(request)
    if not current_user:
        url = app.url_path_for('login') + '?msg=' + 'Faça login para continuar.'
        return RedirectResponse(url, status_code=303)
    mes_key = request.query_params.get('mes_key') if request.query_params else None
    selected_user_id: Optional[int] = None
    if current_user['role'] == 'admin':
        try:
            selected_user_id = int(request.query_params.get('user_id')) if request.query_params.get('user_id') else None
        except (TypeError, ValueError):
            selected_user_id = None
    months = get_months_available(current_user, selected_user_id)
    users = list_users() if current_user['role'] == 'admin' else []
    items = []
    totals = None
    descontos_pct = None
    liquido_pct = None
    selected_key = mes_key
    if selected_key:
        items = get_items_by_month(selected_key, current_user, selected_user_id)
        totals = get_totals_by_month(selected_key, current_user, selected_user_id)
        if totals:
            total_proventos = totals['total_proventos']
            descontos_pct = calculate_percentage(totals['total_descontos'], total_proventos)
            liquido_pct = calculate_percentage(totals['liquido'], total_proventos)
    return templates.TemplateResponse(
        'consulta.html',
        {
            "request": request,
            "months": months,
            "items": items,
            "totals": totals,
            "selected_key": selected_key,
            "descontos_pct": descontos_pct,
            "liquido_pct": liquido_pct,
            "current_user": current_user,
            "users": users,
            "selected_user_id": selected_user_id,
        },
    )




@app.get("/dashboard_totais", response_class=HTMLResponse)
async def dashboard_totais(request: Request):
    current_user = get_current_user(request)
    if not current_user:
        url = app.url_path_for('login') + '?msg=' + 'Faça login para continuar.'
        return RedirectResponse(url, status_code=303)
    start_month = request.query_params.get('start') if request.query_params else None
    end_month = request.query_params.get('end') if request.query_params else None
    selected_types = request.query_params.getlist('types') if request.query_params else []
    selected_user_id: Optional[int] = None
    if current_user['role'] == 'admin':
        try:
            selected_user_id = int(request.query_params.get('user_id')) if request.query_params.get('user_id') else None
        except (TypeError, ValueError):
            selected_user_id = None
    users = list_users() if current_user['role'] == 'admin' else []
    months_available = get_months_available(current_user, selected_user_id)

    # Se nenhum tipo for selecionado, consideramos todos como padrão
    if not selected_types:
        selected_types = ['proventos', 'descontos', 'liquido']

    if months_available:
        sorted_months = sorted(months_available, key=lambda m: m[0])
        default_start = sorted_months[0][0][:7]
        default_end = sorted_months[-1][0][:7]
        start_month = start_month or default_start
        end_month = end_month or default_end

    start_key = f"{start_month}-01" if start_month else None
    end_key = f"{end_month}-01" if end_month else None

    # Garante que o intervalo esteja ordenado
    if start_key and end_key and start_key > end_key:
        start_key, end_key = end_key, start_key
        start_month, end_month = end_month, start_month

    series = get_aggregated_series(
        start_key=start_key, end_key=end_key, current_user=current_user, target_user_id=selected_user_id
    )
    last_month = None
    prev_month = None
    variations = {
        "total_proventos": None,
        "total_descontos": None,
        "liquido": None,
    }
    graphs_json = None
    band_table_rows = []
    if series:
        last_row = series[-1]
        last_month = {
            "mes_key": last_row["mes_key"],
            "mes_ano": last_row["mes_ano"],
            "total_proventos": last_row["total_proventos"],
            "total_descontos": last_row["total_descontos"],
            "liquido": last_row["liquido"],
        }
        if len(series) >= 2:
            prev_row = series[-2]
            prev_month = {
                "mes_key": prev_row["mes_key"],
                "mes_ano": prev_row["mes_ano"],
                "total_proventos": prev_row["total_proventos"],
                "total_descontos": prev_row["total_descontos"],
                "liquido": prev_row["liquido"],
            }
            variations = {
                "total_proventos": calculate_variation(last_row["total_proventos"], prev_row["total_proventos"]),
                "total_descontos": calculate_variation(last_row["total_descontos"], prev_row["total_descontos"]),
                "liquido": calculate_variation(last_row["liquido"], prev_row["liquido"]),
            }
        months = []
        prov_series = []
        desc_series = []
        liq_series = []

        prev_prov = None
        prev_desc = None
        prev_liq = None

        for row in series:
            month_label = row['mes_ano']
            total_prov = row['total_proventos']
            total_desc = row['total_descontos']
            total_liq = row['liquido']

            months.append(month_label)
            prov_series.append(total_prov)
            desc_series.append(total_desc)
            liq_series.append(total_liq)

            band_table_rows.append(
                {
                    "mes_ano": month_label,
                    "proventos": total_prov,
                    "descontos": total_desc,
                    "liquido": total_liq,
                    "var_proventos": calculate_variation(total_prov, prev_prov),
                    "var_descontos": calculate_variation(total_desc, prev_desc),
                    "var_liquido": calculate_variation(total_liq, prev_liq),
                }
            )

            prev_prov = total_prov
            prev_desc = total_desc
            prev_liq = total_liq

        traces = []
        series_map = {
            'proventos': ('Proventos', prov_series),
            'descontos': ('Descontos', desc_series),
            'liquido': ('Líquido', liq_series),
        }
        for key, (label, values) in series_map.items():
            if key in selected_types:
                traces.append(go.Scatter(x=months, y=values, mode='lines+markers', name=label))

        layout = go.Layout(
            title='Série histórica de proventos, descontos e líquido',
            xaxis={'title': 'Mês'},
            yaxis={'title': 'Valor (R$)'},
        )
        fig_history = go.Figure(data=traces, layout=layout)

        def build_hover_text(label: str, values: List[float]):
            hover_texts = []
            previous = None
            for month, value in zip(months, values):
                delta_pct = None
                if previous not in (None, 0):
                    delta_pct = ((value - previous) / previous) * 100
                delta_text = '—' if delta_pct is None else f"{delta_pct:+.2f}%".replace('.', ',')
                hover_texts.append(
                    f"{label} em {month}: {format_currency_brl(value)}<br>Variação mensal: {delta_text}"
                )
                previous = value
            return hover_texts

        band_traces = []
        band_series_map = {
            'proventos': ('Proventos', prov_series, 'tozeroy'),
            'descontos': ('Descontos', desc_series, 'tonexty'),
            'liquido': ('Líquido', liq_series, 'tonexty'),
        }
        for key, (label, values, fill_mode) in band_series_map.items():
            if key in selected_types:
                band_traces.append(
                    go.Scatter(
                        x=months,
                        y=values,
                        mode='lines',
                        name=f"Faixa {label}",
                        fill=fill_mode,
                        hovertext=build_hover_text(label, values),
                        hoverinfo='text',
                    )
                )

        band_layout = go.Layout(
            title='Faixas acumuladas por período',
            xaxis={'title': 'Mês'},
            yaxis={'title': 'Valor (R$)'},
        )
        fig_bands = go.Figure(data=band_traces, layout=band_layout)

        graphs = [fig_history, fig_bands]
        graphs_json = json.dumps(graphs, cls=plotly.utils.PlotlyJSONEncoder)
    return templates.TemplateResponse(
        'dashboard.html',
        {
            "request": request,
            "graphs_json": graphs_json,
            "start_month": start_month,
            "end_month": end_month,
            "selected_types": selected_types,
            "last_month": last_month,
            "prev_month": prev_month,
            "variations": variations,
            "band_table_rows": band_table_rows,
            "current_user": current_user,
            "users": users,
            "selected_user_id": selected_user_id,
        },
    )


@app.get("/download/{filename:path}")
async def download_file(request: Request, filename: str):
    current_user = get_current_user(request)
    if not current_user:
        url = app.url_path_for('login') + '?msg=' + 'Faça login para continuar.'
        return RedirectResponse(url, status_code=303)
    if not user_can_access_file(filename, current_user):
        url = app.url_path_for('index') + '?msg=' + 'Você não tem permissão para acessar este arquivo.'
        return RedirectResponse(url, status_code=303)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    return FileResponse(file_path, filename=filename)


if __name__ == '__main__':
    # Execução direta com uvicorn para ambiente de desenvolvimento
    import uvicorn
    init_db()
    uvicorn.run(app, host='0.0.0.0', port=5000)
