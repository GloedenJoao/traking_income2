"""
Aplicação web construída com FastAPI para acompanhar demonstrativos de
pagamento. Esta implementação utiliza os mesmos conceitos da versão
original em Flask, mas utiliza FastAPI e Starlette para compatibilidade
com o ambiente atual, onde o Flask não está disponível. Futuras
alterações devem seguir as orientações em ``AGENTS.MD`` e atualizar
este arquivo conforme necessário.
"""

import hashlib
import os
import sqlite3
from typing import List, Tuple, Optional, Dict, Any

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

import plotly.graph_objs as go
import plotly
import json

from .parse_utils import parse_pdf

# Diretórios base
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(BASE_DIR, 'database.db')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Extensões permitidas
ALLOWED_EXTENSIONS = {'pdf'}
ALLOWED_FILE_TYPES = {'FolMen', 'Outros', 'PagPLR'}

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.environ.get('SESSION_SECRET', 'change-me-secret'))

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

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def ensure_user_upload_dir(user_id: int) -> str:
    """Retorna (e cria se necessário) o diretório de uploads do usuário."""

    user_dir = os.path.join(UPLOAD_FOLDER, f"user_{user_id}")
    os.makedirs(user_dir, exist_ok=True)
    return user_dir


def sanitize_filename(filename: str) -> str:
    """Normaliza o nome do arquivo para evitar path traversal e separadores."""

    safe_name = os.path.basename(filename)
    return safe_name.replace('/', '_').replace('\\', '_')


def get_user_file_path(filename: str, user_id: int) -> str:
    user_dir = ensure_user_upload_dir(user_id)
    return os.path.join(user_dir, sanitize_filename(filename))


def extract_statement_type(filename: str) -> Optional[str]:
    """Extrai o tipo do demonstrativo a partir do prefixo do arquivo.

    O tipo é definido pelo texto antes do primeiro ``_`` e deve ser um dos
    valores em ``ALLOWED_FILE_TYPES``.
    """

    base_name = os.path.basename(filename)
    prefix = base_name.split('_', 1)[0]
    # Caso o arquivo não tenha ``_`` usamos apenas o nome antes da extensão
    prefix = prefix.split('.', 1)[0]
    return prefix if prefix in ALLOWED_FILE_TYPES else None


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    def table_has_columns(cursor, table_name: str, required_columns):
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = {row[1] for row in cursor.fetchall()}
        return required_columns.issubset(columns)

    def recreate_data_tables(cursor):
        cursor.execute('DROP TABLE IF EXISTS item_view')
        cursor.execute('DROP TABLE IF EXISTS monthly_totals')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
        '''
    )

    if not table_has_columns(cur, 'users', {'is_admin'}):
        cur.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0')

    # Verifica se as tabelas de dados já possuem coluna de usuário; se não, recria
    if not table_has_columns(cur, 'item_view', {'user_id'}):
        recreate_data_tables(cur)
    if not table_has_columns(cur, 'monthly_totals', {'user_id'}):
        recreate_data_tables(cur)

    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS item_view (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            mes_key TEXT,
            mes_ano TEXT,
            descricao TEXT,
            quantidade TEXT,
            proventos REAL,
            descontos REAL
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS monthly_totals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            mes_key TEXT,
            mes_ano TEXT,
            total_proventos REAL,
            total_descontos REAL,
            liquido REAL
        )
        '''
    )
    conn.commit()
    conn.close()

    ensure_admin_exists()

    # Remove arquivos legados salvos diretamente em ``data/`` para evitar compartilhamento involuntário
    for entry in os.listdir(UPLOAD_FOLDER):
        path = os.path.join(UPLOAD_FOLDER, entry)
        if os.path.isfile(path) and entry.lower().endswith('.pdf'):
            os.remove(path)


def generate_password_hash(password: str, salt_hex: Optional[str] = None) -> Tuple[str, str]:
    salt_bytes = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100_000)
    return salt_bytes.hex(), pwd_hash.hex()


def verify_password(password: str, salt_hex: str, stored_hash: str) -> bool:
    _, new_hash = generate_password_hash(password, salt_hex)
    return stored_hash == new_hash


def get_user_by_username(username: str):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    conn.close()
    return row


def get_user_by_id(user_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def get_all_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, username, is_admin FROM users ORDER BY username')
    rows = cur.fetchall()
    conn.close()
    return rows


def create_user(username: str, password: str, *, is_admin: bool = False) -> Optional[int]:
    salt_hex, pwd_hash = generate_password_hash(password)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            'INSERT INTO users (username, password_hash, salt, is_admin) VALUES (?, ?, ?, ?)',
            (username, pwd_hash, salt_hex, 1 if is_admin else 0),
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        user_id = None
    finally:
        conn.close()
    return user_id


def ensure_admin_exists():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id FROM users WHERE username = ? LIMIT 1', ('admin',))
    exists = cur.fetchone()
    conn.close()
    if exists:
        return
    create_user('admin', 'admin01', is_admin=True)


def get_admin_user(request: Request):
    if not hasattr(request, 'session'):
        return None
    admin_id = request.session.get('admin_id')
    if not admin_id:
        return None
    admin = get_user_by_id(admin_id)
    if admin and admin["is_admin"]:
        return admin
    return None


def get_current_user(request: Request):
    if not hasattr(request, 'session'):
        return None
    user_id = request.session.get('impersonated_user_id') or request.session.get('user_id')
    if not user_id:
        return None
    return get_user_by_id(user_id)


def build_base_context(request: Request, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    context = {
        "request": request,
        "current_user": get_current_user(request),
        "admin_user": get_admin_user(request),
    }
    if extra:
        context.update(extra)
    return context


def ensure_authenticated(request: Request):
    user = get_current_user(request)
    if not user:
        login_url = app.url_path_for('login_get')
        next_path = request.url.path
        if request.url.query:
            next_path += '?' + request.url.query
        redirect_to = f"{login_url}?next={next_path}"
        return None, RedirectResponse(redirect_to, status_code=303)
    return user, None


def ensure_admin(request: Request):
    admin_user = get_admin_user(request)
    if not admin_user:
        login_url = app.url_path_for('login_get')
        next_path = request.url.path
        if request.url.query:
            next_path += '?' + request.url.query
        redirect_to = f"{login_url}?next={next_path}"
        return None, RedirectResponse(redirect_to, status_code=303)
    return admin_user, None


def insert_statement(file_name: str, parsed: dict, user_id: int) -> None:
    mes_key = parsed.get('mes_key')
    mes_ano = parsed.get('mes_ano')
    items = parsed.get('items', [])
    totals = parsed.get('totals', {})
    conn = get_db_connection()
    cur = conn.cursor()
    for item in items:
        cur.execute(
            '''INSERT INTO item_view (user_id, file_name, mes_key, mes_ano, descricao, quantidade, proventos, descontos)
               VALUES (?,?,?,?,?,?,?,?)''',
            (
                user_id,
                file_name,
                mes_key,
                mes_ano,
                item['descricao'],
                item.get('quantidade'),
                item.get('proventos'),
                item.get('descontos'),
            )
        )
    cur.execute(
        '''INSERT INTO monthly_totals (user_id, file_name, mes_key, mes_ano, total_proventos, total_descontos, liquido)
           VALUES (?,?,?,?,?,?,?)''',
        (
            user_id,
            file_name,
            mes_key,
            mes_ano,
            totals.get('total_proventos'),
            totals.get('total_descontos'),
            totals.get('liquido'),
        )
    )
    conn.commit()
    conn.close()


def remove_statement(file_name: str, user_id: int) -> None:
    safe_name = sanitize_filename(file_name)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM item_view WHERE file_name = ? AND user_id = ?', (safe_name, user_id))
    cur.execute('DELETE FROM monthly_totals WHERE file_name = ? AND user_id = ?', (safe_name, user_id))
    conn.commit()
    conn.close()
    file_path = get_user_file_path(safe_name, user_id)
    if os.path.exists(file_path):
        os.remove(file_path)


def get_uploaded_files(user_id: int) -> List[str]:
    user_dir = ensure_user_upload_dir(user_id)
    return sorted([f for f in os.listdir(user_dir) if f.lower().endswith('.pdf')])


def get_files_by_month(mes_key: Optional[str], user_id: int) -> List[str]:
    """Retorna nomes de arquivos já cadastrados para o mês informado."""

    if not mes_key:
        return []
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT DISTINCT file_name FROM monthly_totals WHERE mes_key = ? AND user_id = ?', (mes_key, user_id))
    rows = cur.fetchall()
    conn.close()
    return [row['file_name'] for row in rows]


def get_files_by_month_with_type(mes_key: Optional[str], user_id: int) -> List[Tuple[str, Optional[str]]]:
    """Retorna pares (nome, tipo) para arquivos já cadastrados em ``mes_key``."""

    files = get_files_by_month(mes_key, user_id)
    return [(fname, extract_statement_type(fname)) for fname in files]


def get_months_available(user_id: int) -> List[Tuple[str, str]]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'SELECT DISTINCT mes_key, mes_ano FROM item_view WHERE mes_key IS NOT NULL AND user_id = ? ORDER BY mes_key',
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return [(row['mes_key'], row['mes_ano']) for row in rows]


def get_items_by_month(mes_key: str, user_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        '''SELECT descricao, quantidade, proventos, descontos, file_name
           FROM item_view WHERE mes_key = ? AND user_id = ? ORDER BY descricao''',
        (mes_key, user_id),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_totals_by_month(mes_key: str, user_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        '''SELECT SUM(total_proventos) AS total_proventos,
                  SUM(total_descontos) AS total_descontos,
                  SUM(liquido) AS liquido
           FROM monthly_totals WHERE mes_key = ? AND user_id = ?''',
        (mes_key, user_id),
    )
    row = cur.fetchone()
    conn.close()
    return row


def get_aggregated_series(start_key: Optional[str] = None, end_key: Optional[str] = None, user_id: Optional[int] = None):
    conn = get_db_connection()
    cur = conn.cursor()

    conditions = ["mes_key IS NOT NULL"]
    params: List[str] = []
    if user_id is not None:
        conditions.append("user_id = ?")
        params.append(user_id)
    if start_key:
        conditions.append("mes_key >= ?")
        params.append(start_key)
    if end_key:
        conditions.append("mes_key <= ?")
        params.append(end_key)

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


def get_monthly_totals_by_month(mes_key: str, user_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        '''SELECT file_name, total_proventos, total_descontos, liquido
           FROM monthly_totals
           WHERE mes_key = ? AND user_id = ?
           ORDER BY file_name''',
        (mes_key, user_id),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


@app.on_event("startup")
def startup_event():
    # Inicializa o banco ao iniciar a aplicação
    init_db()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, msg: Optional[str] = None, confirm: Optional[int] = None):
    current_user, redirect_response = ensure_authenticated(request)
    if redirect_response:
        return redirect_response

    files = get_uploaded_files(current_user['id'])
    return templates.TemplateResponse(
        'index.html',
        build_base_context(
            request,
            {
                "files": files,
                "msg": msg,
                "confirm": confirm,
            },
        ),
    )


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, next: Optional[str] = None, msg: Optional[str] = None):
    current_user = get_current_user(request)
    if current_user:
        redirect_to = next or app.url_path_for('index')
        return RedirectResponse(redirect_to, status_code=303)
    return templates.TemplateResponse(
        'login.html',
        build_base_context(request, {"next": next, "msg": msg}),
    )


@app.post("/login")
async def login_post(request: Request):
    form_data = await request.form()
    username = (form_data.get('username') or '').strip()
    password = form_data.get('password') or ''
    next_url = form_data.get('next') or None

    error = None
    user = get_user_by_username(username) if username else None
    if not user:
        error = 'Usuário ou senha inválidos.'
    else:
        if not verify_password(password, user['salt'], user['password_hash']):
            error = 'Usuário ou senha inválidos.'

    if error:
        return templates.TemplateResponse(
            'login.html',
            build_base_context(request, {"next": next_url, "msg": error}),
            status_code=400,
        )

    request.session['user_id'] = user['id']
    request.session.pop('impersonated_user_id', None)
    if user["is_admin"]:
        request.session['admin_id'] = user['id']
        if next_url:
            request.session['post_login_next'] = next_url
        return RedirectResponse(app.url_path_for('admin_select_get'), status_code=303)

    request.session.pop('admin_id', None)
    request.session.pop('post_login_next', None)
    redirect_to = next_url or app.url_path_for('index')
    return RedirectResponse(redirect_to, status_code=303)


@app.get("/register", response_class=HTMLResponse)
async def register_get(request: Request, msg: Optional[str] = None):
    current_user = get_current_user(request)
    if current_user:
        return RedirectResponse(app.url_path_for('index'), status_code=303)
    return templates.TemplateResponse(
        'register.html',
        build_base_context(request, {"msg": msg}),
    )


@app.post("/register")
async def register_post(request: Request):
    form_data = await request.form()
    username = (form_data.get('username') or '').strip()
    password = form_data.get('password') or ''
    confirm_password = form_data.get('confirm_password') or ''

    if not username or not password:
        msg = 'Informe usuário e senha para continuar.'
        return templates.TemplateResponse(
            'register.html',
            build_base_context(request, {"msg": msg}),
            status_code=400,
        )

    if password != confirm_password:
        msg = 'As senhas não conferem.'
        return templates.TemplateResponse(
            'register.html',
            build_base_context(request, {"msg": msg}),
            status_code=400,
        )

    user_id = create_user(username, password)
    if not user_id:
        msg = 'Usuário já existe. Escolha outro nome.'
        return templates.TemplateResponse(
            'register.html',
            build_base_context(request, {"msg": msg}),
            status_code=400,
        )

    request.session['user_id'] = user_id
    return RedirectResponse(app.url_path_for('index'), status_code=303)


@app.post("/logout")
async def logout(request: Request):
    request.session.pop('user_id', None)
    request.session.pop('admin_id', None)
    request.session.pop('impersonated_user_id', None)
    request.session.pop('post_login_next', None)
    return RedirectResponse(app.url_path_for('login_get'), status_code=303)


@app.get("/admin/select", response_class=HTMLResponse)
async def admin_select_get(request: Request, msg: Optional[str] = None):
    admin_user, redirect_response = ensure_admin(request)
    if redirect_response:
        return redirect_response

    users = get_all_users()
    selected_user = get_current_user(request)
    return templates.TemplateResponse(
        'admin_select.html',
        build_base_context(
            request,
            {
                "users": users,
                "selected_user": selected_user,
                "msg": msg,
            },
        ),
    )


@app.post("/admin/select")
async def admin_select_post(request: Request):
    admin_user, redirect_response = ensure_admin(request)
    if redirect_response:
        return redirect_response

    form_data = await request.form()
    target_id_raw = form_data.get('user_id') or ''
    try:
        target_id = int(target_id_raw)
    except ValueError:
        url = app.url_path_for('admin_select_get') + '?msg=Usuário inválido.'
        return RedirectResponse(url, status_code=303)

    target_user = get_user_by_id(target_id)
    if not target_user:
        url = app.url_path_for('admin_select_get') + '?msg=Usuário não encontrado.'
        return RedirectResponse(url, status_code=303)

    if target_user['id'] == admin_user['id']:
        request.session.pop('impersonated_user_id', None)
    else:
        request.session['impersonated_user_id'] = target_user['id']

    request.session['user_id'] = admin_user['id']
    next_url = request.session.pop('post_login_next', None) or app.url_path_for('index')
    return RedirectResponse(next_url, status_code=303)


@app.post("/upload")
async def upload_file(request: Request):
    """
    Endpoint para upload de PDF. A ausência do pacote python-multipart
    impossibilita o uso do parâmetro File/UploadFile do FastAPI. Por
    isso, este handler lê o corpo da requisição diretamente e faz o
    parsing manual do conteúdo multipart/form-data.
    """
    current_user, redirect_response = ensure_authenticated(request)
    if redirect_response:
        return redirect_response
    user_id = current_user['id']
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

        secure_name = sanitize_filename(file_name)
        statement_type = extract_statement_type(secure_name)
        if not statement_type:
            messages.append(
                f'Nome de arquivo inválido para {secure_name}. Use os prefixos FolMen, Outros ou PagPLR antes do primeiro "_".'
            )
            continue
        save_path = get_user_file_path(secure_name, user_id)
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
        existing_month_files = get_files_by_month_with_type(mes_key, user_id)
        existing_types = {ftype: fname for fname, ftype in existing_month_files if ftype}
        duplicate_name = os.path.exists(save_path)
        duplicate_type = bool(mes_key and statement_type in existing_types)

        if (duplicate_name or duplicate_type) and not confirm_flag:
            os.remove(temp_path)
            details = []
            if duplicate_name:
                details.append(f'O arquivo {secure_name} já existe.')
            if duplicate_type:
                conflicting = existing_types.get(statement_type)
                details.append(
                    f'Já existe um arquivo do tipo {statement_type} para {parsed.get("mes_ano", mes_key)} '
                    f'(arquivo: {conflicting}).'
                )
            messages.append(' '.join(details) + ' Confirme a substituição marcando a opção no formulário e envie novamente.')
            reconfirm_needed = True
            continue

        if duplicate_name:
            remove_statement(secure_name, user_id)
        if duplicate_type:
            conflicting = existing_types.get(statement_type)
            if conflicting and conflicting != secure_name:
                remove_statement(conflicting, user_id)

        os.replace(temp_path, save_path)
        insert_statement(secure_name, parsed, user_id)
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
    current_user, redirect_response = ensure_authenticated(request)
    if redirect_response:
        return redirect_response

    remove_statement(filename, current_user['id'])
    url = app.url_path_for('index') + '?msg=' + f'Arquivo {filename} removido.'
    return RedirectResponse(url, status_code=303)


@app.get("/consulta", response_class=HTMLResponse)
async def consulta_get(request: Request):
    """Renderiza a página de consulta. Aceita mes_key via query string."""
    current_user, redirect_response = ensure_authenticated(request)
    if redirect_response:
        return redirect_response

    mes_key = request.query_params.get('mes_key') if request.query_params else None
    months = get_months_available(current_user['id'])
    items = []
    totals = None
    descontos_pct = None
    liquido_pct = None
    selected_key = mes_key
    if selected_key:
        items = get_items_by_month(selected_key, current_user['id'])
        totals = get_totals_by_month(selected_key, current_user['id'])
        if totals:
            total_proventos = totals['total_proventos']
            descontos_pct = calculate_percentage(totals['total_descontos'], total_proventos)
            liquido_pct = calculate_percentage(totals['liquido'], total_proventos)
    return templates.TemplateResponse(
        'consulta.html',
        build_base_context(
            request,
            {
                "months": months,
                "items": items,
                "totals": totals,
                "selected_key": selected_key,
                "descontos_pct": descontos_pct,
                "liquido_pct": liquido_pct,
            },
        ),
    )




@app.get("/dashboard_totais", response_class=HTMLResponse)
async def dashboard_totais(request: Request):
    current_user, redirect_response = ensure_authenticated(request)
    if redirect_response:
        return redirect_response

    months_available = get_months_available(current_user['id'])
    start_month = request.query_params.get('start') if request.query_params else None
    end_month = request.query_params.get('end') if request.query_params else None
    selected_types = request.query_params.getlist('types') if request.query_params else []

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

    series = get_aggregated_series(start_key=start_key, end_key=end_key, user_id=current_user['id'])
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
        build_base_context(
            request,
            {
                "graphs_json": graphs_json,
                "start_month": start_month,
                "end_month": end_month,
                "selected_types": selected_types,
                "last_month": last_month,
                "prev_month": prev_month,
                "variations": variations,
                "band_table_rows": band_table_rows,
            },
        ),
    )


@app.get("/download/{filename:path}")
async def download_file(request: Request, filename: str):
    current_user, redirect_response = ensure_authenticated(request)
    if redirect_response:
        return redirect_response

    safe_name = sanitize_filename(filename)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT 1 FROM monthly_totals WHERE file_name = ? AND user_id = ? LIMIT 1', (safe_name, current_user['id']))
    allowed = cur.fetchone()
    conn.close()
    if not allowed:
        url = app.url_path_for('index') + '?msg=' + 'Arquivo não encontrado.'
        return RedirectResponse(url, status_code=303)

    file_path = get_user_file_path(safe_name, current_user['id'])
    if not os.path.exists(file_path):
        url = app.url_path_for('index') + '?msg=' + 'Arquivo indisponível.'
        return RedirectResponse(url, status_code=303)

    return FileResponse(file_path, filename=safe_name)


if __name__ == '__main__':
    # Execução direta com uvicorn para ambiente de desenvolvimento
    import uvicorn
    init_db()
    uvicorn.run(app, host='0.0.0.0', port=4000)
