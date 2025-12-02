"""
Aplicação web construída com FastAPI para acompanhar demonstrativos de
pagamento. Esta implementação utiliza os mesmos conceitos da versão
original em Flask, mas utiliza FastAPI e Starlette para compatibilidade
com o ambiente atual, onde o Flask não está disponível. Futuras
alterações devem seguir as orientações em ``AGENTS.MD`` e atualizar
este arquivo conforme necessário.
"""

import os
import sqlite3
from typing import List, Tuple, Optional, Dict

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
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

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="change-me-secret-key")

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


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username, password, is_admin FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    conn.close()
    return row


def authenticate_user(username: str, password: str) -> Optional[Dict[str, str]]:
    user_row = get_user_by_username(username)
    if not user_row:
        return None
    if password != user_row['password']:
        return None
    return {"username": user_row['username'], "is_admin": bool(user_row['is_admin'])}


def create_user(username: str, password: str, is_admin: bool = False) -> Tuple[bool, str]:
    if not username or len(username) > 20:
        return False, "Usuário deve ter até 20 caracteres."
    if not password or len(password) <= 1:
        return False, "Senha deve ter mais que 1 caractere."
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
            (username, password, 1 if is_admin else 0),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Usuário já existe ou viola as regras de validação."
    conn.close()
    return True, "Usuário criado com sucesso."


def get_current_user(request: Request) -> Optional[Dict[str, str]]:
    user = request.session.get("user") if hasattr(request, "session") else None
    if not user:
        return None
    return {"username": user.get("username"), "is_admin": bool(user.get("is_admin"))}


def list_users() -> List[sqlite3.Row]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username, is_admin FROM users ORDER BY username')
    rows = cur.fetchall()
    conn.close()
    return rows


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
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
            descontos REAL
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
            liquido REAL
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE CHECK(LENGTH(username) <= 20),
            password TEXT NOT NULL CHECK(LENGTH(password) > 1),
            is_admin INTEGER NOT NULL DEFAULT 0
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS user_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            file_name TEXT NOT NULL,
            UNIQUE(username, file_name)
        )
        '''
    )
    cur.execute(
        '''
        INSERT OR IGNORE INTO users (username, password, is_admin)
        VALUES ('admin', 'admin', 1)
        '''
    )
    conn.commit()
    conn.close()


def associate_file_with_user(username: str, file_name: str) -> None:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'INSERT OR IGNORE INTO user_files (username, file_name) VALUES (?, ?)',
        (username, file_name),
    )
    conn.commit()
    conn.close()


def insert_statement(file_name: str, parsed: dict, owner_username: Optional[str]) -> None:
    mes_key = parsed.get('mes_key')
    mes_ano = parsed.get('mes_ano')
    items = parsed.get('items', [])
    totals = parsed.get('totals', {})
    conn = get_db_connection()
    cur = conn.cursor()
    for item in items:
        cur.execute(
            '''INSERT INTO item_view (file_name, mes_key, mes_ano, descricao, quantidade, proventos, descontos)
               VALUES (?,?,?,?,?,?,?)''',
            (
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
        '''INSERT INTO monthly_totals (file_name, mes_key, mes_ano, total_proventos, total_descontos, liquido)
           VALUES (?,?,?,?,?,?)''',
        (
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
    if owner_username:
        associate_file_with_user(owner_username, file_name)


def remove_statement(file_name: str) -> None:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM item_view WHERE file_name = ?', (file_name,))
    cur.execute('DELETE FROM monthly_totals WHERE file_name = ?', (file_name,))
    cur.execute('DELETE FROM user_files WHERE file_name = ?', (file_name,))
    conn.commit()
    conn.close()
    file_path = os.path.join(UPLOAD_FOLDER, file_name)
    if os.path.exists(file_path):
        os.remove(file_path)


def get_allowed_user_filter(current_user: Dict[str, str], selected_user: Optional[str]) -> Optional[str]:
    if current_user.get("is_admin"):
        return selected_user
    return current_user.get("username")


def get_uploaded_files(current_user: Dict[str, str], selected_user: Optional[str] = None) -> List[str]:
    owner = get_allowed_user_filter(current_user, selected_user)
    conn = get_db_connection()
    cur = conn.cursor()
    if owner:
        cur.execute('SELECT file_name FROM user_files WHERE username = ? ORDER BY file_name', (owner,))
    else:
        cur.execute('SELECT file_name FROM user_files ORDER BY file_name')
    rows = cur.fetchall()
    conn.close()
    return [row['file_name'] for row in rows]


def get_owner_for_file(file_name: str) -> Optional[str]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username FROM user_files WHERE file_name = ?', (file_name,))
    row = cur.fetchone()
    conn.close()
    return row['username'] if row else None


def get_files_by_month(
    mes_key: Optional[str], current_user: Dict[str, str], selected_user: Optional[str] = None
) -> List[str]:
    """Retorna nomes de arquivos já cadastrados para o mês informado."""

    if not mes_key:
        return []
    owner = get_allowed_user_filter(current_user, selected_user)
    conn = get_db_connection()
    cur = conn.cursor()
    if owner:
        cur.execute(
            '''
            SELECT DISTINCT mt.file_name
            FROM monthly_totals mt
            JOIN user_files uf ON uf.file_name = mt.file_name
            WHERE mt.mes_key = ? AND uf.username = ?
            ''',
            (mes_key, owner),
        )
    else:
        cur.execute(
            '''
            SELECT DISTINCT file_name
            FROM monthly_totals
            WHERE mes_key = ?
            ''',
            (mes_key,),
        )
    rows = cur.fetchall()
    conn.close()
    return [row['file_name'] for row in rows]


def get_months_available(
    current_user: Dict[str, str], selected_user: Optional[str] = None
) -> List[Tuple[str, str]]:
    conn = get_db_connection()
    cur = conn.cursor()
    owner = get_allowed_user_filter(current_user, selected_user)
    if owner:
        cur.execute(
            '''
            SELECT DISTINCT iv.mes_key, iv.mes_ano
            FROM item_view iv
            JOIN user_files uf ON uf.file_name = iv.file_name
            WHERE iv.mes_key IS NOT NULL AND uf.username = ?
            ORDER BY iv.mes_key
            ''',
            (owner,),
        )
    else:
        cur.execute(
            'SELECT DISTINCT mes_key, mes_ano FROM item_view WHERE mes_key IS NOT NULL ORDER BY mes_key'
        )
    rows = cur.fetchall()
    conn.close()
    return [(row['mes_key'], row['mes_ano']) for row in rows]


def get_items_by_month(mes_key: str, current_user: Dict[str, str], selected_user: Optional[str]):
    conn = get_db_connection()
    cur = conn.cursor()
    owner = get_allowed_user_filter(current_user, selected_user)
    if owner:
        cur.execute(
            '''SELECT iv.descricao, iv.quantidade, iv.proventos, iv.descontos, iv.file_name
               FROM item_view iv
               JOIN user_files uf ON uf.file_name = iv.file_name
               WHERE iv.mes_key = ? AND uf.username = ?
               ORDER BY iv.descricao''',
            (mes_key, owner),
        )
    else:
        cur.execute(
            '''SELECT descricao, quantidade, proventos, descontos, file_name
               FROM item_view WHERE mes_key = ? ORDER BY descricao''',
            (mes_key,),
        )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_totals_by_month(mes_key: str, current_user: Dict[str, str], selected_user: Optional[str]):
    conn = get_db_connection()
    cur = conn.cursor()
    owner = get_allowed_user_filter(current_user, selected_user)
    if owner:
        cur.execute(
            '''SELECT SUM(mt.total_proventos) AS total_proventos,
                      SUM(mt.total_descontos) AS total_descontos,
                      SUM(mt.liquido) AS liquido
               FROM monthly_totals mt
               JOIN user_files uf ON uf.file_name = mt.file_name
               WHERE mt.mes_key = ? AND uf.username = ?''',
            (mes_key, owner),
        )
    else:
        cur.execute(
            '''SELECT SUM(total_proventos) AS total_proventos,
                      SUM(total_descontos) AS total_descontos,
                      SUM(liquido) AS liquido
               FROM monthly_totals WHERE mes_key = ?''',
            (mes_key,),
        )
    row = cur.fetchone()
    conn.close()
    return row



def get_aggregated_series(
    start_key: Optional[str] = None, end_key: Optional[str] = None, current_user: Optional[Dict[str, str]] = None,
    selected_user: Optional[str] = None,
):
    conn = get_db_connection()
    cur = conn.cursor()

    conditions = ["mt.mes_key IS NOT NULL"]
    params: List[str] = []
    owner = get_allowed_user_filter(current_user or {}, selected_user)
    if owner:
        conditions.append("uf.username = ?")
        params.append(owner)
    if start_key:
        conditions.append("mt.mes_key >= ?")
        params.append(start_key)
    if end_key:
        conditions.append("mt.mes_key <= ?")
        params.append(end_key)

    where_clause = " AND ".join(conditions)
    query = f'''
        SELECT mt.mes_key, mt.mes_ano,
               SUM(mt.total_proventos) AS total_proventos,
               SUM(mt.total_descontos) AS total_descontos,
               SUM(mt.liquido) AS liquido
        FROM monthly_totals mt
        LEFT JOIN user_files uf ON uf.file_name = mt.file_name
        WHERE {where_clause}
        GROUP BY mt.mes_key, mt.mes_ano
        ORDER BY mt.mes_key
    '''

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_monthly_totals_by_month(mes_key: str, current_user: Dict[str, str], selected_user: Optional[str]):
    conn = get_db_connection()
    cur = conn.cursor()
    owner = get_allowed_user_filter(current_user, selected_user)
    if owner:
        cur.execute(
            '''SELECT mt.file_name, mt.total_proventos, mt.total_descontos, mt.liquido
               FROM monthly_totals mt
               JOIN user_files uf ON uf.file_name = mt.file_name
               WHERE mt.mes_key = ? AND uf.username = ?
               ORDER BY mt.file_name''',
            (mes_key, owner),
        )
    else:
        cur.execute(
            '''SELECT file_name, total_proventos, total_descontos, liquido
               FROM monthly_totals
               WHERE mes_key = ?
               ORDER BY file_name''',
            (mes_key,),
        )
    rows = cur.fetchall()
    conn.close()
    return rows


@app.on_event("startup")
def startup_event():
    # Inicializa o banco ao iniciar a aplicação
    init_db()


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, msg: Optional[str] = None):
    if get_current_user(request):
        return RedirectResponse(app.url_path_for('index'), status_code=303)
    return templates.TemplateResponse('login.html', {"request": request, "msg": msg, "current_user": None})


@app.post("/login")
async def login_post(request: Request):
    form = await request.form()
    username = str(form.get('username') or '').strip()[:20]
    password = str(form.get('password') or '')
    user = authenticate_user(username, password)
    if not user:
        url = app.url_path_for('login_get') + '?msg=Credenciais inválidas.'
        return RedirectResponse(url, status_code=303)
    request.session['user'] = user
    return RedirectResponse(app.url_path_for('index'), status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(app.url_path_for('login_get'), status_code=303)


@app.get("/register", response_class=HTMLResponse)
async def register_get(request: Request, msg: Optional[str] = None):
    return templates.TemplateResponse('register.html', {"request": request, "msg": msg, "current_user": None})


@app.post("/register")
async def register_post(request: Request):
    form = await request.form()
    username = str(form.get('username') or '').strip()[:20]
    password = str(form.get('password') or '')
    success, message = create_user(username, password, is_admin=False)
    if not success:
        url = app.url_path_for('register_get') + f'?msg={message}'
        return RedirectResponse(url, status_code=303)
    url = app.url_path_for('login_get') + '?msg=Cadastro realizado com sucesso. Faça login.'
    return RedirectResponse(url, status_code=303)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, msg: Optional[str] = None, confirm: Optional[int] = None):
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(app.url_path_for('login_get'), status_code=303)

    selected_user = None
    if current_user.get("is_admin"):
        selected_user = (request.query_params.get('user') or None) if request.query_params else None
    files = get_uploaded_files(current_user, selected_user)
    users = list_users() if current_user.get("is_admin") else []
    return templates.TemplateResponse(
        'index.html',
        {
            "request": request,
            "files": files,
            "msg": msg,
            "confirm": confirm,
            "current_user": current_user,
            "selected_user": selected_user or current_user.get("username"),
            "users": users,
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
        return RedirectResponse(app.url_path_for('login_get'), status_code=303)
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
    owner_field_value: Optional[str] = None
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
        elif field_name == 'owner':
            owner_field_value = content.rstrip(b'\r\n').decode(errors='ignore').strip()
    if not files_data:
        url = app.url_path_for('index') + '?msg=' + 'Nenhum arquivo encontrado no upload.'
        return RedirectResponse(url, status_code=303)

    messages: List[str] = []
    reconfirm_needed = False

    owner_username = current_user.get("username")
    if owner_field_value and current_user.get("is_admin"):
        owner_username = owner_field_value[:20]
    owner_row = get_user_by_username(owner_username)
    if not owner_row:
        url = app.url_path_for('index') + '?msg=' + 'Usuário destino inválido para o upload.'
        return RedirectResponse(url, status_code=303)

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
        existing_month_files = get_files_by_month(mes_key, current_user, owner_username)
        duplicate_name = os.path.exists(save_path)
        if duplicate_name and not current_user.get("is_admin"):
            existing_owner = get_owner_for_file(secure_name)
            if existing_owner and existing_owner != owner_username:
                os.remove(temp_path)
                messages.append('Arquivo já pertence a outro usuário.')
                continue
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
            remove_statement(secure_name)
        if duplicate_month:
            for fname in existing_month_files:
                if fname != secure_name:
                    remove_statement(fname)

        os.replace(temp_path, save_path)
        insert_statement(secure_name, parsed, owner_username)
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
        return RedirectResponse(app.url_path_for('login_get'), status_code=303)
    owner = get_owner_for_file(filename)
    if owner is None:
        url = app.url_path_for('index') + '?msg=' + 'Arquivo não encontrado para exclusão.'
        return RedirectResponse(url, status_code=303)
    if not current_user.get("is_admin") and owner != current_user.get("username"):
        url = app.url_path_for('index') + '?msg=' + 'Você não tem permissão para remover este arquivo.'
        return RedirectResponse(url, status_code=303)
    remove_statement(filename)
    url = app.url_path_for('index') + '?msg=' + f'Arquivo {filename} removido.'
    return RedirectResponse(url, status_code=303)


@app.get("/consulta", response_class=HTMLResponse)
async def consulta_get(request: Request):
    """Renderiza a página de consulta. Aceita mes_key via query string."""
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(app.url_path_for('login_get'), status_code=303)

    mes_key = request.query_params.get('mes_key') if request.query_params else None
    selected_user = None
    if current_user.get("is_admin"):
        selected_user = (request.query_params.get('user') or None) if request.query_params else None
    months = get_months_available(current_user, selected_user)
    items = []
    totals = None
    descontos_pct = None
    liquido_pct = None
    selected_key = mes_key
    if selected_key:
        items = get_items_by_month(selected_key, current_user, selected_user)
        totals = get_totals_by_month(selected_key, current_user, selected_user)
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
            "selected_user": selected_user or current_user.get("username"),
            "users": list_users() if current_user.get("is_admin") else [],
        },
    )




@app.get("/dashboard_totais", response_class=HTMLResponse)
async def dashboard_totais(request: Request):
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(app.url_path_for('login_get'), status_code=303)

    selected_user = None
    if current_user.get("is_admin"):
        selected_user = (request.query_params.get('user') or None) if request.query_params else None
    months_available = get_months_available(current_user, selected_user)
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

    series = get_aggregated_series(start_key=start_key, end_key=end_key, current_user=current_user, selected_user=selected_user)
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
            "selected_user": selected_user or current_user.get("username"),
            "users": list_users() if current_user.get("is_admin") else [],
        },
    )


@app.get("/download/{filename:path}")
async def download_file(request: Request, filename: str):
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(app.url_path_for('login_get'), status_code=303)
    owner = get_owner_for_file(filename)
    if owner is None:
        return RedirectResponse(app.url_path_for('index'), status_code=303)
    if not current_user.get("is_admin") and owner != current_user.get("username"):
        return RedirectResponse(app.url_path_for('index') + '?msg=Sem permissão para baixar este arquivo.', status_code=303)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    return FileResponse(file_path, filename=filename)


if __name__ == '__main__':
    # Execução direta com uvicorn para ambiente de desenvolvimento
    import uvicorn
    init_db()
    uvicorn.run(app, host='0.0.0.0', port=5000)