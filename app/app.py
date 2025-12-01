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
from typing import List, Tuple, Optional

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

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

# Monta diretório de uploads como estático para servir PDFs
app.mount("/uploads", StaticFiles(directory=UPLOAD_FOLDER), name="uploads")


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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
    conn.commit()
    conn.close()


def insert_statement(file_name: str, parsed: dict) -> None:
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


def remove_statement(file_name: str) -> None:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM item_view WHERE file_name = ?', (file_name,))
    cur.execute('DELETE FROM monthly_totals WHERE file_name = ?', (file_name,))
    conn.commit()
    conn.close()
    file_path = os.path.join(UPLOAD_FOLDER, file_name)
    if os.path.exists(file_path):
        os.remove(file_path)


def get_uploaded_files() -> List[str]:
    return sorted([f for f in os.listdir(UPLOAD_FOLDER) if f.lower().endswith('.pdf')])


def get_files_by_month(mes_key: Optional[str]) -> List[str]:
    """Retorna nomes de arquivos já cadastrados para o mês informado."""

    if not mes_key:
        return []
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT DISTINCT file_name FROM monthly_totals WHERE mes_key = ?', (mes_key,))
    rows = cur.fetchall()
    conn.close()
    return [row['file_name'] for row in rows]


def get_months_available() -> List[Tuple[str, str]]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT DISTINCT mes_key, mes_ano FROM item_view WHERE mes_key IS NOT NULL ORDER BY mes_key')
    rows = cur.fetchall()
    conn.close()
    return [(row['mes_key'], row['mes_ano']) for row in rows]


def get_items_by_month(mes_key: str):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        '''SELECT descricao, quantidade, proventos, descontos, file_name
           FROM item_view WHERE mes_key = ? ORDER BY descricao''',
        (mes_key,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_totals_by_month(mes_key: str):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        '''SELECT SUM(total_proventos) AS total_proventos,
                  SUM(total_descontos) AS total_descontos,
                  SUM(liquido) AS liquido
           FROM monthly_totals WHERE mes_key = ?''',
        (mes_key,)
    )
    row = cur.fetchone()
    conn.close()
    return row


def get_aggregated_series():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        '''SELECT mes_key, mes_ano,
                  SUM(total_proventos) AS total_proventos,
                  SUM(total_descontos) AS total_descontos,
                  SUM(liquido) AS liquido
           FROM monthly_totals
           WHERE mes_key IS NOT NULL
           GROUP BY mes_key, mes_ano
           ORDER BY mes_key'''
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
    files = get_uploaded_files()
    return templates.TemplateResponse('index.html', {"request": request, "files": files, "msg": msg, "confirm": confirm})


@app.post("/upload")
async def upload_file(request: Request):
    """
    Endpoint para upload de PDF. A ausência do pacote python-multipart
    impossibilita o uso do parâmetro File/UploadFile do FastAPI. Por
    isso, este handler lê o corpo da requisição diretamente e faz o
    parsing manual do conteúdo multipart/form-data.
    """
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
    file_name = None
    file_content = None
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
            file_name = filename
            file_content = content.rstrip(b'\r\n')  # remove CRLF final
        elif field_name == 'confirm':
            value = content.rstrip(b'\r\n').decode(errors='ignore')
            confirm_flag = value.strip() == '1'
    if not file_name or file_content is None:
        url = app.url_path_for('index') + '?msg=' + 'Nenhum arquivo encontrado no upload.'
        return RedirectResponse(url, status_code=303)
    if not allowed_file(file_name):
        url = app.url_path_for('index') + '?msg=' + 'Extensão de arquivo não permitida.'
        return RedirectResponse(url, status_code=303)
    secure_name = file_name.replace('/', '_')
    save_path = os.path.join(UPLOAD_FOLDER, secure_name)
    temp_path = save_path + '.upload'
    with open(temp_path, 'wb') as f:
        f.write(file_content)
    try:
        parsed = parse_pdf(temp_path)
    except Exception as e:
        os.remove(temp_path)
        url = app.url_path_for('index') + '?msg=' + f'Falha ao processar PDF: {e}'
        return RedirectResponse(url, status_code=303)
    mes_key = parsed.get('mes_key')
    existing_month_files = get_files_by_month(mes_key)
    duplicate_name = os.path.exists(save_path)
    duplicate_month = bool(existing_month_files)
    if (duplicate_name or duplicate_month) and not confirm_flag:
        os.remove(temp_path)
        messages = []
        if duplicate_name:
            messages.append(f'O arquivo {secure_name} já existe.')
        if duplicate_month:
            messages.append(f'O mês {parsed.get("mes_ano", mes_key)} já está cadastrado (arquivos: {", ".join(existing_month_files)}).')
        msg = ' '.join(messages) + " Confirme a substituição marcando a opção no formulário e envie novamente."
        url = app.url_path_for('index') + '?msg=' + msg + '&confirm=1'
        return RedirectResponse(url, status_code=303)

    if duplicate_name:
        remove_statement(secure_name)
    if duplicate_month:
        for fname in existing_month_files:
            if fname != secure_name:
                remove_statement(fname)

    os.replace(temp_path, save_path)
    insert_statement(secure_name, parsed)
    url = app.url_path_for('index') + '?msg=' + f'Arquivo {secure_name} carregado com sucesso.'
    return RedirectResponse(url, status_code=303)


@app.post("/delete/{filename:path}")
async def delete_file(filename: str):
    remove_statement(filename)
    url = app.url_path_for('index') + '?msg=' + f'Arquivo {filename} removido.'
    return RedirectResponse(url, status_code=303)


@app.get("/consulta", response_class=HTMLResponse)
async def consulta_get(request: Request):
    """Renderiza a página de consulta. Aceita mes_key via query string."""
    mes_key = request.query_params.get('mes_key') if request.query_params else None
    months = get_months_available()
    items = []
    totals = None
    selected_key = mes_key
    if selected_key:
        items = get_items_by_month(selected_key)
        totals = get_totals_by_month(selected_key)
    return templates.TemplateResponse('consulta.html', {"request": request, "months": months, "items": items, "totals": totals, "selected_key": selected_key})




@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    series = get_aggregated_series()
    graphs_json = None
    if series:
        months = [row['mes_ano'] for row in series]
        prov_series = [row['total_proventos'] for row in series]
        desc_series = [row['total_descontos'] for row in series]
        liq_series = [row['liquido'] for row in series]
        traces = []
        traces.append(go.Scatter(x=months, y=prov_series, mode='lines+markers', name='Proventos'))
        traces.append(go.Scatter(x=months, y=desc_series, mode='lines+markers', name='Descontos'))
        traces.append(go.Scatter(x=months, y=liq_series, mode='lines+markers', name='Líquido'))
        layout = go.Layout(title='Série histórica de proventos, descontos e líquido', xaxis={'title': 'Mês'}, yaxis={'title': 'Valor (R$)'})
        fig_history = go.Figure(data=traces, layout=layout)
        latest = series[-1]
        latest_month = latest['mes_key']
        latest_items = get_items_by_month(latest_month)
        desc_labels = []
        desc_prov = []
        desc_descs = []
        for item in latest_items:
            desc_labels.append(item['descricao'])
            desc_prov.append(item['proventos'] or 0)
            desc_descs.append(item['descontos'] or 0)
        bar_trace1 = go.Bar(x=desc_labels, y=desc_prov, name='Proventos')
        bar_trace2 = go.Bar(x=desc_labels, y=desc_descs, name='Descontos')
        bar_layout = go.Layout(title=f'Composição de proventos e descontos em {latest["mes_ano"]}', barmode='group', xaxis={'title':'Descrição'}, yaxis={'title':'Valor (R$)'})
        fig_latest = go.Figure(data=[bar_trace1, bar_trace2], layout=bar_layout)
        graphs = [fig_history, fig_latest]
        graphs_json = json.dumps(graphs, cls=plotly.utils.PlotlyJSONEncoder)
    return templates.TemplateResponse('dashboard.html', {"request": request, "graphs_json": graphs_json})


@app.get("/download/{filename:path}")
async def download_file(filename: str):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    return FileResponse(file_path, filename=filename)


if __name__ == '__main__':
    # Execução direta com uvicorn para ambiente de desenvolvimento
    import uvicorn
    init_db()
    uvicorn.run(app, host='0.0.0.0', port=5000)