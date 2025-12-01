"""
Helper utilities to parse Brazilian payroll PDF statements into structured data.

This module provides functions to extract itemized earnings and deductions
from a PDF as well as overall totals (proventos, descontos and net value).

The parser uses the PyMuPDF library (imported as ``fitz``) to read the
geometry of each word in the PDF. Column boundaries are calculated based
on the positions of the header labels (``Descrição``, ``Qtde``, ``Unid``,
``Proventos`` and ``Descontos``) on the first page. Words are grouped
according to those boundaries and assembled into rows.

These functions are designed to work with demonstration pay slips
following the same layout as the samples provided. If the layout of
future documents changes (for example, additional columns or different
label names), the parsing logic may need to be revisited. When making
changes to the parsing logic remember to also update the documentation
in this file and the AGENTS.MD guide.
"""

from __future__ import annotations

import fitz  # PyMuPDF
from typing import Dict, List, Tuple
import re

# Mapping of Portuguese month names to numeric month values. Used to
# convert the "Mês/Ano" field into a sortable ISO date string. If a
# new month name appears in future documents it should be added here.
MONTH_MAP = {
    "Janeiro": 1,
    "Fevereiro": 2,
    "Março": 3,
    "Abril": 4,
    "Maio": 5,
    "Junho": 6,
    "Julho": 7,
    "Agosto": 8,
    "Setembro": 9,
    "Outubro": 10,
    "Novembro": 11,
    "Dezembro": 12,
}

def _find_header_positions(words: List[Tuple[float, float, float, float, str, int, int, int]]) -> Tuple[float, float, float, float, float, float]:
    """Locate the horizontal boundaries for each column on the first page.

    The PDF places each column label on its own line, but they share a
    common horizontal position. This function groups header words by the
    rounded y‐coordinate and selects the first row that contains all
    expected labels. It then computes midpoints between adjacent labels
    to establish boundaries for the description, quantity, unit,
    proventos and descontos columns.

    Returns
    -------
    tuple
        A tuple containing the upper bounds of the description,
        quantity, unit and proventos columns. Any word with an x
        coordinate greater than the last bound is assumed to belong to
        the descontos column.
    """
    from collections import defaultdict

    header_candidates: Dict[int, Dict[str, Tuple[float, float]]] = defaultdict(dict)
    for x0, y0, x1, y1, text, block_no, line_no, word_no in words:
        if text in ["Descrição", "Qtde", "Unid", "Proventos", "Descontos"]:
            key = round(y0)
            header_candidates[key][text] = (x0, x1)
    header_y = None
    desc_header = qtde_header = unid_header = prov_header = descs_header = None
    for y, labels in header_candidates.items():
        if all(key in labels for key in ["Descrição", "Qtde", "Unid", "Proventos", "Descontos"]):
            header_y = y
            desc_header = labels["Descrição"]
            qtde_header = labels["Qtde"]
            unid_header = labels["Unid"]
            prov_header = labels["Proventos"]
            descs_header = labels["Descontos"]
            break
    if header_y is None:
        raise ValueError("Não foi possível localizar as colunas do cabeçalho no PDF.")
    # Calculate column boundaries by averaging adjacent header positions.
    bound_desc_end = (desc_header[1] + qtde_header[0]) / 2
    bound_qtde_end = (qtde_header[1] + unid_header[0]) / 2
    bound_unid_end = (unid_header[1] + prov_header[0]) / 2
    bound_prov_end = (prov_header[1] + descs_header[0]) / 2
    return header_y, bound_desc_end, bound_qtde_end, bound_unid_end, bound_prov_end


def _parse_value(value: str) -> float | None:
    """Convert a Brazilian formatted number into a Python float.

    Empty strings or non‐numeric values return ``None``. Thousands
    separators (periods) are stripped and the decimal comma is
    converted to a dot.
    """
    value = value.strip()
    if not value:
        return None
    # Remove non breaking spaces and thousands separators
    cleaned = value.replace(".", "").replace("\xa0", "").replace(",", ".")
    # Use regex to ensure it contains digits
    if not re.search(r"\d", cleaned):
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


def parse_pdf(path: str) -> Dict[str, object]:
    """Extract structured data from a payroll PDF.

    Parameters
    ----------
    path : str
        Absolute path to the PDF file.

    Returns
    -------
    dict
        A dictionary containing the following keys:

        - ``mes_ano``: the raw month/year string (e.g., ``"Outubro/2025"``)
        - ``mes_key``: an ISO date string (``YYYY-MM-01``) useful for
          grouping and sorting chronologically
        - ``items``: list of dictionaries, one per row, with keys
          ``descricao``, ``quantidade``, ``proventos`` and
          ``descontos`` (floats or ``None``)
        - ``totals``: dictionary with keys ``total_proventos``,
          ``total_descontos`` and ``liquido`` (floats or ``None``)

    Raises
    ------
    ValueError
        If mandatory fields such as ``Mês/Ano`` or column headers are not found.
    """
    doc = fitz.open(path)
    page = doc[0]
    # Extract all words with coordinates
    words = page.get_text("words")
    # Determine column boundaries and header y position
    header_y, b_desc, b_qtde, b_unid, b_prov = _find_header_positions(words)
    # Collect rows grouped by approximate y coordinate
    from collections import defaultdict

    row_map: Dict[int, List[Tuple[float, str]]] = defaultdict(list)
    for x0, y0, x1, y1, text, block_no, line_no, word_no in words:
        # Skip header rows
        if y0 <= header_y:
            continue
        row_key = round(y0)
        row_map[row_key].append((x0, text))
    # Build item rows
    items: List[Dict[str, object]] = []
    for y_key in sorted(row_map.keys()):
        row = row_map[y_key]
        # Sort words by x coordinate
        row.sort(key=lambda x: x[0])
        desc_tokens: List[str] = []
        qtde_tokens: List[str] = []
        prov_tokens: List[str] = []
        descs_tokens: List[str] = []
        # Flag to break outer loop when summary section starts
        encountered_summary = False
        for x0, text in row:
            # Determine if this row is part of the summary section. We look
            # for specific keywords at the beginning of the description
            # column. The string "Sal" can legitimately start the
            # description "Salário", so only break on "Sal" if it
            # continues with "Contribuição" (found in the summary area).
            text_stripped = text.strip()
            is_summary = (
                text_stripped.startswith(("Base", "Total", "Líquido", "FGTS"))
                or (text_stripped.startswith("Sal") and "Contribuição" in text_stripped)
            )
            if is_summary:
                encountered_summary = True
                break
            # Assign token to column based on x position
            if x0 < b_desc:
                desc_tokens.append(text)
            elif x0 < b_qtde:
                qtde_tokens.append(text)
            elif x0 < b_unid:
                # A coluna "Unid" é ignorada, mas sua posição delimita as demais
                # colunas numéricas.
                continue
            elif x0 < b_prov:
                prov_tokens.append(text)
            else:
                descs_tokens.append(text)
        if encountered_summary:
            break
        if not desc_tokens:
            continue
        descricao = " ".join(desc_tokens).strip()
        quantidade = " ".join(qtde_tokens).strip()
        prov_str = " ".join(prov_tokens).strip()
        desc_str = " ".join(descs_tokens).strip()
        proventos = _parse_value(prov_str)
        descontos = _parse_value(desc_str)
        items.append({
            "descricao": descricao,
            "quantidade": quantidade or None,
            "proventos": proventos,
            "descontos": descontos,
        })
    # Parse totals from the plain text
    text_lines = page.get_text("text").split("\n")
    totals: Dict[str, float | None] = {
        "total_proventos": None,
        "total_descontos": None,
        "liquido": None,
    }
    for idx, line in enumerate(text_lines):
        line_stripped = line.strip()
        if line_stripped == "Total Proventos" and idx + 1 < len(text_lines):
            totals["total_proventos"] = _parse_value(text_lines[idx + 1].strip())
        elif line_stripped == "Total Descontos" and idx + 1 < len(text_lines):
            totals["total_descontos"] = _parse_value(text_lines[idx + 1].strip())
        elif line_stripped.startswith("Líquido a Receber"):
            # try to parse value on next line or end of current line
            if idx + 1 < len(text_lines):
                val = text_lines[idx + 1].strip()
                candidate = _parse_value(val)
                if candidate is not None:
                    totals["liquido"] = candidate
            # sometimes the value appears on the same line
            parts = line_stripped.split()
            if totals["liquido"] is None and parts:
                maybe_val = _parse_value(parts[-1])
                totals["liquido"] = maybe_val
    # Parse month/year (Mês/Ano) field
    mes_ano_raw: str | None = None
    for i, line in enumerate(text_lines):
        if line.strip() == "Mês/Ano" and i + 1 < len(text_lines):
            mes_ano_raw = text_lines[i + 1].strip()
            break
    if not mes_ano_raw:
        raise ValueError("Campo 'Mês/Ano' não encontrado no PDF.")
    # Convert month/year to ISO key for chronological sorting
    # mes_ano_raw format: e.g. 'Outubro/2025'
    try:
        mes_nome, ano = mes_ano_raw.split("/")
        mes_num = MONTH_MAP.get(mes_nome.strip(), None)
        ano_num = int(ano.strip())
        if mes_num is None:
            mes_key = None
        else:
            mes_key = f"{ano_num:04d}-{mes_num:02d}-01"
    except Exception:
        mes_key = None
    return {
        "mes_ano": mes_ano_raw,
        "mes_key": mes_key,
        "items": items,
        "totals": totals,
    }


__all__ = ["parse_pdf"]