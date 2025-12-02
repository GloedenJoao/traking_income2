# Aplicação de Acompanhamento de Demonstrativos de Pagamento

Esta aplicação web, escrita em Python usando Flask, permite que o usuário carregue demonstrativos de pagamento em PDF, armazene as informações em um banco de dados SQLite e visualize dados agregados por meio de consultas e dashboards interativos.

## Pré‑requisitos

Para executar a aplicação, é necessário ter instalado:

* Python 3.9 ou superior
* As bibliotecas Python `Flask`, `PyMuPDF` (pacote `pymupdf`) e `plotly`. Em muitas distribuições estas bibliotecas já se encontram disponíveis. Caso contrário, instale-as com `pip`:

```bash
pip install flask pymupdf plotly
```

## Inicialização

1. Clone ou copie este repositório para a sua máquina local.
2. No diretório raiz do projeto, execute o arquivo `app/app.py` para iniciar o servidor Flask. O comando abaixo cria o banco de dados automaticamente se ele ainda não existir:

```bash
python3 -m app.app
```

3. A aplicação ficará acessível em `http://localhost:5000/`.

## Uso

1. **Login**: O acesso agora é autenticado. Utilize o usuário padrão `admin` (senha `admin`) ou crie um novo cadastro na tela de registro. Contas comuns visualizam apenas seus próprios arquivos; o administrador pode filtrar por qualquer usuário.
2. **Upload**: Acesse a página inicial e utilize o formulário para enviar arquivos PDF. Somente arquivos com extensão `.pdf` são aceitos. Após o envio, o arquivo é armazenado no diretório `app/data/`, processado e suas informações são inseridas no banco de dados. O administrador pode atribuir o upload a outro usuário pelo seletor da página.
3. **Consulta**: Na aba “Consulta”, selecione um mês disponível para listar todos os itens (descrição, quantidade, unidade, proventos e descontos) daquele período. A página exibe também os totais consolidados de proventos, descontos e valor líquido do mês selecionado. Administradores podem aplicar filtro por usuário.
4. **Dashboard**: A aba “Dashboard” apresenta uma série histórica com os totais de proventos, descontos e valor líquido ao longo dos meses processados. Também exibe um gráfico de barras com a composição dos proventos e descontos do mês mais recente. O filtro de usuário está disponível para administradores.
5. **Exclusão**: Na página inicial, cada arquivo carregado possui um botão “Excluir”. Ao utilizá‑lo, o arquivo é removido do diretório de uploads e todos os registros associados são apagados do banco de dados, respeitando as permissões do usuário logado.

## Estrutura do projeto

* `app/` – Contém o código fonte da aplicação Flask.
  * `app.py` – Define as rotas, inicializa o banco e executa o servidor.
  * `parse_utils.py` – Funções para extração de dados dos PDFs.
  * `templates/` – Arquivos HTML Jinja2.
  * `data/` – Diretório onde os PDFs enviados são armazenados.
  * `database.db` – Arquivo SQLite criado automaticamente.
  * `AGENTS.MD` – Guia para manutenção e evolução do código.

## Observações

* A aplicação foi desenvolvida para demonstrativos que seguem o mesmo padrão dos arquivos de exemplo. Caso novos layouts sejam utilizados, será necessário ajustar o parser em `parse_utils.py`.
* O banco de dados utiliza apenas duas tabelas conforme solicitado: uma com todos os itens de cada demonstrativo e outra com os totais por demonstrativo. Os dados agregados por mês são calculados a partir dessas tabelas.

Para quaisquer dúvidas ou problemas, consulte o guia `AGENTS.MD` e os comentários espalhados no código.