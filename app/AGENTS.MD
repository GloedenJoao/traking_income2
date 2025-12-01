# Guia de manutenção para agentes futuros

**Este documento deve ser atualizado sempre que alterações significativas forem feitas no código.**

O objetivo deste projeto é fornecer uma aplicação web simples para ingestão, armazenamento e visualização de demonstrativos de pagamento em formato PDF. O código foi estruturado visando facilitar sua compreensão e evolução por outros agentes. Abaixo estão algumas diretrizes para modificar ou estender a aplicação.

## Estrutura geral

* `app.py` – Arquivo principal da aplicação Flask. Define rotas para upload, consulta e dashboard, inicializa o banco de dados SQLite e instancia o servidor.
* `parse_utils.py` – Conjunto de utilitários para extrair dados dos PDFs utilizando a biblioteca PyMuPDF. Caso o layout dos demonstrativos mude ou novos campos sejam adicionados, este arquivo deve ser ajustado.
* `templates/` – Contém os arquivos Jinja2 usados para renderizar as páginas. Utilize estes arquivos como base caso novas páginas ou componentes visuais sejam necessários.
* `data/` – Diretório onde os PDFs enviados são armazenados. As rotas de upload e exclusão operam sobre este diretório.
* `database.db` – Banco SQLite onde os dados são persistidos. As tabelas são criadas automaticamente em tempo de execução.

## Adicionando novos campos ou relatórios

1. **Atualize o parser** – Se um novo demonstrativo contiver colunas diferentes ou novas seções, ajuste `parse_utils.py` para capturar corretamente esses campos. Verifique os limites das colunas e as regras de parada utilizadas no parsing.
2. **Modifique o banco de dados** – Caso sejam necessárias novas colunas, adicione-as nas declarações de criação de tabelas em `app.py` dentro da função `init_db()`. Lembre-se de escrever migrações apropriadas para bancos existentes se a aplicação já estiver em produção.
3. **Ajuste as rotas e templates** – Para exibir ou manipular os novos dados, crie ou modifique rotas em `app.py` e ajuste os templates em `templates/` para incluir os novos campos. Siga o padrão das páginas já existentes para garantir consistência.
4. **Atualize o dashboard** – Para adicionar novas visualizações, utilize a biblioteca Plotly no endpoint `/dashboard`. Gere os dados a partir do banco e serialize as figuras para o template. Não esqueça de atualizar a função `get_aggregated_series()` ou criar novas funções agregadoras conforme necessário.

## Comentários no código

Comentários descritivos foram incluídos em pontos estratégicos do código para auxiliar no entendimento do fluxo. Sempre que novas funcionalidades forem implementadas ou quando existir alteração de lógica relevante, **atualize ou adicione comentários** explicativos próximos ao trecho modificado. Isso ajuda a garantir que futuros agentes compreendam o racional das mudanças.

## Boas práticas

* **Consistência** – Mantenha a organização de diretórios e nomenclatura de arquivos. Caso crie novos módulos, preferencialmente agrupe utilidades em subpastas para manter a coesão.
* **Validação** – Sempre valide as entradas de usuários (por exemplo, arquivos enviados) e trate erros de parsing ou de banco de dados de forma a informar o usuário sem expor informações sensíveis.
* **Testes manuais** – Após alterações significativas, execute a aplicação localmente e realize uploads, consultas e exclusões para garantir que tudo continua funcionando como esperado.
* **Documentação** – Se adicionar endpoints ou comandos novos, documente-os neste arquivo e, se necessário, atualize o `README.md` com instruções de uso.

Seguindo estas orientações, esperamos que a manutenção e expansão desta aplicação seja simples e segura. Em caso de dúvidas, leia o código existente e os comentários para entender as motivações de cada escolha de design.