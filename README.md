# InfoSec News Agent

Agente de IA para buscar notícias de segurança da informação na internet (RSS), categorizar por tema e publicar via Docker.

## O que este projeto faz

- Coleta notícias de fontes reconhecidas de cibersegurança.
- Categoriza automaticamente em temas (Ransomware, Vulnerabilidades, Malware, etc).
- Exponibiliza API HTTP para consulta.
- Exibe um site no navegador para acompanhar notícias em tempo real.
- Atualiza automaticamente a base de notícias a cada 5 minutos.
- Roda em container com `docker compose`.

## Endpoints

- `GET /health`: status da aplicacao.
- `GET /sources`: lista completa das fontes de pesquisa (coletadas e referenciais).
- `GET /sources/stats`: quantidade de noticias por fonte no cache atual.
- `GET /categories`: categorias disponíveis para filtro.
- `GET /cves`: lista de CVEs detectadas nas notícias em cache.
- `GET /news?limit=30&hours=72&category=Malware&source=bleepingcomputer&cve=CVE-2025-12345&q=ransomware`: retorna notícias com filtros por categoria, fonte, CVE e texto.
- `GET /`: interface web do agente.

## Como executar com Docker

```bash
docker compose up -d --build
```

Se você já tinha um container antigo rodando, recrie para pegar as correções:

```bash
docker rm -f infosec-news-agent 2>/dev/null || true
docker build -t infosec-news-agent:local .
docker run -d --name infosec-news-agent -p 8000:8000 infosec-news-agent:local
```

Teste rapido:

```bash
curl "http://localhost:8000/health"
curl "http://localhost:8000/news?limit=10&hours=48"
```

Abrir no navegador:

- Site: `http://localhost:8000/`
- API interativa: `http://localhost:8000/docs`

## Fontes utilizadas

Inclui a lista enviada de fontes de segurança (noticias gerais, oficiais, threat intel, vendors, appsec e DFIR), com coleta ativa onde ha RSS/JSON confiavel e fonte referencial onde nao ha feed publico.

## Execução local (opcional)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Fontes RSS padrão

As fontes estão em `app/sources.py` e podem ser ajustadas conforme necessidade.
