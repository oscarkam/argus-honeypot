# T-Pot LLM Analyser

Generates plain-English threat intelligence reports from T-Pot honeypot data using a local LLM (Ollama + Llama 3.2).

Designed for non-technical audiences — turns raw attack telemetry into readable prose summaries suitable for security team leads, business stakeholders, or educational contexts.

## Architecture

Runs on the operator's laptop:
- **Ollama** (localhost:11434) provides local LLM inference (llama3.2:3b, ~3GB RAM footprint).
- **`analyzer.py`** queries T-Pot Elasticsearch (via SSH tunnel), formats attack telemetry into a structured prompt, and asks Ollama to generate a plain-English narrative.
- Reports are written as Markdown to `../reports/`.

## Setup

1. **Create venv and install dependencies**:
cd analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

2. **Copy and configure**:
cp config.example.yml config.yml

Edit config.yml — fill in Elasticsearch credentials from T-Pot install:
3. **Smoke-test Ollama connectivity** (no T-Pot needed):
python analyzer.py --test-ollama

## Usage (requires T-Pot to be live)

Open an SSH tunnel to expose T-Pot's Elasticsearch on your laptop's localhost:9200:

Terminal 1: SSH tunnel (from home/hotspot — campus WiFi blocks SSH)
ssh -L 9200:localhost:9200 -N -p 64295 ubuntu@<PUBLIC_IP>

Terminal 2: generate reports
source .venv/bin/activate
python analyzer.py --period daily
python analyzer.py --period weekly
python analyzer.py --period monthly

Reports appear in `../reports/`.

## Development status

- ✓ Ollama client — functional and tested
- ⧗ Elasticsearch query layer — stub (awaits live T-Pot schema)
- ⧗ Real report generation — blocked on above
- ⧗ Scheduled runs — future work (cron / systemd timer)