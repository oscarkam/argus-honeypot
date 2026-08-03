# ARGUS

An AI-assisted threat intelligence platform for automated cloud-hosted honeypot telemetry visualisation and framework-mapped reporting.

ARGUS deploys a multi-sensor honeypot to cloud infrastructure using Infrastructure-as-Code, ingests the resulting attack telemetry, classifies it against three cybersecurity frameworks, and produces analyst-ready reports in Markdown, PDF and Word formats. A locally hosted language model generates prose interpretation without transmitting telemetry to any external service.

---

## Overview

Honeypots capture high-fidelity attacker behaviour, but most deployments stop at log storage. The analytical work of turning raw telemetry into usable intelligence is left to the operator, which limits their practical value for small teams, students and organisations without a dedicated security operations centre.

ARGUS addresses this by adding three layers on top of an established sensor distribution:

- **An analytical layer** classifying observed activity against MITRE ATT&CK, the Lockheed Martin Cyber Kill Chain, and the NIST Cybersecurity Framework
- **A narrative layer** using a locally hosted language model to translate classified statistics into readable prose
- **An accessibility layer** presenting the results through a plain-language interface, alongside the expert-tier analytical interface for users who need it

---

## Architecture

The system is organised into four planes, each a distinct trust boundary.

| Plane | Function | Components |
|---|---|---|
| **Deception** | Presents exposed services and captures adversary interaction | T-Pot Community Edition 24.04, 24 honeypot services on isolated container networks |
| **Ingestion** | Normalises and indexes captured telemetry | Logstash, Elasticsearch, GeoIP and ASN enrichment |
| **Analytical** | Classifies, interprets and reports | ARGUS analyser, framework mappers, Ollama inference, report pipeline |
| **Accessibility** | Presents results to the operator | ARGUS Control Center, Kibana |

The deception plane runs on a cloud instance with ingress restricted to six ports. The analytical and accessibility planes run on the operator workstation and reach the cloud instance over an SSH tunnel. No inbound path exists from the deception plane to the operator workstation.

---

## Requirements

**Operator workstation**

| Component | Version |
|---|---|
| Terraform | 1.14.3 |
| Ansible | 2.19 |
| Python | 3.12 |
| Ollama | 0.32.5 |
| pandoc | 3.1.3 |
| XeLaTeX | TeX Live 2023 |

**Cloud account**

An AWS account with permission to create VPC, EC2, Elastic IP and IAM resources. The deployment provisions a `t3.xlarge` instance with a 128 GiB volume.

**Optional**

API keys for AbuseIPDB, VirusTotal and GreyNoise, required only for the external validation module.

---

## Deployment

### 1. Clone and configure

```bash
git clone https://github.com/oscarkam/argus-honeypot
cd argus-honeypot
cp analyzer/config.example.yml analyzer/config.yml
cp infra/ansible/vars/tpot_secrets.example.yml infra/ansible/vars/tpot_secrets.yml
```

Edit both files with your own values. Neither is tracked by git.

### 2. Provision infrastructure

```bash
cd infra/terraform
terraform init
terraform plan
terraform apply
```

Terraform outputs the instance identifier, public address and connection string.

### 3. Install the sensor

```bash
cd ../ansible
# update inventory with the address from the previous step
ansible-playbook -i inventory site.yml
ansible-playbook -i inventory install_tpot.yml
```

Installation takes approximately 20 minutes. The instance reboots on completion.

### 4. Prepare the analyser

```bash
cd ../../analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ollama pull llama3.2:3b
```

---

## Configuration

`analyzer/config.yml` controls the analyser. Key sections:

| Key | Purpose |
|---|---|
| `elasticsearch.hosts` | Index endpoint, normally `http://localhost:9200` through the tunnel |
| `ollama.host` | Inference endpoint |
| `ollama.model` | Model identifier, default `llama3.2:3b` |
| `ollama.temperature` | Sampling temperature, default `0.3` |
| `report.organization` | Name appearing in generated report headers |

Environment variables, set in your shell profile and never committed:

```bash
export ABUSEIPDB_API_KEY="..."
export VIRUSTOTAL_API_KEY="..."
export GREYNOISE_API_KEY="..."
export ARGUS_OPERATOR_IP="..."   # your admin source address, excluded from analysis
```

---

## Usage

### Start a session

```bash
./scripts/session-start.sh
```

Starts the instance if suspended, establishes the SSH tunnel, and verifies that the index and inference service are reachable.

### Generate a report from the command line

```bash
cd analyzer
source .venv/bin/activate
python analyzer.py --period monthly --style full --theme light
```

| Flag | Values |
|---|---|
| `--period` | `daily`, `weekly`, `monthly` |
| `--style` | `brief`, `full` |
| `--theme` | `dark`, `light` |

Output is written to `reports/` as Markdown, PDF and Word.

### Launch the Control Center

```bash
./scripts/argus-web.sh
```

Opens at `http://localhost:8501` with five views: Home, Report Studio, Reports Archive, T-Pot Bridge and System Health.

### Validate captured addresses

```bash
cd analyzer
python validate_ips.py --population-audit --hours 720
python validate_ips.py --live --stratified --top-n 100 --tail-n 100 --hours 720
```

The first command reports how much captured telemetry originates from platform infrastructure rather than external sources. The second cross-references a stratified sample of source addresses against external threat intelligence feeds.

### Suspend the instance

```bash
./scripts/instance-stop.sh
```

Compute charges stop; storage and address charges continue.

---

## Repository structure

```
infra/
  terraform/        Infrastructure definitions: network, compute, addressing, identity
  ansible/          Sensor installation and configuration playbooks
analyzer/
  analyzer.py       Pipeline entry point
  es_client.py      Index query layer
  frameworks/       ATT&CK, Kill Chain and CSF classifiers
  charts.py         Chart rendering
  exporters.py      Document conversion
  metrics.py        Pipeline instrumentation
  validate_ips.py   External threat intelligence validation
  templates/        Report templates
  prompts/          Language model prompt templates
argus_web/          Control Center application
scripts/            Session lifecycle helpers
docs/               Architecture and troubleshooting documentation
```

---

## Security notes

- Ingress is restricted to six deception ports plus two administrative ports. The sensor distribution's default configuration exposes a wider range; this deployment does not.
- Administrative SSH is relocated from port 22. Port 22 exposes a deception service.
- Each deception service runs on a dedicated container network with a distinct subnet, so no service shares a layer-two or layer-three path with another.
- `config.yml`, `tpot_secrets.yml`, Terraform state and all credential material are excluded from version control.
- The deployment is intended for controlled research use. Operating an internet-facing honeypot on a network you do not control, or without the authority to expose it, is not appropriate.

---

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## Acknowledgements

Built on [T-Pot Community Edition](https://github.com/telekom-security/tpotce) by Telekom Security, which provides the sensor and indexing infrastructure. ARGUS contributes the analytical, narrative and accessibility layers above it.

---

## Licence

See [LICENSE](LICENSE).
