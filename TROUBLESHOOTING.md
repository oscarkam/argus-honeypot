# Troubleshooting

Problems encountered during deployment and operation, with resolutions.

---

## SSH to port 64295 times out

**Cause:** many institutional and corporate networks block outbound connections on non-standard ports.

**Fix:** connect from a network without egress filtering, or use AWS Systems Manager Session Manager, which requires no inbound port.

```bash
aws ssm start-session --target <instance-id> --region <region>
```

---

## T-Pot installation fails or installs the wrong edition

**Cause:** the installer requires explicit flags in unattended mode.

**Fix:**

```bash
sudo ./install.sh -s -t h -u <user> -p <password>
```

`-t h` selects the HIVE edition. Omitting it produces an interactive prompt that stalls the playbook.

---

## Elasticsearch unreachable at localhost:9200

**Cause:** the tunnel is not established. The index binds to `localhost:64298` on the instance and is not exposed externally by design.

**Fix:**

```bash
ssh -p 64295 -N -L 9200:localhost:64298 <user>@<instance-ip>
```

Verify:

```bash
curl -s localhost:9200/_cluster/health
```

---

## Ollama unreachable from WSL2

**Cause:** Ollama running on Windows binds to the Windows host, not the WSL2 network namespace.

**Fix:** point the analyser at the Windows host address rather than localhost.

```bash
ip route show | grep default | awk '{print $3}'
```

Set the resulting address as `ollama.host` in `config.yml`, port 11434.

---

## PDF export fails, DOCX succeeds

**Cause:** missing XeLaTeX, or a table exceeding the page margin.

**Fix:**

```bash
sudo apt install texlive-xetex texlive-fonts-recommended
```

Margin and table sizing are handled by `analyzer/templates/pdf_header.tex`. If tables still overflow, widen the margin there.

---

## Tables render as raw pipe characters in PDF or DOCX

**Cause:** a template loop emitting a blank line inside a table, which pandoc reads as a paragraph break.

**Fix:** use whitespace control on every loop wrapping a table row.

```jinja
{%- for row in rows %}
| {{ row.a }} | {{ row.b }} |
{%- endfor %}
```

---

## API keys not visible to Python despite being set

**Cause:** activating a virtual environment in a new shell does not re-read the shell profile.

**Fix:**

```bash
source ~/.bashrc
python -c "import os; print(bool(os.getenv('ABUSEIPDB_API_KEY')))"
```

---

## Validation returns fewer addresses than requested

**Cause:** a terms aggregation size cap in the query layer limits results before sampling.

**Fix:** raise the `size` parameter in the relevant aggregation in `analyzer/es_client.py`.

---

## GreyNoise returns no data for every address

**Cause:** the Community tier daily quota is exhausted.

**Fix:** wait for quota reset, or proceed with the remaining feeds. The validation module records the error per address and continues rather than aborting.

---

## Terraform apply succeeds but state is not committed

**Cause:** applying before committing leaves the repository inconsistent with deployed infrastructure.

**Fix:** commit configuration before applying. If state and configuration have already diverged, `terraform plan` reports the difference.

---

## Instance stopped but charges continue

**Expected.** Suspending an instance stops compute charges. Storage and the associated static address continue to accrue.

To eliminate them, release the address and snapshot the volume, accepting a longer resumption time and a changed public address.
