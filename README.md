# CP2 Honeypot IaC

Capstone Project 2: Automated Low-Interaction Honeypot with Threat Intelligence Visualization.

## Overview

Infrastructure-as-Code and analyser components for a cloud-deployed honeypot using:

- **Terraform** — AWS infrastructure provisioning (Singapore region)
- **Ansible** — T-Pot Community Edition deployment and OS hardening
- **ELK Stack** — log collection, normalization, dashboarding
- **Ollama (local LLM)** — plain-English threat report generation for non-expert users

## Structure

| Directory | Contents |
|---|---|
| `docs/` | Logbook, MSD (Master State Document), viva defence cards, pitfalls log |
| `infra/terraform/` | AWS EC2 + security group + VPC provisioning |
| `infra/ansible/` | T-Pot installation, hardening, ELK configuration playbooks |
| `elk/` | Custom Logstash filters, Kibana dashboard exports |
| `analyzer/` | Python + Ollama report generator |
| `reports/` | Generated daily/weekly/monthly threat reports |

## Author

Oscar Kam Gen Jynn (22064430)
BSc (Hons) Information Technology (Computer Networking and Security), Sunway University

Supervisor: Associate Professor Dr. Morteza SaberiKamarposhti

## Status

Active development. Submission target: 30 July 2026. Viva: 10-14 August 2026.