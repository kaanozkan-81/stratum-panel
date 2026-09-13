# Stratum Gateway — Web Panel

The management interface for **Stratum Gateway**, an enterprise-grade, self-hosted firewall and network security platform. This repository contains the Python/FastAPI backend and Jinja2 templates that power the panel's UI.

> **Repository status:** Private. This is the source snapshot for the Stratum Gateway management panel. It is not yet publicly distributed.

---

## What this is

The panel is a single-process web application that exposes every configuration surface of the gateway through a browser-based interface. It talks to the underlying system — nftables, Suricata, CrowdSec, Unbound, WireGuard, and the rest — through a combination of direct file access, CLI tool invocation, and systemd service management.

There is no cloud component. The panel runs on the same machine as the gateway, bound to a local interface, and authenticates users against a local credential store.

---

## Technology stack

| Layer | Component |
|---|---|
| Language | Python 3 |
| Web framework | FastAPI |
| ASGI server | Uvicorn (behind nginx) |
| Templating | Jinja2 |
| Sessions | Starlette SessionMiddleware (signed cookies) |
| Password hashing | bcrypt |
| System integration | `subprocess`, `nftables` CLI, systemd |
| Frontend | Server-rendered templates, vanilla JavaScript |

No JavaScript framework. No client-side build step. No database — state lives in files under `/etc/` and `/var/lib/`.

---

## Repository layout
