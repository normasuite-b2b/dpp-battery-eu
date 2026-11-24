# EU Battery Passport Validator (`dpp-battery-eu`)

> **Online Browser Studio (100% Client-Side, Zero Upload):** [Open EU Battery Passport Studio →](https://normasuite-b2b.normasuite-b2b.workers.dev/battery-passport/)
> Generate **Auto-Repaired 3-Tier JSON-LD**, **GS1 Digital Link SVG Labels (`EN 18219`)**, and a **Printable Regulation (EU) 2023/1542 Pre-Audit PDF Certificate** directly in your browser without sending BOM secrets to third-party servers.

[![EU 2023/1542](https://img.shields.io/badge/EU%20Battery%20Reg-2023%2F1542-1d4ed8)](https://normasuite-b2b.normasuite-b2b.workers.dev/battery-passport/)
[![Mandatory Deadline](https://img.shields.io/badge/Mandatory%20Deadline-18%20Feb%202027-b45309)](https://normasuite-b2b.normasuite-b2b.workers.dev/battery-passport/)
[![Zero Dependencies](https://img.shields.io/badge/Python%20Dependencies-0-15803d)](#cli-usage)

Zero-dependency deterministic Python library, CLI, and browser studio validating **EU Battery Passports** against **Regulation (EU) 2023/1542 Annex XIII**, **CIRPASS-2** JSON-LD serialization, **EN 18219:2026** unique identifiers, and **EN 18222:2026** interoperability rules (mandatory **18 February 2027** for EV, LMT, and industrial batteries > 2 kWh).

## Browser Export Pack vs CLI Pre-Audit

| Capability | Open CLI (`dpp-battery-eu`) | Online Browser Studio |
| :--- | :---: | :---: |
| 26 deterministic Annex XIII & EN 18222 rules | Included | [Free Instant Audit](https://normasuite-b2b.normasuite-b2b.workers.dev/battery-passport/) |
| Tiered Access Leak Check (`Public` vs `Legitimate Interest` vs `Authorities`) | Included | [Free Instant Audit](https://normasuite-b2b.normasuite-b2b.workers.dev/battery-passport/) |
| GS1 GTIN-14 check-digit & EN 18219 Digital Link / URN validation | Included | [Free Instant Audit](https://normasuite-b2b.normasuite-b2b.workers.dev/battery-passport/) |
| **Auto-Repaired 3-Tier JSON-LD Export** | CLI `--repair-out` | [Browser Export Pack →](https://normasuite-b2b.normasuite-b2b.workers.dev/battery-passport/) |
| **GS1 Digital Link SVG Carrier Label (`EN 18219`)** | — | [Browser Export Pack →](https://normasuite-b2b.normasuite-b2b.workers.dev/battery-passport/) |
| **Printable Pre-Audit Compliance Certificate (PDF A4)** | — | [Browser Export Pack →](https://normasuite-b2b.normasuite-b2b.workers.dev/battery-passport/) |

## Quick CLI Usage

```bash
python -m dpp_battery_eu.cli validate samples/non_compliant_industrial.jsonld
python -m dpp_battery_eu.cli validate samples/compliant_ev_battery_2027.jsonld --json
python -m dpp_battery_eu.cli rules --json
```

Run tests locally (`0` external packages required):

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

## Live Online Tool

Need an immediate browser audit, SVG carrier label, and printable Annex XIII certificate?
Launch the zero-upload web studio: **[https://normasuite-b2b.normasuite-b2b.workers.dev/battery-passport/](https://normasuite-b2b.normasuite-b2b.workers.dev/battery-passport/)**
