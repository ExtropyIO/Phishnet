# TEE Phishing Agent System

A comprehensive phishing detection and verification framework using **Trusted Execution Environments (TEE)** and **multi-agent architecture**, combining **Go-based secure computation** with **Python uAgents** orchestration.

---

## Project Overview

This system provides a **secure phishing detection pipeline** that analyzes digital artifacts (URLs, emails, Solana transactions, etc.) through a **trusted enclave**, producing **verifiable, cryptographically signed reports**. Results can be **verified externally** and optionally **logged on-chain**.

---

## Architecture Overview

### System Layers

| Layer                     | Technology              | Purpose                                                      |
| ------------------------- | ----------------------- | ------------------------------------------------------------ |
| **Agents Layer (Python)** | uAgents / Chat Protocol | Handles messaging, coordination, and blockchain interaction  |
| **Core Analysis (Go)**    | Go 1.22                 | Deterministic threat detection, signing, and TEE integration |
| **Blockchain Layer**      | Solana (optional)       | Immutable logging of verified reports                        |

---

### Agents Overview (Python)

| Agent             | Function                                                          |
| ----------------- | ----------------------------------------------------------------- |
| **IntakeAgent**   | Receives artifacts (URLs, emails, transactions) from users        |
| **AnalyzerAgent** | Sends artifacts to the Go analysis service, orchestrates analysis |
| **RefereeAgent**  | Verifies signatures and attestations from Go reports              |
| **OnchainAgent**  | Logs verified reports to blockchain (optional)                    |

Agents communicate using the **Chat Protocol**, each acting as a modular node in the system.

---

### Go Backend (TEE Core)

| Component              | Description                                                |
| ---------------------- | ---------------------------------------------------------- |
| **cmd/analyzer**       | HTTP API — exposes `/analyze` and `/verify` endpoints      |
| **cmd/enclave-server** | Vsock server for secure enclave or Nitro mock              |
| **internal/api**       | Data types, schemas, and JSON structures                   |
| **internal/analyzer**  | Core deterministic pipeline and signing logic              |
| **internal/detect**    | Extractors for URLs, emails, text, and Solana transactions |
| **internal/rules**     | Severity mapping engine (MeTTa integration planned)        |
| **internal/report**    | Canonical JSON + Ed25519 signing/verification              |
| **internal/vsock**     | Host/guest stubs (replace with real vsock library later)   |
| **internal/util**      | Utility functions (hashing, helpers)                       |
| **tests/golden**       | Golden test data for deterministic validation              |

---

## Team Structure

### Josh – Python Agents & Integration

* **Focus:** Agent orchestration, blockchain integration, and interface
* **Components:** `agents/`
* **Languages:** Python, uAgents
* **Next:** Integrate with Go analyzer API via REST

### Laurence – TEE & Core Go Development

* **Focus:** Secure enclave logic, Go backend, attestation
* **Components:** `cmd/`, `internal/`
* **Languages:** Go
* **Next:** Replace mock attestation with real Nitro/QEMU attestation

### Manar – Threat Identification & Rule Logic

* **Focus:** Phishing signal extraction and severity scoring
* **Components:** `internal/detect/`, `internal/rules/`
* **Languages:** Go, MeTTa (future)
* **Next:** Extend rule engine and test golden outputs

---

## Project Structure

```
tee-phishing-analyzer/
├── cmd/
│   ├── analyzer/              # Go HTTP API: POST /analyze, POST /verify
│   └── enclave-server/        # Go vsock guest server (mock attestation)
├── internal/
│   ├── api/                   # DTOs and JSON schemas
│   ├── analyzer/              # Deterministic pipeline & signing logic
│   ├── detect/                # URL/Text/Email/Solana extractors
│   ├── rules/                 # Severity engine (MeTTa-ready)
│   ├── report/                # Canonical JSON + signing/verify
│   ├── server/                # HTTP router/handlers
│   ├── vsock/                 # Host/guest stubs
│   └── util/                  # Misc utilities
├── agents/                    # Python uAgents layer
│   ├── intake_agent.py
│   ├── analyzer_agent.py
│   ├── referee_agent.py
│   └── onchain_agent.py
├── solana/                    # Optional Anchor program for on-chain logging
│   ├── program/
│   └── client/
├── tests/
│   └── golden/                # Deterministic output comparisons
├── Makefile
├── go.mod
└── README.md
```

---

## Getting Started

### 1. Build and Run the Go Backend

```bash
make build
./bin/analyzer
```

* Runs HTTP API at `http://localhost:8080`
* Endpoints:

  * `POST /analyze` → returns signed JSON report + mock attestation
  * `POST /verify` → verifies signature (TEE attestation coming soon)

### 2. Run Python Agents

```bash
cd agents
pip install -r requirements.txt
python intake_agent.py
```

Agents will communicate with the Go backend over HTTP.

### 3. (Optional) Deploy Solana Program

Compile and deploy your Anchor program, then link the `OnchainAgent` to push verified reports.

---

## Security Features

* **TEE Attestation:** Verifiable enclave execution (mocked now, replaceable)
* **Canonical JSON Signing:** Ed25519-based deterministic signing
* **Immutable Logging:** Optional Solana blockchain log
* **Integrity Verification:** `/verify` ensures signature and attestation validity

---

## Workflow Summary

1. User submits an artifact to `IntakeAgent`
2. `AnalyzerAgent` sends it to the Go backend (`/analyze`)
3. The Go backend produces a deterministic signed report
4. `RefereeAgent` validates report and attestation (`/verify`)
5. `OnchainAgent` optionally logs the result to blockchain
6. User receives a verified verdict and cryptographic signature


