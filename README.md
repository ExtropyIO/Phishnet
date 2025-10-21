# TEE Phishing Agent System

A comprehensive phishing detection system using Trusted Execution Environment (TEE) technology with multi-agent architecture for secure artifact analysis and verification.

## Project Overview

This system implements a secure phishing detection pipeline that analyzes artifacts (URLs, emails, transactions) through a trusted execution environment, providing verifiable results with blockchain logging capabilities.

## Architecture

The system consists of multiple agents working together:

- **IntakeAgent**: Initial artifact processing and user interface
- **AnalyzerAgent**: Orchestrates analysis workflow
- **RefereeAgent**: Verifies analysis results and attestations
- **OnchainAgent**: Handles blockchain transactions for immutable logging
- **HostAPI**: Interface between agents and TEE
- **Enclave**: Secure computation environment for threat analysis

## Team Structure

### Josh - Python Agents & Integration
- **Focus**: Python agent development, blockchain integration, user interface
- **Components**: IntakeAgent, AnalyzerAgent, RefereeAgent, OnchainAgent
- **Directory**: `agents/`

### Laurence - TEE Development
- **Focus**: Trusted Execution Environment, secure computation, attestation
- **Components**: HostAPI, Enclave, TEE infrastructure
- **Directory**: `tee/`

### Manar - Threat Identification
- **Focus**: Phishing detection algorithms, threat scoring, analysis logic
- **Components**: Threat detection models, scoring algorithms, analysis engines
- **Directory**: `threat_detection/`

## Project Structure

```
PhishingHackathon/
├── agents/                    # Josh's Python agents
│   ├── intake_agent.py
│   ├── analyzer_agent.py
│   ├── referee_agent.py
│   └── onchain_agent.py
├── tee/                      # Laurence's TEE components
│   ├── host_api.py
│   └── enclave/              # Secure computation environment
│       ├── analyzer.py
│       └── attestation.py
├── threat_detection/         # Manar's threat analysis
│   ├── scoring_engine.py
│   └── models/               # Threat detection models
│       ├── url_analyzer.py
│       ├── email_analyzer.py
│       ├── transaction_analyzer.py
│       └── text_analyzer.py
├── shared/                   # Shared components
│   ├── config/
│   │   └── settings.py
│   ├── utils/
│   │   └── crypto_utils.py
│   └── schemas/
│       └── artifact_schema.py
├── tests/                    # Test files
│   ├── test_agents.py
│   ├── test_tee.py
│   └── test_threat_detection.py
└── README.md
```

## Getting Started

1. **Setup Environment**: Install Python dependencies and configure environment
2. **Configure TEE**: Set up TEE environment (Laurence)
3. **Initialize Agents**: Start Python agents (Josh)
4. **Load Models**: Initialize threat detection models (Manar)

## Security Features

- **TEE Attestation**: Cryptographic proof of secure execution
- **Immutable Logging**: Blockchain-based audit trail
- **Verifiable Results**: Cryptographic signatures on all outputs
- **Secure Communication**: Encrypted channels between components

## Workflow

1. User submits artifact to IntakeAgent
2. AnalyzerAgent coordinates with HostAPI for TEE analysis
3. Enclave performs secure threat analysis
4. Results are signed and attested
5. RefereeAgent verifies attestations
6. OnchainAgent logs results to blockchain (optional)