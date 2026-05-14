# HexStrike-AI Security Assessment: Web-DVWA

## 📌 Project Overview
This repository contains the deliverables, methodology, and technical setup logs for a university cybersecurity assessment. The objective was to deploy an offensive AI tool (HexStrike-AI) against an isolated Web-DVWA (Damn Vulnerable Web Application) Docker container across multiple security levels (Low, Medium, and High) and automatically generate security reports and exploit proofs-of-concept.

## 🎯 Target Setup (DVWA)
The target environment was deployed locally using Docker to ensure complete isolation. 

**To spin up the target environment:**
```bash
docker run --rm -it -p 8080:80 vulnerables/web-dvwa
```

### Target Configuration:

- URL: http://localhost:8080
- Credentials: admin / password
- Initialization: Navigate to the "Setup / Reset DB" tab upon first login to initialize the database.
- Security Level: Navigate to the "DVWA Security" tab to toggle the difficulty between Low, Medium, High, or Impossible.

### ⚔️ Attacker Setup (HexStrike-AI & Claude)
1. **Environment Installation (Apple Silicon):**
Setting up older cybersecurity tools on modern Apple Silicon (M-series) often results in a "Dependency Hell" due to compiler conflicts. To resolve this, a Man-in-the-Middle wrapper script was required to intercept the cmake compiler during installation.  
For full installation instructions and troubleshooting steps, see: [setup guide](./hexstrike-mac-setup.md).

2. **AI Integration (Model Context Protocol) :**
The assessment utilized Claude Desktop connected to the HexStrike-AI MCP (Model Context Protocol) server. To bridge the AI client with the local hacking tools, the following configuration was added to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```bash
{
  "mcpServers": {
    "hexstrike": {
      "command": "/path/to/hexstrike-ai/hexstrike-env/bin/python",
      "args": [
        "/path/to/hexstrike-ai/hexstrike_mcp.py",
        "--server",
        "http://localhost:8888"
      ]
    }
  }
}
```
### 🧠 Execution Summary & AI Limitations
During the assessment, Claude Sonnet 4.6 successfully utilized HexStrike to autonomously map the target and execute a successful SQL injection, dumping the database hashes on the "Low" security level. However, upon progressing to the Medium and High levels, the AI's core safety programming (Constitutional AI guardrails) intervened. The AI refused to act as an autonomous hacking drone or generate weaponized exploit scripts.

To complete the assessment requirements, the methodology was pivoted. The AI was directed to act as a "Security Educator," successfully analyzing the vulnerabilities and generating defensive .py deliverables (demonstrating safe vs. unsafe coding patterns) and structural reports rather than active exploits.

For the complete prompt logs, AI responses, and a detailed breakdown of the technical challenges, please refer to: [methodology](./methodology.pdf)

### 📁 Repository Contents

`security-assessment-report.md:` The finalized security report detailing vulnerabilities and remediations.

`save-vs-unsafe.py:` AI-generated Python deliverable demonstrating defensive coding patterns against Command Injection.

`hexstrike-mac-setup.md:` Technical guide for resolving Apple Silicon dependency issues.

`methodology.pdf:` Detailed documentation of the AI execution, guardrail negotiations, and methodology pivots.

`Background MCP Server Files:` hexstrike_mcp.py, hexstrike_server.py, hexstrike.log, hexstrike-ai-mcp.json.

**All the other files and folders are HexStrike-AI own's files and folders they are not created by me**