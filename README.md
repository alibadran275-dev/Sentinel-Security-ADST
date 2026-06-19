# Sentinel™ Real-Time Code Analyzer

Sentinel™ is a premium, full-stack Application Security Testing (AST) platform designed for modern DevSecOps workflows. It provides real-time vulnerability detection through both a high-performance Web Dashboard and a portable CLI tool.

## 🛡️ Core Capabilities

Sentinel focuses on identifying critical logical flaws and injection vulnerabilities, including:

- **Open Redirect Detection**: Identifies unvalidated redirection targets that could lead to phishing attacks.
- **IDOR (Insecure Direct Object Reference)**: Detects missing authorization checks on sensitive resource retrieval.
- **Parameter Tampering**: Flags critical application attributes (prices, roles, quantities) loaded directly from untrusted request parameters.
- **AI-Powered Deep Audit**: Leverages the Gemini 3.5 Flash engine to perform complex logical reasoning and generate security patches.
- **Attack Simulation Tree (ADST)**: Provides a visual representation of potential exploit vectors and their impacts.

## 🏗️ Architecture

- **Frontend**: React 19 + TypeScript + Tailwind CSS 4.0 + Lucide Icons + Motion (Framer Motion).
- **Backend**: Node.js + Express + Vite (SSR/Middleware mode) + Google Gemini SDK.
- **CLI Tool**: Python 3 + Rich (for terminal visualization).

## 🚀 Getting Started

### Prerequisites

- Node.js (v18+)
- Python (v3.10+)
- Google Gemini API Key (Optional, for Deep AI Audit)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/Sentinel-Security-ADST.git
   cd Sentinel-Security-ADST
   ```

2. **Install Dependencies**:
   ```bash
   # Install Node.js dependencies
   npm install

   # Install CLI dependencies
   pip install rich requests
   ```

3. **Environment Setup**:
   Create a `.env` file in the root directory:
   ```env
   GEMINI_API_KEY=your_api_key_here
   ```

### Running the Web Dashboard

Start the development server:
```bash
npm run dev
```
The dashboard will be available at `http://localhost:3000`.

### Running the CLI Tool

Analyze any file or directory directly from your terminal:
```bash
python sentinel.py <path-to-target>
```

## 📊 Attack Simulation Tree (ADST)

Sentinel™ introduces the **ADST** format, a hierarchical visualization that maps:
1. **Entry Point**: How an attacker interacts with the system.
2. **Exploit Vector**: The specific mechanism used to bypass security.
3. **Impact**: The ultimate consequence of a successful breach.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---
**Sentinel™ Security Engine v2.4** - *Stand Guard Over Your Code.*
