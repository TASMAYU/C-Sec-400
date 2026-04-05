# C-Sec-400 | AI Cyber Defence System for Banks

C-Sec-400 is an AI-powered security system that helps banks prevent cyber attacks. It uses a graph database (TigerGraph) to map the bank's entire computer network and Generative AI to predict how hackers would break in.

C-Sec-400 maps everything as a graph and uses AI to:
- Find attack paths before hackers do
- Predict exactly how an attacker would break in
- Generate step-by-step commands to fix vulnerabilities
- Simulate thousands of attacks to find weak spots

## How It Works

1. **TigerGraph** stores all bank assets, vulnerabilities, and network connections as a graph
2. **AI agents** read this graph and analyze attack possibilities


## Features (5 AI Agents)

| Agent | What it does |
|-------|--------------|
| **Pathfinder** | Finds the shortest attack path between two assets |
| **Predictor** | Predicts how a hacker would compromise an asset |
| **Remediator** | Generates commands to fix vulnerabilities |
| **RCA** | Explains why a security incident happened |
| **Red Team** | Simulates attacks to find weak points |

## Tech Stack

- **FastAPI** – Python backend framework
- **TigerGraph** – Graph database for connections
- **Groq** – LLM for AI predictions
- **Render** – For Hosting 

## Local Setup

```bash
# Clone the repo
git clone https://github.com/TASMAYU/C-Sec-400.git
cd C-Sec-400

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create .env file in backend folder
# Then run
cd backend
python main.py
