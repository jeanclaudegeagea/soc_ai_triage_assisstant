# 🛡️ SOC AI Triage Assistant

An ethical AI-powered Security Operations Center (SOC) assistant designed for defensive log analysis. This tool provides role-adaptive explanations and maintains focus on security-oriented conversations with built-in ethical guardrails.

## 📋 Project Overview

The SOC AI Triage Assistant is a full-stack application that helps security analysts automatically analyze and triage security logs. It uses LLMs (via LangChain and Groq) to identify threats and provide contextual explanations tailored to the user's role.

### Key Features

- **Role-Based Analysis**: Adaptive explanations for Junior analysts, Experts, and C-level executives
- **Security Log Analysis**: Upload and analyze logs in TXT, LOG, or CSV formats
- **Pattern Detection**: Identify security patterns like brute force attacks, suspicious logins, etc.
- **Ethical AI**: Built-in guardrails to ensure defensive-only usage
- **Interactive Chat**: Continuous SOC-oriented conversations for deeper analysis
- **Health Checks**: API health monitoring and service status

## 🏗️ Project Structure

```
soc_assistant/
├── backend/                    # FastAPI backend service
│   ├── app.py                 # Main FastAPI application
│   ├── models.py              # Data models and schemas
│   ├── requirements.txt       # Backend dependencies
│   ├── ethics/
│   │   └── guardrails.py      # Ethical AI guardrails
│   ├── prompts/
│   │   ├── analyze_prompt.py  # Log analysis prompts
│   │   └── chat_prompt.py     # Chat conversation prompts
│   ├── routers/
│   │   └── chat.py            # Chat API endpoints
│   └── services/
│       └── llm.py             # LLM integration (LangChain)
├── frontend/                   # Streamlit UI
│   ├── app.py                 # Main Streamlit application
│   └── requirements.txt       # Frontend dependencies
└── README.md                  # This file
```

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+**
- **pip** (Python package manager)
- **Groq API Key** (for LLM access) - Get one at [console.groq.com](https://console.groq.com)

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd soc_assistant
   ```

2. **Create a `.env` file** in the `backend` directory with your Groq API key:

   ```
   GROQ_API_KEY=your_api_key_here
   ```

3. **Install backend dependencies**

   ```bash
   cd backend
   pip install -r requirements.txt
   ```

4. **Install frontend dependencies**
   ```bash
   cd ../frontend
   pip install -r requirements.txt
   ```

## 🎯 Running the Project

The application consists of two components that must be run simultaneously:

### Option 1: Using Terminal Commands (Recommended)

**Terminal 1 - Start the Backend (FastAPI)**

```bash
cd backend
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

The backend will be available at `http://localhost:8000`

- API Documentation: `http://localhost:8000/docs` (Swagger UI)
- Health Check: `http://localhost:8000/`

**Terminal 2 - Start the Frontend (Streamlit)**

```bash
cd frontend
streamlit run app.py
```

The frontend will be available at `http://localhost:8501`

### Option 2: Quick Start Script

Create a batch file (`run.bat` on Windows) or shell script (`run.sh` on Linux/Mac):

**Windows (run.bat)**

```batch
@echo off
start cmd /k "cd backend && uvicorn app:app --reload --host 0.0.0.0 --port 8000"
timeout /t 2
start cmd /k "cd frontend && streamlit run app.py"
```

**Linux/Mac (run.sh)**

```bash
#!/bin/bash
cd backend && uvicorn app:app --reload --host 0.0.0.0 --port 8000 &
sleep 2
cd ../frontend && streamlit run app.py
```

## 📖 Usage Guide

### Through the Web Interface

1. **Open Streamlit UI**: Navigate to `http://localhost:8501`
2. **Select Your Role**:
   - **Junior**: Detailed, educational explanations
   - **Expert**: Technical, in-depth analysis
   - **CEO**: High-level, business-focused summaries
3. **Upload Security Logs**: Select a TXT, LOG, or CSV file containing security events
4. **Add Detection Pattern** (optional): Specify what you're looking for (e.g., "brute force")
5. **Click "Analyze Logs"**: The AI will process and provide role-tailored analysis
6. **Continue the Conversation**: Ask follow-up questions in the chat interface

### Through the API

**Health Check**

```bash
curl http://localhost:8000/
```

**Response:**

```json
{
  "status": "ok",
  "service": "SOC AI Triage Assistant",
  "mode": "defensive-only",
  "ethics": "enabled"
}
```

**Chat Endpoint** (See API docs at `http://localhost:8000/docs` for detailed specifications)

## 🔐 Architecture

### Backend Components

- **FastAPI Server**: RESTful API for log analysis and chat
- **LangChain Integration**: Manages LLM interactions with Groq
- **Ethical Guardrails** (`ethics/guardrails.py`): Ensures defensive-only usage
- **Role-Based Prompts** (`prompts/`): Customized analysis templates
- **Data Models** (`models.py`): Request/response schemas

### Frontend Components

- **Streamlit UI**: Interactive web interface for easy access
- **Session Management**: Maintains chat history and analysis state
- **File Upload**: Support for multiple log file formats
- **Role Selection**: Dynamic UI adaptation based on user role

## 🛠️ Configuration

### Environment Variables

Create a `.env` file in the `backend` directory:

```env
# Groq API Configuration
GROQ_API_KEY=<your-groq-api-key>
GROQ_MODEL=mixtral-8x7b-32768  # or your preferred model

# Optional: API Configuration
API_HOST=0.0.0.0
API_PORT=8000
```

### Streamlit Configuration

Create `.streamlit/config.toml` in the `frontend` directory (optional):

```toml
[client]
showErrorDetails = true

[logger]
level = "info"
```

## 🧪 Testing

To verify the setup is working:

1. Check backend health:

   ```bash
   curl http://localhost:8000/
   ```

2. View API documentation:
   Open `http://localhost:8000/docs` in your browser

3. Upload a test log file through the Streamlit interface and verify analysis completes

## 📦 Dependencies

### Backend

- **fastapi**: Web framework
- **uvicorn**: ASGI server
- **langchain**: LLM orchestration
- **langchain-groq**: Groq provider for LangChain
- **python-dotenv**: Environment variable management
- **pydantic**: Data validation

### Frontend

- **streamlit**: Web UI framework
- **requests**: HTTP client for API communication

## 🔒 Ethical Guidelines

This assistant includes built-in ethical guardrails to ensure responsible usage:

- **Defensive-Only Mode**: Designed exclusively for defensive security analysis
- **Guardrail Checks** (`ethics/guardrails.py`): Validates requests before processing
- **Role-Based Filtering**: Appropriate information disclosure per role
- **Transparent Operations**: All analysis and reasoning is auditable

## 🐛 Troubleshooting

### Backend Won't Start

- Ensure Python 3.9+ is installed: `python --version`
- Check all dependencies are installed: `pip list`
- Verify GROQ_API_KEY is set in `.env`
- Try running without `--reload` flag

### Frontend Can't Connect to Backend

- Verify backend is running at `http://localhost:8000`
- Check there are no port conflicts (8000 for backend, 8501 for frontend)
- Try clearing Streamlit cache: `streamlit cache clear`

### API Endpoint Errors

- Check API documentation at `http://localhost:8000/docs`
- Verify request format matches expected schema
- Check backend logs for detailed error messages

## 📝 Development Notes

- The project uses relative imports - ensure you're running from the correct directory
- All LLM interactions are logged for audit purposes
- Chat history is maintained in session state during the frontend session

## 📄 License

Specify your project license here.

## 👥 Contributing

Specify contribution guidelines here.

## 📞 Support

For issues or questions, please contact the development team or open an issue in the repository.

---

**Version**: 1.0.0
