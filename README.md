<p align="center">
  <img src="https://img.shields.io/badge/Azure_Functions-v4-0078D4" alt="Azure Functions">
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB" alt="Python">
  <img src="https://img.shields.io/badge/Status-Active-success" alt="Status">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License">
</p>

<div align="center">
  <h1>🔐 Authentication Function App</h1>
  <p><em>Serverless Authentication & Authorization System</em></p>
</div>

---

## 📋 Table of Contents
- [📖 Overview](#-overview)
- [🎯 Learning Objectives](#-learning-objectives)
- [🛠️ Tech Stack](#️-tech-stack)
- [📁 Project Structure](#-project-structure)
- [🚀 Getting Started](#-getting-started)
- [💡 Usage](#-usage)
- [🏆 Key Features](#-key-features)
- [📚 Resources](#-resources)
- [👥 Contributors](#-contributors)

## 📖 Overview

This authentication app is a comprehensive serverless solution designed for exploring advanced authentication mechanisms in cloud-native environments using Azure Functions v4. Built with security-first principles, it demonstrates production-ready patterns for user management, JWT-based authentication, and scalable serverless architecture.

The application showcases modern cloud development practices including event-driven architecture, asynchronous processing, and microservices design patterns. It serves as both a learning resource and a reference implementation for building secure, scalable authentication systems on Azure.

**⚠️ Note**: This project is designed for educational and development purposes. While following security best practices, additional hardening may be required for production deployment.

## 🎯 Learning Objectives

Through this project, you will master:

- **Serverless Architecture**: Build and deploy production-ready Azure Functions with Python v2 programming model
- **Authentication Systems**: Implement JWT-based authentication with token blacklisting and session management
- **Cloud Security**: Apply security best practices including password hashing, rate limiting, and input validation
- **Azure Services Integration**: Leverage Azure Table Storage, Queue Storage, and Application Insights
- **Event-Driven Design**: Design asynchronous systems using queue triggers and timer-based functions
- **API Development**: Create RESTful APIs with proper error handling and response formatting
- **Testing Strategies**: Develop comprehensive test suites for serverless applications
- **System Architecture**: Design scalable, maintainable cloud-native applications

## 🛠️ Tech Stack

**Core Technologies:**
- **Azure Functions v4**: Serverless compute platform with Python v2 programming model
- **Python 3.9+**: Modern Python runtime with async/await support
- **PyJWT**: Industry-standard JWT token handling and validation
- **Azure SDK**: Native integration with Azure cloud services

**Development Tools:**
- **Azure Functions Core Tools**: Local development and testing
- **pytest**: Comprehensive testing framework
- **VS Code Azure Extension**: Enhanced development experience
- **Azure CLI**: Cloud resource management and deployment

**Azure Services:**
- **Azure Table Storage**: NoSQL data storage for user information
- **Azure Queue Storage**: Asynchronous message processing
- **Application Insights**: Monitoring, logging, and telemetry
- **Azure Key Vault**: Secure configuration and secrets management

## 📁 Project Structure

```
authentication-FA/
├── 📜 function_app.py          # Main Azure Functions application entry point
├── 🛡️ guard.py                 # JWT authentication middleware and guards
├── 🔧 helper_functions.py      # Utility functions for data operations
├── ⚡ rate_limit.py            # Rate limiting implementation
├── 📋 queue_triggers.py        # Queue-based trigger handlers
├── ⏰ active_cron_trigger.py   # Timer-based cleanup operations
├── 📋 requirements.txt         # Python dependencies
├── ⚙️ host.json               # Azure Functions configuration
├── 📖 README.md               # Project documentation
├── 🏗️ ARCHITECTURE.md         # System architecture documentation
├── 🎯 SKILLS-INDEX.md         # Learning objectives and skills catalog
└── 🧪 tests/                  # Test suite
    ├── test_helper_functions.py
    ├── test_queue_triggers.py
    ├── test_login.sh
    ├── test_register.sh
    ├── test_logout.sh
    └── test_others.sh
```

## How It Works

1. **User Registration**: When a user registers, the app checks for rate limiting (based on email, username, and IP address). If valid, a registration request is queued for further processing, including email verification.

2. **Login and Logout**: The user’s credentials are validated, and after successful authentication, a JWT token is issued. The logout process invalidates the session and blacklists the token.

3. **Queue-Based Processing**: User-related actions (like registration, login, password reset) are processed asynchronously using Azure Queues. This helps maintain system scalability and reliability.

4. **Email Confirmation**: The app uses another Azure Function app to handle user email confirmation. A confirmation token is generated upon registration and sent to the user.

5. **Rate Limiting**: The app ensures that both users (by username or email) and IP addresses do not exceed a set number of requests in a given period.

### Example of the `authenticate` decorator:

```python
def authenticate(func):
    @wraps(func)
    async def wrapper(req, *args, **kwargs):
        # Authentication logic goes here
        ...
    return wrapper
```

## Setup and Deployment

## Prerequisites

Before you begin, ensure you have the following installed on your local machine:

- **Azure Functions Core Tools**: For running and testing Azure Functions locally.
  - Install guide: [Install Azure Functions Core Tools](https://docs.microsoft.com/en-us/azure/azure-functions/functions-run-local)
- **Azure CLI**: For managing Azure resources from the command line.
  - Install guide: [Install Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- **Python 3.7+**: The authentication app is built using Python.
  - Download Python: [Python Downloads](https://www.python.org/downloads/)
- **Visual Studio Code (VS Code)** with the **Azure Functions Extension** (optional but recommended for local debugging).
  - Install VS Code: [Download Visual Studio Code](https://code.visualstudio.com/)
  - Azure Functions Extension: [Install Azure Functions Extension](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azurefunctions)

## Step 1: Clone the Authentication App Repository

1. Open your terminal and run the following command to clone the repository:

    ```bash
    git clone https://github.com/yungryce/authentication-FA.git
    cd authentication-app
    ```

2. Ensure you are on the correct branch (e.g., `master`) and that the repository is up to date:

    ```bash
    git checkout master
    git pull origin master
    ```

## Step 2: Set Up Your Local Environment

### 1. Install Required Python Packages

## 🚀 Getting Started

### Prerequisites

Before you begin, ensure you have the following installed on your local machine:

- **Azure Functions Core Tools v4**: For running and testing Azure Functions locally
  - Install: `npm install -g azure-functions-core-tools@4 --unsafe-perm true`
  - [Official Documentation](https://docs.microsoft.com/en-us/azure/azure-functions/functions-run-local)

- **Azure CLI**: For managing Azure resources from the command line
  - [Installation Guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)

- **Python 3.9+**: Required runtime for the function app
  - [Download Python](https://www.python.org/downloads/)
  - Verify: `python --version`

- **Visual Studio Code** (Recommended): Enhanced development experience
  - [Download VS Code](https://code.visualstudio.com/)
  - Install Azure Functions Extension: `ms-azuretools.vscode-azurefunctions`

### Installation

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd authentication-FA
   ```

2. **Set Up Python Environment**
   ```bash
   # Create virtual environment
   python -m venv .venv
   
   # Activate virtual environment
   # On Linux/macOS:
   source .venv/bin/activate
   # On Windows:
   .venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   ```

3. **Configure Local Settings**
   ```bash
   # Create local.settings.json (not included in repo for security)
   cp local.settings.json.template local.settings.json
   # Edit with your Azure connection strings and secrets
   ```

### Running the Project

1. **Start Function App Locally**
   ```bash
   func start
   ```

2. **Test the Endpoints**
   The function app will be available at `http://localhost:7071`
   
   Example registration request:
   ```bash
   curl -X POST http://localhost:7071/api/register \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser",
       "email": "test@example.com", 
       "password": "SecurePassword123",
       "first_name": "John",
       "last_name": "Doe"
     }'
   ```

3. **Run Tests**
   ```bash
   # Unit tests
   pytest tests/
   
   # Integration tests
   chmod +x tests/*.sh
   ./tests/test_register.sh
   ./tests/test_login.sh
   ```

## 💡 Usage

### Authentication Workflow

The system implements a comprehensive JWT-based authentication flow:

1. **User Registration**: Users register with email verification
2. **Login**: Credentials validation and JWT token issuance  
3. **Protected Routes**: JWT token validation for secure endpoints
4. **Logout**: Token blacklisting for secure session termination

### API Endpoints

#### Public Endpoints
- `POST /api/register` - User registration
- `POST /api/login` - User authentication
- `POST /api/verify` - Email verification
- `POST /api/forgot-password` - Password reset initiation

#### Protected Endpoints (Require JWT Token)
- `POST /api/logout` - User logout (requires `@authenticate` decorator)
- `POST /api/change-password` - Password change
- `DELETE /api/delete-user` - Account deletion
- `POST /api/resend-confirmation` - Resend verification email

### Queue Processing

The system uses Azure Queues for asynchronous processing:

```python
# Example: Queue message for user registration
{
    "action": "register_user",
    "user_data": {
        "username": "testuser",
        "email": "test@example.com",
        "confirmation_token": "abc123"
    }
}
```

### Rate Limiting

Built-in protection against abuse:
- **User-based**: 5 requests per minute per username/email
- **IP-based**: 10 requests per minute per IP address
- **Configurable**: Easily adjustable limits in `rate_limit.py`

## 🏆 Key Features

### 🔐 **Comprehensive Authentication**
- JWT-based stateless authentication
- Secure password hashing with BCrypt
- Token blacklisting for secure logout
- Email verification and account activation

### ⚡ **Serverless Architecture**
- Azure Functions v4 with Python v2 programming model
- Event-driven design with queue triggers
- Auto-scaling and pay-per-use pricing
- Timer-based cleanup operations

### 🛡️ **Advanced Security**
- Multi-tier rate limiting (user and IP-based)
- Input validation and sanitization
- CORS configuration and security headers
- Protection against common attack vectors

### 🔄 **Asynchronous Processing**
- Queue-based message processing
- Non-blocking user operations
- Email service integration
- Scalable workflow orchestration

### 🧪 **Comprehensive Testing**
- Unit tests with pytest
- Integration tests with shell scripts
- API endpoint testing
- Local development support

### 📊 **Monitoring & Observability**
- Application Insights integration
- Structured logging with JSON format
- Performance metrics and telemetry
- Error tracking and alerting

## 📚 Resources

### Documentation
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Detailed system architecture and design
- [SKILLS-INDEX.md](./SKILLS-INDEX.md) - Learning objectives and competencies
- [Azure Functions Documentation](https://docs.microsoft.com/en-us/azure/azure-functions/)
- [Python Developer Guide](https://docs.microsoft.com/en-us/azure/azure-functions/functions-reference-python)

### Related Projects
- Email Function App - Companion service for email operations
- Authentication Frontend - React/Angular client implementation examples
- Infrastructure as Code - ARM/Bicep templates for deployment

### Learning Resources
- [JWT Best Practices](https://tools.ietf.org/html/rfc7519)
- [Azure Functions Best Practices](https://docs.microsoft.com/en-us/azure/azure-functions/functions-best-practices)
- [Serverless Security Patterns](https://docs.microsoft.com/en-us/azure/architecture/patterns/)

## 👥 Contributors

**Primary Developer**: Authentication System Architect  
**Role**: Full-stack serverless developer with expertise in Azure cloud services  
**Focus**: Secure authentication systems and cloud-native architecture

### Contributing Guidelines
1. Fork the repository and create a feature branch
2. Follow PEP 8 Python coding standards
3. Add comprehensive tests for new functionality
4. Update documentation for API changes
5. Submit pull request with detailed description

### Current Limitations & Future Enhancements

**Known Limitations:**
- OAuth integration not yet implemented
- Educational project - additional hardening needed for production
- Single-region deployment (no global distribution)
- Basic error handling - comprehensive error management needed

**Planned Enhancements:**
- OAuth 2.0 and OpenID Connect integration
- Multi-factor authentication (SMS, TOTP)
- Advanced monitoring and alerting
- Infrastructure as Code templates
- Performance optimization and caching strategies

---

<div align="center">
  <p><em>🌟 Star this repository if it helped you learn serverless authentication!</em></p>
  <p>Built with ❤️ using Azure Functions and modern cloud-native practices</p>
</div>
