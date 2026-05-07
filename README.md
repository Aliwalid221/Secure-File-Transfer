# Secure File Transfer & Data Leakage Prevention (DLP) System

## Project Overview
This is a desktop application designed to provide secure local file encryption and prevent data leakage by enforcing organizational policies. It features zero-knowledge encryption (AES-256-GCM), automatic DLP policy enforcement, and secure local file sharing with expiration.

## Key Features
- **File Encryption Engine**: AES-256-GCM encryption for data-at-rest.
- **DLP Policy Engine**: Pattern matching for sensitive data (SSN, Credit Cards) and file type restrictions.
- **Secure File Sharing**: Local HTTP server for temporary, expiring download links.
- **Complete Audit Logging**: SQLite-based logging of all user operations and system events.
- **Local-first Design**: Encryption, policies, links, and logs all run on the user's machine.

## Technologies Used
- **Python 3**
- **PyQt5**: For the desktop graphical user interface.
- **PyCryptodome**: For high-standard AES-256-GCM encryption.
- **SQLite**: For local database and audit logging.
- **Flask**: For the local secure sharing server.

## Installation
1. Ensure you have Python 3.8+ installed.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
1. Run the application:
   ```bash
   python main.py
   ```
2. **Encrypt/Share**: Select a file, enter a password, and generate a local expiring link after DLP approval.
3. **Decrypt**: Provide the encrypted file and key to retrieve the original data.
4. **Audit Logs**: View the history of all operations in the 'Audit Logs' tab.

## Requirement Checklist
- AES-256-GCM file encryption: `crypto_engine.py`
- DLP pattern and file type rules: `dlp_engine.py` and SQLite policies
- Expiring encrypted sharing links: `sharing_server.py`
- Timestamped audit logs: `db_manager.py`

## Presentation Specifications
- **Duration**: 10-15 minutes.
- **Implementation**: Local-first, zero-cloud dependency.
- **Results**: Verified encryption integrity and DLP enforcement success.
