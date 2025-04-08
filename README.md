# AxcelT-passintel
A lightweight Python-based password auditing tool that checks password strength and breach status using a custom AWS Lambda API and the HaveIBeenPwned service. Prioritizes privacy by using hashed communication and secure API practices.

## Project Overview

AxcelT-passintel is designed as a CLI tool that:
- Securely accepts a password using Python's `getpass`.
- Hashes the password (using SHA1, for example) to protect plaintext.
- Checks the hashed password against the HaveIBeenPwned API to determine if it’s been compromised.
- Analyzes password strength based on factors like length and complexity.

This tool serves as a portfolio project for demonstrating both cybersecurity fundamentals and practical Python/cloud integration skills.

## Getting Started

### Prerequisites
- Python 3.8 or higher (tested on Windows)
- pip (Python package installer)

### Setup Instructions for Windows

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/AxcelT-passintel.git
   cd AxcelT-passintel

## AWS Deployment Instructions

### Setting up the Lambda Function
1. Just upload the zip file in the directory.
