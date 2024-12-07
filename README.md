# WAF-AI: Web Application Firewall with Artificial Intelligence
## Overview

This repository contains a **Web Application Firewall (WAF)** that integrates **Artificial Intelligence** to detect and mitigate security threats in real-time, with a primary focus on SQL Injection and Cross-Site Scripting (XSS) attacks. The system utilizes pre-trained models to analyze HTTP traffic and automatically block potentially malicious requests.

The application is built using the **Flask** framework, providing a simple web interface for easy interaction with the firewall. The WAF uses custom tokenization methods and machine learning models to detect security threats and return appropriate responses when an attack is detected.

## Features

- **Real-Time Threat Detection**: The system monitors incoming HTTP requests and detects SQL Injection, XSS, and other malicious patterns in real-time.
- **Machine Learning Integration**: Pre-trained models are used for detecting attacks based on patterns within URL paths and query parameters.
- **Custom Tokenization**: A custom tokenizer is employed to extract features from request paths and parameters to better identify malicious activities.
- **HTML Response on Detection**: In the event of an attack, the WAF blocks the request and returns a custom HTML page notifying the user of the threat.
- **Extendable Framework**: The system can easily be extended to detect additional threats, such as command injection, file inclusion attacks, and more.

## Technologies Used

- **Flask**: A lightweight Python web framework used for building the WAF application.
- **Python**: Core programming language for the backend logic and model implementation.
- **Machine Learning Models**: Pre-trained models for detecting SQL Injection and XSS, built using algorithms such as Random Forest, SVM, and Logistic Regression.
- **Joblib**: Used for loading machine learning models efficiently.
- **HTML/CSS**: Used for creating and styling the response page.
- **Jinja2 Templates**: Templating engine for dynamically rendering HTML content.

## Threat Detection

### **Current Threats Detected**

1. **SQL Injection**: This attack occurs when attackers inject malicious SQL code into a query, often leading to data leakage or unauthorized access to the database. The WAF detects such attacks using:
   - **Custom Tokenization**: Breaking down URLs or request parameters into tokens to detect common SQL injection patterns (e.g., `';--`, `' OR 1=1`).
   - **Machine Learning Models**: Pre-trained models identify malicious patterns in requests and classify them as safe or dangerous.



## Getting Started

### Prerequisites

- **Python 3.x**: Install Python if you don't have it.
- **Flask**: Install Flask using `pip install flask`.
- **Joblib**: Install Joblib using `pip install joblib`.
- **Scikit-learn**: Install scikit-learn if you plan to train your own models (`pip install scikit-learn`).

### Running the Application

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/WAF-AI.git
   cd WAF-AI


### Key Updates:
- Added **SQL** Injection detection.
  
# Contributing
We welcome contributions to improve this project! If you'd like to help, please refer to the  `CONTRIBUTING.md`  file for guidelines on how to contribute.
Don’t Hesitate to Contribute! If you have ideas for new features or improvements, feel free to fork the repository, make your changes, and submit a pull request. 
Your help is highly appreciated in making this project better


