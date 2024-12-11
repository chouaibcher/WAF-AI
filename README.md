# WAF_AI: Web Application Firewall with Artificial Intelligence

## Overview
This repository contains a **Web Application Firewall (WAF_AI)** that integrates **Artificial Intelligence** to detect and mitigate security threats in real-time. The system utilizes pre-trained models to analyze HTTP traffic and automatically block potentially malicious requests.

## Why ?
AI-based web application firewalls (WAFs) are superior to rule-based ones because they adapt, learn from traffic patterns, and scale effortlessly, making them ideal for detecting complex threats. They tolerate unknown and evolving threats, whereas rule-based WAFs work best for simple, predefined attack signatures and fixed conditions.

### Running the Application

Install the latest release from PyPI:
   ```bash
   pip install WAF-AI
   ```

For development or accessing the latest features, clone the repository:
   ```bash
   git clone https://github.com/chouaibcher/WAF_AI.git
   cd WAF_AI
   ```

## Features

- **Real-Time Threat Detection**: The system monitors incoming HTTP requests and detects SQL Injection, XSS, and other malicious patterns in real-time.
- **Machine Learning Integration**: Pre-trained models are used for detecting attacks based on patterns within URL paths and query parameters.
- **Extendable Framework**: The system can easily be extended to detect additional threats, such as command injection, file inclusion attacks, and more.

## Technologies Used

- **Flask**: A lightweight Python web framework used for building the WAF_AI application.
- **Python**: Core programming language for the backend logic and model implementation.
- **Machine Learning Models**: Pre-trained models for detecting SQL Injection and XSS, built using algorithms such as Random Forest, SVM, and Logistic Regression.
- **Joblib**: Used for loading machine learning models efficiently.
- **HTML/CSS**: Used for creating and styling the response page.
- **Jinja2 Templates**: Templating engine for dynamically rendering HTML content.

## Threat Detection

### **Current Threats Detected**

1. **SQL Injection**: This attack occurs when attackers inject malicious SQL code into a query, often leading to data leakage or unauthorized access to the database. 


## Getting Started

### Prerequisites

- **Python 3.x**: Install Python if you don't have it.
- **Flask**: Install Flask using `pip install flask`.
- **Joblib**: Install Joblib using `pip install joblib`.
- **Scikit-learn**: Install scikit-learn if you plan to train your own models (`pip install scikit-learn`).


### Key Updates:
- Added **SQL** Injection detection.
<img width="958" alt="image" src="https://github.com/user-attachments/assets/62a4143a-33f9-4bf3-be2c-012342154828">
<img width="959" alt="image" src="https://github.com/user-attachments/assets/91bbe2e5-cc04-41ef-83cd-c4ec6e3de819">



# Used Dataset :
If you reuse it, please mention us to avoid any problems
</br>
https://www.kaggle.com/datasets/chouaibcher/sql-injection-dataset


# Contributing
We welcome contributions to improve this project! If you'd like to help, please refer to the  `CONTRIBUTING.md`  file for guidelines on how to contribute.
Don’t Hesitate to Contribute! If you have ideas for new features or improvements, feel free to fork the repository, make your changes, and submit a pull request. 
Your help is highly appreciated in making this project better


