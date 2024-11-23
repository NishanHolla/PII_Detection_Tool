# Aurva Backend Assignment

## Overview
This tool is designed to scan uploaded files for sensitive information, such as PAN card numbers, Social Security Numbers (SSN), medical record numbers, health insurance information, email addresses, and credit card numbers. The scanned data is categorized into multiple categories, including:
- *PII (Personally Identifiable Information)*
- *PHI (Protected Health Information)*
- *PCI (Payment Card Information)*
- *Sensitive Personal Information (SPI)*
- *Communication Information (CI)*
- *Financial Information (FI)*

The tool utilizes *Presidio Analyzer*, a powerful library for detecting and classifying sensitive information using advanced natural language processing techniques. This enables the tool to scan text data and identify patterns of sensitive information based on predefined recognizers.

## Features
- *File Upload:* Users can upload files (e.g., text files) to be scanned for sensitive data.
- *Sensitive Data Detection:* The tool uses *Presidio Analyzer* to detect and classify sensitive information such as credit card numbers, SSNs, emails, and more.
- *Database Integration:* Scans and stores results in a MongoDB database.
- *Web Interface:* Allows users to upload files, view scan results, and delete records.
- *Backend APIs:* Provides RESTful APIs to interact with the data, including retrieving scan results and deleting entries.

## Tech Stack
- *Backend Framework:* Flask / FastAPI
- *Database:* MongoDB
- *Sensitive Data Detection:* *Presidio Analyzer* (via the presidio-analyzer library)
- *Frontend:* HTML (for file upload and scan results display)
- *Containerization:* Docker (for containerized environment)
- *Deployment:* Render, Railway, or Koyeb for cloud deployment (optional)

## Presidio Analyzer Integration

The *Presidio Analyzer* is an open-source library developed by Microsoft for detecting and classifying sensitive information. It uses advanced Natural Language Processing (NLP) techniques and machine learning-based models to scan text and identify various types of sensitive information such as emails, credit card numbers, SSNs, health information, and more.

### Why *Presidio Analyzer*?
- *Advanced Detection:* The Presidio Analyzer is capable of detecting sensitive information by recognizing patterns in text, even if the information is embedded within other content.
- *Customizable Recognizers:* You can define custom rules and patterns to detect additional types of sensitive information tailored to specific needs or regulatory requirements.
- *Accuracy:* By applying multiple filtering layers and NLP techniques, the analyzer ensures that the detection of sensitive data is both accurate and reliable.

### How It Works:
1. *Text Extraction:* Files are uploaded, and their content is extracted (e.g., from .txt, .pdf, or .docx files).
2. *Text Analysis:* The extracted text is passed to the Presidio Analyzer, which scans the text using predefined recognizers for different types of sensitive information.
3. *Categorization and Classification:* Detected sensitive information is classified into categories such as PII (Personally Identifiable Information), PHI (Protected Health Information), PCI (Payment Card Information), and others.
4. *Data Storage:* The sensitive data, along with its classification and confidence scores, is stored in a MongoDB database for further auditing, reporting, or deletion.

## System Architecture

### Components:
1. *File Upload API:* Users upload files to be scanned.
2. *Scanning Engine (Presidio Analyzer):* Scans and classifies sensitive information within the uploaded text using Presidio's NLP-based techniques.
3. *Database (MongoDB):* Stores the scan results and metadata (such as detected entities and their classifications).
4. *Frontend Interface:* Provides a user interface for file uploads and viewing scan results.
5. *Backend APIs:* Exposes RESTful endpoints to manage uploaded files, retrieve scan results, and delete entries.

### Database Design:
**MongoDB Collection: scans**
- *file_name:* Name of the uploaded file
- *scan_date:* Date and time when the scan was completed
- *sensitive_data_found:* List of sensitive data items detected
- *classification:* The classification (PII, PHI, PCI, SPI, CI, FI) of the detected data
- *status:* Scan status (e.g., completed, in-progress)

*System Diagram: ![WhatsApp Image 2024-11-23 at 09 39 51_606a7527](https://github.com/user-attachments/assets/1f9f00c3-c302-4c32-b582-1e0e6565290d)
*
