# OSINT Intelligence Framework

Advanced Open Source Intelligence framework for reconnaissance and information gathering operations.

## Overview

This framework provides comprehensive OSINT capabilities including username enumeration, email analysis, domain intelligence, dark web reconnaissance, and advanced correlation features. Built for security professionals, penetration testers, and researchers conducting authorized investigations.

## Features

- Username reconnaissance across 200+ platforms
- Email intelligence and breach correlation
- Domain and DNS analysis
- Repository intelligence gathering
- Dark web surface scanning
- Advanced correlation engine
- Multi-format report generation (JSON, CSV, XML, HTML)
- Asynchronous HTTP engine for performance
- Proxy support and rate limiting
- Batch processing capabilities

## Requirements

- Python 3.8 or higher
- Internet connection
- Linux, macOS, or WSL on Windows

## Installation
```bash
git clone https://github.com/genesisgzdev/nexus-intelligence.git
cd nexus-intelligence
pip install -r requirements.txt
```

## Usage

### Basic Username Search
```bash
python src/osinth.py username_target
```

### Email Investigation
```bash
python src/osinth.py --email user@example.com
```

### Domain Analysis
```bash
python src/osinth.py --domain example.com
```

### Advanced Options
```bash
python src/osinth.py target --format html --output report.html --proxy https://proxy:8080 -v
```

## Author

Genesis GZ - Security Researcher  
Contact: genzt.dev@pm.me

## License

MIT License - See LICENSE file for details
