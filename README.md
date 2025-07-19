# Python ML Microservice

Flask-based microservice for malicious URL detection using ML models.

## Quick Start

### Local Development
```bash
pip install -r requirements.txt
python3 ml_microservice.py
```

### Docker
```bash
docker build -t python-ml-microservice .
docker run -p 5002:5002 python-ml-microservice
```

## Port: 5002
## Model: distilbert-base-uncased 