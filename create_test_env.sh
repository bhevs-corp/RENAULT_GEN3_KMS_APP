#!/bin/bash

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python test/test_token.py
deactivate

## python -m venv venv
## .\venv\Scripts\Activate.ps1
## pip install -r requirements.txt
## pip install pycryptodomex
## python .\test\test_token.py
## deactivate