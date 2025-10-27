#!/bin/bash

python3 -m venv venv
source venv/bin/activate
pip install --break-system-packages -r requirements.txt
export PATH=$PATH:/home/choiseu/.local/bin
pyinstaller --onefile app.py
deactivate

## Remove-Item -Recurse -Force .\venv
## Remove-Item -Recurse -Force .\build
## py -m venv venv
## .\venv\Scripts\Activate.ps1
## pip install --break-system-packages -r requirements.txt
## export PATH=$PATH:/home/choiseu/.local/bin
## pyinstaller --onefile --add-data "data.txt;." --add-data "api;api" app.py

## deactivate