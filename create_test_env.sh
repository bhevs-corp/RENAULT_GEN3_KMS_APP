#!/bin/bash

Remove-Item -Recurse -Force .\venv
Remove-Item -Recurse -Force .\build
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install --break-system-packages -r requirements.txt
pyinstaller --onefile --add-data "data.txt;." --add-data "api;api" --add-data "key;key" --add-data ".env;." app.py

deactivate
rm -rf ./dist/app.exe
