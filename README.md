# ProtCyber Ultra Scanner

```bash
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pyside6-rcc resources/resources.qrc -o resources_rc.py
pyside6-uic mainwindow.ui -o ui_mainwindow.py
pyside6-uic frontwindow.ui -o ui_frontwindow.py
py main.py

pyside6-designer mainwindow.ui
pyside6-designer frontwindow.ui

pyinstaller --windowed --icon=resources/app.ico main.py
