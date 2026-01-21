# ProtCyber Ultra Scanner

```bash
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pyside6-rcc resources/resources.qrc -o resources_rc.py
pyside6-uic mainwindow.ui -o ui_mainwindow.py
pyside6-uic frontwindow.ui -o ui_frontwindow.py
pyside6-uic settingwindow.ui -o ui_settingwindow.py
py main.py

pyside6-designer mainwindow.ui
pyside6-designer frontwindow.ui
pyside6-designer settingwindow.ui

pyinstaller --windowed --icon=resources/app.ico main.py
