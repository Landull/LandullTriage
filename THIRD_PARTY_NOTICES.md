# Third-party notices

LandullTriage's own code is under the MIT License (see `LICENSE`). Release builds include these components, each under its own license:

| Component | Used for | License | Source |
|---|---|---|---|
| WinPmem (`winpmem.exe`, Windows builds) | RAM capture on Windows | Apache License 2.0 | https://github.com/Velocidex/WinPmem |
| AVML (`avml`, Linux builds) | RAM capture on Linux | MIT License | https://github.com/microsoft/avml |
| Volatility 3 | Memory analysis | Volatility Software License 1.0 | https://github.com/volatilityfoundation/volatility3 |
| pefile | Used by Volatility 3 | MIT License | https://github.com/erocarrera/pefile |
| Qt for Python (PySide6) | The app window | LGPL v3 | https://doc.qt.io/qtforpython/ |
| PyInstaller bootloader | Packaging | GPL v2 with bootloader exception | https://pyinstaller.org |

The exact WinPmem/AVML release and SHA-256 bundled in a build are recorded in `assets/bin/TOOLS.txt` inside the app. LandullTriage runs these tools unmodified.
