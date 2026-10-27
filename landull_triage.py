#!/usr/bin/env python3
"""
LandullTriage - live-response evidence collection and memory analysis for Windows, macOS and Linux.

Run from source:   python3 landull_triage.py           (needs: pip install PySide6-Essentials)
Command line:      LandullTriage --collect --out <folder> [--modules default|all|a,b] [--case ID] [--examiner NAME]
                   LandullTriage --analyze <image> --out <folder> [--os windows|linux|mac]

The window never collects anything itself: it writes a config into the new case folder and starts a
collector process (elevated when needed), then follows that run's progress.jsonl.
"""

import json
import os
import shlex
import subprocess
import sys
import time
import traceback

APP_NAME = "LandullTriage"
GITHUB = "https://github.com/Landull/LandullTriage"


def base_dir():
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def asset(name):
    return os.path.join(base_dir(), "assets", name)


def _fix_stdio():
    """Windowed builds on Windows start with no stdout/stderr."""
    for name, fd in (("stdout", 1), ("stderr", 2)):
        if getattr(sys, name) is None:
            try:
                setattr(sys, name, os.fdopen(fd, "w", encoding="utf-8", errors="replace", buffering=1))
            except OSError:
                setattr(sys, name, open(os.devnull, "w"))
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            pass


def self_command(args):
    """Program + arguments that run this app in a non-GUI mode."""
    if getattr(sys, "frozen", False):
        return [sys.executable] + list(args)
    return [sys.executable, os.path.abspath(__file__)] + list(args)


def log_path():
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Logs/LandullTriage.log")
    if sys.platform.startswith("win"):
        return os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "LandullTriage.log")
    return os.path.expanduser("~/.landull_triage.log")


def log(msg):
    try:
        with open(log_path(), "a", encoding="utf-8") as fh:
            fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg.rstrip() + "\n")
    except OSError:
        pass


# ============================================================== GUI
def gui_main():
    from PySide6.QtCore import QProcess, QSize, Qt, QTimer, QUrl, Signal
    from PySide6.QtGui import QColor, QDesktopServices, QIcon, QPixmap, QTextCharFormat, QTextCursor
    from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QFrame,
                                   QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget,
                                   QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
                                   QScrollArea, QSizePolicy, QSpinBox, QStackedWidget, QTableWidget, QTableWidgetItem,
                                   QVBoxLayout, QWidget)

    from triage import VERSION
    from triage.analyze import PLUGINS, SYMBOL_NOTE, guess_os
    from triage.collectors.memory import availability as mem_availability
    from triage.core import (PLATFORM, STOP_FILE, case_folder_name, human_size, is_admin, same_volume, system_drive,
                             total_ram)
    from triage.modules import MODULES, available, describe

    BG, PANEL, SURFACE, BORDER = "#141414", "#101010", "#1c1c1c", "#2c2c2c"
    TEXT, MUTED, DIM, BONE = "#e6e3dd", "#9a968f", "#6b6862", "#e6e3dd"
    RED, AMBER, GREEN, BLUE = "#e06a6a", "#e0b25a", "#86c98a", "#7fa7d9"
    ADMIN = is_admin()
    MONO = 'Menlo, Consolas, "DejaVu Sans Mono", monospace'

    def rgba(hexcolor, a):
        c = QColor(hexcolor)
        return f"rgba({c.red()},{c.green()},{c.blue()},{a})"

    def qss():
        chk = asset("check.svg").replace("\\", "/")
        chev = asset("chevron.svg").replace("\\", "/")
        return f"""
        * {{ color: {TEXT}; font-size: 13px; }}
        QMainWindow, #root, #page {{ background: {BG}; }}
        QToolTip {{ background: #232323; color: {TEXT}; border: 1px solid #3a3a3a; padding: 6px; }}
        #sidebar {{ background: {PANEL}; border-right: 1px solid #222; }}
        #brand {{ font-size: 15px; font-weight: 700; letter-spacing: 3px; }}
        #brandSub {{ color: {DIM}; font-size: 11px; letter-spacing: 2px; }}
        #nav {{ background: transparent; border: none; outline: none; }}
        #nav::item {{ padding: 8px 10px; border-radius: 6px; margin: 1px 6px; }}
        #nav::item:hover {{ background: #1b1b1b; }}
        #nav::item:selected {{ background: #262626; color: #ffffff; }}
        QLineEdit, QPlainTextEdit, QComboBox, QSpinBox {{
            background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 6px; padding: 6px 8px;
            selection-background-color: #4a4a4a; }}
        QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: #6a675f; }}
        QComboBox::drop-down {{ border: none; width: 22px; }}
        QComboBox::down-arrow {{ image: url({chev}); width: 12px; height: 12px; }}
        QComboBox QAbstractItemView {{ background: #202020; border: 1px solid {BORDER}; selection-background-color: #333; }}
        QSpinBox::up-button, QSpinBox::down-button {{ width: 0; border: none; }}
        QPushButton, QToolButton {{ background: #232323; border: 1px solid #343434; border-radius: 6px; padding: 6px 12px; }}
        QPushButton:hover, QToolButton:hover {{ background: #2c2c2c; border-color: #444; }}
        QPushButton:pressed {{ background: #1a1a1a; }}
        QPushButton:disabled {{ color: #5a5a5a; background: #1b1b1b; border-color: #262626; }}
        #runButton {{ background: {BONE}; color: #141414; font-weight: 700; font-size: 14px; border: none; padding: 10px 22px; }}
        #runButton:hover {{ background: #ffffff; }}
        #runButton:disabled {{ background: #3a3a3a; color: #777; }}
        #stopButton {{ background: #3a1616; border-color: #6e2a2a; color: #ff9b9b; font-weight: 600; padding: 10px 16px; }}
        #stopButton:hover {{ background: #4a1c1c; }}
        #stopButton:disabled {{ background: #1b1b1b; border-color: #262626; color: #5a5a5a; }}
        #linkButton {{ background: transparent; border: none; color: {MUTED}; padding: 4px 6px; }}
        #linkButton:hover {{ color: {TEXT}; }}
        #toggle {{ background: transparent; border: none; color: {MUTED}; padding: 6px 0; font-weight: 600; text-align: left; }}
        #toggle:hover {{ color: {TEXT}; }}
        QCheckBox {{ spacing: 8px; }}
        QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px; border: 1px solid #555; background: {SURFACE}; }}
        QCheckBox::indicator:hover {{ border-color: #888; }}
        QCheckBox::indicator:checked {{ background: {BONE}; border-color: {BONE}; image: url({chk}); }}
        QCheckBox::indicator:disabled {{ background: #181818; border-color: #2c2c2c; }}
        QCheckBox:disabled {{ color: #5f5c57; }}
        #fieldLabel {{ font-weight: 600; color: #d8d5cf; }}
        #help {{ color: {DIM}; font-size: 12px; }}
        #sectionTitle {{ color: {MUTED}; font-size: 11px; font-weight: 700; letter-spacing: 2px; }}
        #pageTitle {{ font-size: 26px; font-weight: 800; letter-spacing: 1px; }}
        #pageSub {{ color: {MUTED}; font-size: 14px; }}
        #card {{ background: #181818; border: 1px solid #252525; border-radius: 10px; }}
        #modTitle {{ font-weight: 700; }}
        #modDesc {{ color: {MUTED}; font-size: 12px; }}
        #modRow {{ border-bottom: 1px solid #222; }}
        #warning {{ background: {rgba(AMBER, 0.08)}; border: 1px solid {rgba(AMBER, 0.35)}; color: {AMBER};
                    border-radius: 6px; padding: 8px 10px; }}
        #info {{ background: {rgba(BLUE, 0.07)}; border: 1px solid {rgba(BLUE, 0.3)}; color: #b7cbe6;
                 border-radius: 6px; padding: 8px 10px; }}
        #errors {{ background: {rgba(RED, 0.08)}; border: 1px solid {rgba(RED, 0.4)}; color: {RED};
                   border-radius: 6px; padding: 8px 10px; }}
        #output {{ background: #0d0d0d; border: 1px solid #222; border-radius: 8px; padding: 8px;
                   font-family: {MONO}; font-size: 12px; }}
        #stepName {{ font-weight: 600; }}
        #stepState {{ color: {DIM}; font-family: {MONO}; font-size: 12px; }}
        #bigNum {{ font-size: 28px; font-weight: 800; }}
        #status {{ font-weight: 600; }}
        #footer {{ color: {DIM}; font-size: 11px; }}
        QProgressBar {{ background: #0f0f0f; border: 1px solid #262626; border-radius: 5px; height: 10px; text-align: center;
                        color: transparent; }}
        QProgressBar::chunk {{ background: {BONE}; border-radius: 4px; }}
        QTableWidget {{ background: #0f0f0f; border: 1px solid #222; border-radius: 8px; gridline-color: #222;
                        font-family: {MONO}; font-size: 12px; }}
        QHeaderView::section {{ background: #1a1a1a; color: {MUTED}; border: none; border-right: 1px solid #222;
                                border-bottom: 1px solid #222; padding: 5px 6px; font-weight: 700; }}
        QScrollArea {{ border: none; background: transparent; }}
        QScrollArea > QWidget > QWidget {{ background: transparent; }}
        QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
        QScrollBar::handle:vertical {{ background: #333; border-radius: 4px; min-height: 30px; }}
        QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
        QScrollBar::handle:horizontal {{ background: #333; border-radius: 4px; min-width: 30px; }}
        QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
        QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
        QMessageBox {{ background: #1a1a1a; }}
        """

    def label(text, obj=None, wrap=False, sel=False):
        lab = QLabel(text)
        if obj:
            lab.setObjectName(obj)
        lab.setWordWrap(wrap)
        if sel:
            lab.setTextInteractionFlags(Qt.TextSelectableByMouse)
        return lab

    def chip(text, color):
        c = QLabel(text)
        c.setStyleSheet(f"background:{rgba(color, 0.12)}; color:{color}; border:1px solid {rgba(color, 0.35)};"
                        "border-radius:9px; padding:1px 8px; font-size:11px; font-weight:700;")
        c.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        return c

    def card():
        f = QFrame()
        f.setObjectName("card")
        lay = QVBoxLayout(f)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(10)
        return f, lay

    def open_path(p):
        QDesktopServices.openUrl(QUrl.fromLocalFile(p))

    def reveal(p):
        if sys.platform == "darwin":
            subprocess.Popen(["open", "-R", p])
        elif sys.platform.startswith("win"):
            subprocess.Popen(["explorer", "/select,", os.path.normpath(p)])
        else:
            open_path(os.path.dirname(p) if os.path.isfile(p) else p)

    class PathRow(QWidget):
        changed = Signal()

        def __init__(self, placeholder, mode="dir", parent=None):
            super().__init__(parent)
            self.mode = mode
            lay = QHBoxLayout(self)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.setSpacing(6)
            self.edit = QLineEdit()
            self.edit.setPlaceholderText(placeholder)
            self.edit.textChanged.connect(self.changed)
            self.setAcceptDrops(True)
            lay.addWidget(self.edit, 1)
            b = QPushButton("Browse...")
            b.clicked.connect(self.pick)
            lay.addWidget(b)

        def pick(self):
            start = self.edit.text() or os.path.expanduser("~")
            if self.mode == "dir":
                p = QFileDialog.getExistingDirectory(self, "Choose a folder", start)
            else:
                p, _ = QFileDialog.getOpenFileName(self, "Choose a memory image", start,
                                                   "Memory images (*.raw *.mem *.lime *.vmem *.dmp *.bin *.img *.aff4);;All files (*)")
            if p:
                self.edit.setText(p)

        def text(self):
            return self.edit.text().strip()

        def setText(self, t):
            self.edit.setText(t)

        def dragEnterEvent(self, e):
            if e.mimeData().hasUrls():
                e.acceptProposedAction()

        def dropEvent(self, e):
            urls = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
            if urls:
                self.edit.setText(urls[0])

    class LogView(QPlainTextEdit):
        def __init__(self):
            super().__init__()
            self.setObjectName("output")
            self.setReadOnly(True)
            self.setMaximumBlockCount(20000)
            self.setLineWrapMode(QPlainTextEdit.NoWrap)
            self.setMinimumHeight(170)

        def add(self, text, color=None):
            cur = self.textCursor()
            cur.movePosition(QTextCursor.End)
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(color or "#bdb9b2"))
            cur.insertText(text.rstrip("\n") + "\n", fmt)
            sb = self.verticalScrollBar()
            if sb.value() >= sb.maximum() - 40:
                self.setTextCursor(cur)
                sb.setValue(sb.maximum())

    class Step(QWidget):
        """One line in the progress list: dot, name, state."""

        def __init__(self, title):
            super().__init__()
            lay = QHBoxLayout(self)
            lay.setContentsMargins(0, 2, 0, 2)
            lay.setSpacing(10)
            self.dot = QLabel("○")
            self.dot.setFixedWidth(16)
            self.dot.setStyleSheet(f"color:{DIM}; font-size:14px;")
            self.name = label(title, "stepName")
            self.state = label("waiting", "stepState")
            lay.addWidget(self.dot)
            lay.addWidget(self.name, 1)
            lay.addWidget(self.state)

        def set(self, state, text):
            sym, col = {"running": ("◉", BONE), "ok": ("✓", GREEN), "partial": ("!", AMBER), "failed": ("✕", RED),
                        "skipped": ("–", DIM), "missing": ("–", DIM), "waiting": ("○", DIM)}.get(state, ("○", DIM))
            self.dot.setText(sym)
            self.dot.setStyleSheet(f"color:{col}; font-size:14px; font-weight:700;")
            self.state.setText(text)
            self.state.setStyleSheet(f"color:{col if state != 'running' else MUTED};")

    def scroll_page(widget):
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        sc.setFrameShape(QFrame.NoFrame)
        sc.setWidget(widget)
        return sc

    # ------------------------------------------------------------------ Collect page
    class CollectPage(QWidget):
        analyze_image = Signal(str)

        def __init__(self):
            super().__init__()
            self.setObjectName("page")
            self.proc = None
            self.case_dir = None
            self.offset = 0
            self.steps = {}
            self.timer = QTimer(self)
            self.timer.setInterval(300)
            self.timer.timeout.connect(self.poll)
            self.started_at = 0
            self.started = False
            self.mem_image = None

            inner = QWidget()
            root = QVBoxLayout(inner)
            root.setContentsMargins(36, 30, 36, 30)
            root.setSpacing(16)
            root.addWidget(label("Collect evidence", "pageTitle"))
            root.addWidget(label("Captures this computer's volatile state first (RAM, connections, processes), then "
                                 "persistence, logs and disk artifacts. Everything is hashed into one case folder.",
                                 "pageSub", wrap=True))

            # privilege banner
            self.priv = QFrame()
            pl = QHBoxLayout(self.priv)
            pl.setContentsMargins(0, 0, 0, 0)
            pl.setSpacing(10)
            self.priv_text = label("", wrap=True)
            pl.addWidget(self.priv_text, 1)
            self.elevate_btn = QPushButton("Relaunch as administrator")
            self.elevate_btn.clicked.connect(self.relaunch_admin)
            pl.addWidget(self.elevate_btn, 0, Qt.AlignTop)
            self.root_box = QCheckBox("Run the collection as root (asks for your password)")
            self.root_box.setChecked(True)
            root.addWidget(self.priv)
            root.addWidget(self.root_box)
            self._setup_priv()

            # case details
            c, cl = card()
            cl.addWidget(label("CASE", "sectionTitle"))
            g = QGridLayout()
            g.setHorizontalSpacing(14)
            g.setVerticalSpacing(8)
            self.case_id = QLineEdit()
            self.case_id.setPlaceholderText("e.g. IR-2026-014 (optional)")
            self.examiner = QLineEdit()
            self.examiner.setPlaceholderText("your name (optional)")
            self.notes = QLineEdit()
            self.notes.setPlaceholderText("why this collection is happening, ticket number, etc. (optional)")
            self.out = PathRow("choose where to save the case folder (an external drive is best)")
            self.out.changed.connect(self.check_output)
            for r, (lab_, w) in enumerate((("Case", self.case_id), ("Examiner", self.examiner), ("Notes", self.notes),
                                           ("Save to", self.out))):
                g.addWidget(label(lab_, "fieldLabel"), r, 0)
                g.addWidget(w, r, 1)
            g.setColumnStretch(1, 1)
            cl.addLayout(g)
            self.out_msg = label("", wrap=True)
            self.out_msg.hide()
            cl.addWidget(self.out_msg)
            root.addWidget(c)

            # modules
            c, cl = card()
            top = QHBoxLayout()
            top.addWidget(label("WHAT TO COLLECT", "sectionTitle"))
            top.addStretch(1)
            for text, fn in (("Defaults", self.sel_default), ("All", self.sel_all), ("None", self.sel_none)):
                b = QPushButton(text)
                b.setObjectName("linkButton")
                b.setCursor(Qt.PointingHandCursor)
                b.clicked.connect(fn)
                top.addWidget(b)
            cl.addLayout(top)
            self.boxes = {}
            ram = total_ram()
            for m in MODULES:
                if PLATFORM not in m["platforms"] and m["id"] != "memory":
                    continue
                row = QWidget()
                row.setObjectName("modRow")
                rl = QHBoxLayout(row)
                rl.setContentsMargins(0, 8, 0, 8)
                rl.setSpacing(12)
                box = QCheckBox()
                txt = QVBoxLayout()
                txt.setSpacing(2)
                head = QHBoxLayout()
                head.setSpacing(8)
                head.addWidget(label(m["title"], "modTitle"))
                ok = available(m)
                why = ""
                if m["id"] == "memory":
                    ok, why = mem_availability()
                if ok and m.get("admin") and not ADMIN and PLATFORM == "windows":
                    head.addWidget(chip("needs admin", AMBER))
                elif ok and m.get("admin") and not ADMIN:
                    head.addWidget(chip("needs root", AMBER))
                if m["id"] == "memory" and ok and ram:
                    head.addWidget(chip(f"≈ {human_size(ram)}", BLUE))
                if m["id"] == "memfiles":
                    try:
                        from triage.collectors.windows import memfile_sizes
                        sz = sum(memfile_sizes().values())
                        if sz:
                            head.addWidget(chip(f"≈ {human_size(sz)}", BLUE))
                    except Exception:
                        pass
                if not ok:
                    head.addWidget(chip("not available", DIM))
                head.addStretch(1)
                txt.addLayout(head)
                txt.addWidget(label(why or describe(m), "modDesc", wrap=True))
                rl.addWidget(box, 0, Qt.AlignTop)
                rl.addLayout(txt, 1)
                box.setEnabled(ok)
                box.setChecked(ok and m["default"])
                row.setEnabled(True)
                self.boxes[m["id"]] = box
                cl.addWidget(row)
            opts = QHBoxLayout()
            opts.setSpacing(10)
            opts.addWidget(label("Log range", "fieldLabel"))
            self.days = QSpinBox()
            self.days.setRange(1, 365)
            self.days.setValue(7)
            self.days.setSuffix(" days")
            self.days.setFixedWidth(110)
            self.days.setToolTip("How far back to export logs where the OS supports a range (journal, unified log, key events).\n"
                                 "Windows .evtx files are always exported whole.")
            opts.addWidget(self.days)
            opts.addSpacing(18)
            self.zip_box = QCheckBox("Zip the case folder when done")
            opts.addWidget(self.zip_box)
            opts.addStretch(1)
            cl.addLayout(opts)
            root.addWidget(c)

            # run bar
            bar = QHBoxLayout()
            self.run_btn = QPushButton("Start collection")
            self.run_btn.setObjectName("runButton")
            self.run_btn.setCursor(Qt.PointingHandCursor)
            self.run_btn.clicked.connect(self.start)
            self.stop_btn = QPushButton("Stop")
            self.stop_btn.setObjectName("stopButton")
            self.stop_btn.setEnabled(False)
            self.stop_btn.clicked.connect(self.stop)
            self.status = label("", "status")
            bar.addWidget(self.run_btn)
            bar.addWidget(self.stop_btn)
            bar.addSpacing(10)
            bar.addWidget(self.status, 1)
            root.addLayout(bar)
            self.errors = label("", "errors", wrap=True)
            self.errors.hide()
            root.addWidget(self.errors)

            # progress card
            self.prog_card, pc = card()
            ph = QHBoxLayout()
            ph.addWidget(label("PROGRESS", "sectionTitle"))
            ph.addStretch(1)
            self.elapsed = label("", "stepState")
            ph.addWidget(self.elapsed)
            pc.addLayout(ph)
            self.bar = QProgressBar()
            self.bar.setTextVisible(False)
            self.bar.setFixedHeight(10)
            pc.addWidget(self.bar)
            self.step_box = QVBoxLayout()
            self.step_box.setSpacing(2)
            pc.addLayout(self.step_box)
            self.mem_bar = QProgressBar()
            self.mem_bar.setTextVisible(False)
            self.mem_bar.setFixedHeight(8)
            self.mem_label = label("", "help")
            pc.addWidget(self.mem_label)
            pc.addWidget(self.mem_bar)
            self.mem_bar.hide()
            self.mem_label.hide()
            self.log_toggle = QPushButton("▸ Show details")
            self.log_toggle.setObjectName("toggle")
            self.log_toggle.clicked.connect(self.toggle_log)
            pc.addWidget(self.log_toggle, 0, Qt.AlignLeft)
            self.logv = LogView()
            self.logv.hide()
            pc.addWidget(self.logv)
            root.addWidget(self.prog_card)
            self.prog_card.hide()

            # done card
            self.done_card, dc = card()
            dc.addWidget(label("RESULT", "sectionTitle"))
            nums = QHBoxLayout()
            self.n_high, self.n_med, self.n_low, self.n_files = (QLabel("0") for _ in range(4))
            for w, cap, col in ((self.n_high, "high findings", RED), (self.n_med, "medium", AMBER), (self.n_low, "low", BLUE),
                                (self.n_files, "files hashed", TEXT)):
                box = QVBoxLayout()
                w.setObjectName("bigNum")
                w.setStyleSheet(f"color:{col};")
                box.addWidget(w)
                box.addWidget(label(cap, "help"))
                nums.addLayout(box)
                nums.addSpacing(24)
            nums.addStretch(1)
            dc.addLayout(nums)
            self.done_path = label("", "help", wrap=True, sel=True)
            dc.addWidget(self.done_path)
            btns = QHBoxLayout()
            self.open_report = QPushButton("Open report")
            self.open_report.setObjectName("runButton")
            self.open_report.clicked.connect(lambda: open_path(os.path.join(self.case_dir, "report.html")))
            self.show_folder = QPushButton("Show case folder")
            self.show_folder.clicked.connect(lambda: reveal(self.case_dir))
            self.analyze_btn = QPushButton("Analyze the RAM image")
            self.analyze_btn.clicked.connect(lambda: self.analyze_image.emit(self.mem_image or ""))
            btns.addWidget(self.open_report)
            btns.addWidget(self.show_folder)
            btns.addWidget(self.analyze_btn)
            btns.addStretch(1)
            dc.addLayout(btns)
            root.addWidget(self.done_card)
            self.done_card.hide()

            root.addStretch(1)
            root.addWidget(label("Only collect from systems you own or are authorized to examine. Running any tool changes "
                                 "a live system a little; LandullTriage logs its own footprint so it can be accounted for.",
                                 "footer", wrap=True))
            lay = QVBoxLayout(self)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.addWidget(scroll_page(inner))
            self.check_output()

        # -- setup helpers
        def _setup_priv(self):
            if ADMIN:
                self.priv.hide()
                self.root_box.hide()
                return
            if PLATFORM == "windows":
                self.priv.setObjectName("warning")
                self.priv_text.setText("Running without administrator rights. RAM capture, the Security log, registry hives, "
                                       "Amcache, the $MFT and other users' processes need admin.")
                self.root_box.hide()
            else:
                self.priv.hide()
                self.elevate_btn.hide()
                self.root_box.setToolTip("Without root, RAM capture, protected logs and other users' data are skipped.")

        def relaunch_admin(self):
            try:
                import ctypes
                exe = sys.executable
                params = "" if getattr(sys, "frozen", False) else subprocess.list2cmdline([os.path.abspath(__file__)])
                r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
                if r > 32:
                    QApplication.quit()
            except Exception as e:
                QMessageBox.warning(self, APP_NAME, f"Couldn't relaunch as administrator:\n{e}")

        def check_output(self):
            p = self.out.text()
            if not p:
                self.out_msg.hide()
                return
            if not os.path.isdir(p):
                self.out_msg.setObjectName("errors")
                self.out_msg.setText("That folder doesn't exist.")
            else:
                import shutil
                free = shutil.disk_usage(p).free
                msg = f"{human_size(free)} free on this drive."
                obj = "info"
                if same_volume(p, system_drive()):
                    msg += (" This is the system drive: writing evidence here changes the disk you're investigating. "
                            "An external or network drive is better when you have one.")
                    obj = "warning"
                need = total_ram() if self.boxes.get("memory") and self.boxes["memory"].isChecked() else 0
                if need and free < need * 1.05:
                    msg += f" Not enough space for the RAM image (≈ {human_size(need)})."
                    obj = "errors"
                self.out_msg.setObjectName(obj)
                self.out_msg.setText(msg)
            self.out_msg.style().unpolish(self.out_msg)
            self.out_msg.style().polish(self.out_msg)
            self.out_msg.show()

        def sel_default(self):
            for m in MODULES:
                b = self.boxes.get(m["id"])
                if b and b.isEnabled():
                    b.setChecked(m["default"])

        def sel_all(self):
            for b in self.boxes.values():
                if b.isEnabled():
                    b.setChecked(True)

        def sel_none(self):
            for b in self.boxes.values():
                b.setChecked(False)

        def toggle_log(self):
            vis = not self.logv.isVisible()
            self.logv.setVisible(vis)
            self.log_toggle.setText("▾ Hide details" if vis else "▸ Show details")

        # -- running
        def is_running(self):
            return self.proc is not None and self.proc.state() != QProcess.NotRunning

        def start(self):
            mods = [mid for mid, b in self.boxes.items() if b.isChecked() and b.isEnabled()]
            out = self.out.text()
            problems = []
            if not out:
                problems.append("Choose where to save the case folder.")
            elif not os.path.isdir(out):
                problems.append("The save folder doesn't exist.")
            if not mods:
                problems.append("Pick at least one thing to collect.")
            if problems:
                self.errors.setText("\n".join(problems))
                self.errors.show()
                return
            self.errors.hide()
            import socket
            self.case_dir = os.path.join(out, case_folder_name(self.case_id.text().strip(), socket.gethostname()))
            try:
                os.makedirs(self.case_dir, exist_ok=False)
            except OSError as e:
                self.errors.setText(f"Couldn't create the case folder: {e}")
                self.errors.show()
                return
            cfg = {"case_id": self.case_id.text().strip(), "examiner": self.examiner.text().strip(),
                   "notes": self.notes.text().strip(), "output_dir": out, "modules": mods,
                   "log_days": self.days.value(), "zip": self.zip_box.isChecked()}
            if hasattr(os, "getuid"):
                cfg["owner_uid"], cfg["owner_gid"] = os.getuid(), os.getgid()
            cfg_path = os.path.join(self.case_dir, "collection_config.json")
            with open(cfg_path, "w", encoding="utf-8") as fh:
                json.dump(cfg, fh, indent=2)
            args = ["--collect", "--config", cfg_path, "--case-dir", self.case_dir]
            prog, pargs = self._elevated(self_command(args))
            # reset UI
            for i in reversed(range(self.step_box.count())):
                w = self.step_box.itemAt(i).widget()
                if w:
                    w.deleteLater()
            self.steps = {}
            titles = {m["id"]: m["title"] for m in MODULES}
            for mid in [m["id"] for m in MODULES if m["id"] in mods]:
                s = Step(titles[mid])
                self.steps[mid] = s
                self.step_box.addWidget(s)
            self.bar.setRange(0, len(self.steps) + 1)
            self.bar.setValue(0)
            self.logv.clear()
            self.mem_bar.hide()
            self.mem_label.hide()
            self.done_card.hide()
            self.prog_card.show()
            self.offset = 0
            self.mem_image = None
            self.started = False
            self.started_at = time.time()
            self.proc = QProcess(self)
            self.proc.setProcessChannelMode(QProcess.MergedChannels)
            self.proc.readyRead.connect(self._child_output)
            self.proc.finished.connect(self.finished)
            self.proc.errorOccurred.connect(self._proc_error)
            self.proc.start(prog, pargs)
            log(f"collect: {prog} {' '.join(pargs)}")
            self.run_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self._status("Starting…" if not prog.endswith(("osascript", "pkexec")) else "Waiting for your password…", MUTED)
            self.timer.start()

        def _elevated(self, cmd):
            if ADMIN or PLATFORM == "windows" or not self.root_box.isChecked():
                return cmd[0], cmd[1:]
            if PLATFORM == "linux":
                import shutil
                pk = shutil.which("pkexec")
                if pk:
                    return pk, cmd
                self.logv.add("pkexec isn't installed; collecting without root.", AMBER)
                return cmd[0], cmd[1:]
            shell = " ".join(shlex.quote(c) for c in cmd) + " >/dev/null 2>&1"
            script = 'do shell script "' + shell.replace("\\", "\\\\").replace('"', '\\"') + '" with administrator privileges ' \
                     'with prompt "LandullTriage needs administrator rights to collect protected evidence."'
            return "/usr/bin/osascript", ["-e", script]

        def _child_output(self):
            data = bytes(self.proc.readAll()).decode("utf-8", "replace")
            for line in data.splitlines():
                if line.strip():
                    self.logv.add(line, DIM)

        def _proc_error(self, err):
            if err == QProcess.FailedToStart:
                self._status("Couldn't start the collector.", RED)

        def _status(self, text, color):
            self.status.setText(text)
            self.status.setStyleSheet(f"color:{color};")

        def poll(self):
            if self.started_at:
                s = int(time.time() - self.started_at)
                self.elapsed.setText(f"{s // 60}:{s % 60:02d}")
            path = os.path.join(self.case_dir or "", "progress.jsonl")
            try:
                with open(path, "rb") as fh:
                    fh.seek(self.offset)
                    chunk = fh.read()
            except OSError:
                return
            if not chunk:
                return
            end = chunk.rfind(b"\n")
            if end < 0:
                return
            self.offset += end + 1
            for raw in chunk[:end].splitlines():
                try:
                    ev = json.loads(raw)
                except ValueError:
                    continue
                self.handle(ev)

        def handle(self, ev):
            t = ev.get("t")
            if t == "start":
                self.started = True
                self._status("Collecting…", TEXT)
                if not ev.get("admin"):
                    self.logv.add("Running without administrator/root rights; some items will be skipped.", AMBER)
            elif t == "module_start":
                s = self.steps.get(ev.get("module"))
                if s:
                    s.set("running", "collecting…")
                self._status(f"Collecting {ev.get('title', '').lower()}…", TEXT)
                self.logv.add(f"== {ev.get('title')}", BONE)
            elif t == "module_end":
                s = self.steps.get(ev.get("module"))
                st = ev.get("status")
                if s:
                    s.set(st, {"ok": "done", "partial": "partial", "failed": "failed", "skipped": "skipped"}.get(st, st)
                          + f" · {ev.get('seconds', 0)}s")
                self.bar.setValue(self.bar.value() + 1)
                if ev.get("module") == "memory":
                    self.mem_bar.hide()
                    self.mem_label.hide()
            elif t == "progress" and ev.get("module") == "memory":
                total = ev.get("total") or 0
                done = ev.get("done") or 0
                self.mem_bar.show()
                self.mem_label.show()
                if total:
                    self.mem_bar.setRange(0, 1000)
                    self.mem_bar.setValue(min(1000, int(done * 1000 / total)))
                self.mem_label.setText(f"RAM image: {human_size(done)} of ≈ {human_size(total)}")
            elif t == "log":
                lvl = ev.get("level")
                self.logv.add(ev.get("msg", ""), {"warn": AMBER, "error": RED}.get(lvl, "#bdb9b2"))
            elif t == "stage":
                self._status(ev.get("msg", ""), TEXT)
                self.logv.add(ev.get("msg", ""), BONE)
            elif t == "done":
                self.bar.setValue(self.bar.maximum())
                self.show_done(ev)

        def show_done(self, ev):
            try:
                with open(os.path.join(self.case_dir, "case.json"), encoding="utf-8") as fh:
                    case = json.load(fh)
            except (OSError, ValueError):
                case = {}
            flags = case.get("flags") or []
            self.n_high.setText(str(sum(1 for f in flags if f.get("severity") == "high")))
            self.n_med.setText(str(sum(1 for f in flags if f.get("severity") == "medium")))
            self.n_low.setText(str(sum(1 for f in flags if f.get("severity") == "low")))
            self.n_files.setText(str(ev.get("files", 0)))
            txt = f"Case folder: {self.case_dir}"
            if ev.get("zip"):
                txt += f"\nZip: {ev['zip']}"
            self.done_path.setText(txt)
            img = (case.get("modules", {}).get("memory", {}).get("result") or {}).get("image")
            self.mem_image = os.path.join(self.case_dir, img) if img else None
            self.analyze_btn.setVisible(bool(self.mem_image))
            self.done_card.show()
            stopped = ev.get("stopped")
            self._status("Stopped early. What was collected is hashed and in the report." if stopped
                         else "Collection complete.", AMBER if stopped else GREEN)

        def finished(self, code, status):
            self.timer.stop()
            self.poll()
            self.run_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            if not self.done_card.isVisible():
                if not self.started:
                    self._status("Cancelled before the collection started (password prompt dismissed?).", AMBER)
                    try:  # remove the empty case folder we created
                        for f in os.listdir(self.case_dir):
                            os.remove(os.path.join(self.case_dir, f))
                        os.rmdir(self.case_dir)
                    except OSError:
                        pass
                else:
                    self._status(f"The collector stopped unexpectedly (exit code {code}). See details.", RED)
                    self.logv.setVisible(True)

        def stop(self):
            if not self.case_dir:
                return
            try:
                open(os.path.join(self.case_dir, STOP_FILE), "w").close()
            except OSError:
                pass
            self.stop_btn.setEnabled(False)
            self._status("Stopping after the current step… (finishing the report and hashes)", AMBER)

        def kill(self):
            if self.is_running():
                self.stop()

    # ------------------------------------------------------------------ Analyze page
    class AnalyzePage(QWidget):
        def __init__(self):
            super().__init__()
            self.setObjectName("page")
            self.proc = None
            self.steps = {}
            self.outdir = None
            inner = QWidget()
            root = QVBoxLayout(inner)
            root.setContentsMargins(36, 30, 36, 30)
            root.setSpacing(16)
            root.addWidget(label("Analyze memory", "pageTitle"))
            root.addWidget(label("Runs core Volatility 3 plugins on a RAM image and saves each result as CSV. "
                                 "Works on images from LandullTriage, WinPmem, AVML, DumpIt, FTK Imager, VMware and more.",
                                 "pageSub", wrap=True))
            c, cl = card()
            cl.addWidget(label("IMAGE", "sectionTitle"))
            g = QGridLayout()
            g.setHorizontalSpacing(14)
            g.setVerticalSpacing(8)
            self.image = PathRow("drop a memory image here (.raw, .mem, .lime, .vmem, .dmp...)", mode="file")
            self.image.changed.connect(self.image_changed)
            self.os = QComboBox()
            self.os.addItems(["Windows", "Linux", "macOS"])
            self.os.currentIndexChanged.connect(self.fill_plugins)
            self.os.setFixedWidth(160)
            self.symbols = PathRow("optional: folder with symbol tables (needed for Linux/macOS)")
            self.out = PathRow("where to save results (default: next to the image)")
            for r, (lab_, w) in enumerate((("Image", self.image), ("System", self.os), ("Symbols", self.symbols),
                                           ("Save to", self.out))):
                g.addWidget(label(lab_, "fieldLabel"), r, 0)
                if w is self.os:
                    g.addWidget(w, r, 1, Qt.AlignLeft)
                else:
                    g.addWidget(w, r, 1)
            g.setColumnStretch(1, 1)
            cl.addLayout(g)
            self.offline = QCheckBox("Offline: don't download Windows symbols")
            cl.addWidget(self.offline)
            self.note = label("", "info", wrap=True)
            cl.addWidget(self.note)
            root.addWidget(c)
            c, cl = card()
            cl.addWidget(label("PLUGINS", "sectionTitle"))
            self.plug_box = QVBoxLayout()
            self.plug_box.setSpacing(4)
            cl.addLayout(self.plug_box)
            root.addWidget(c)
            bar = QHBoxLayout()
            self.run_btn = QPushButton("Run analysis")
            self.run_btn.setObjectName("runButton")
            self.run_btn.clicked.connect(self.start)
            self.stop_btn = QPushButton("Stop")
            self.stop_btn.setObjectName("stopButton")
            self.stop_btn.setEnabled(False)
            self.stop_btn.clicked.connect(self.stop)
            self.status = label("", "status")
            bar.addWidget(self.run_btn)
            bar.addWidget(self.stop_btn)
            bar.addSpacing(10)
            bar.addWidget(self.status, 1)
            root.addLayout(bar)
            self.errors = label("", "errors", wrap=True)
            self.errors.hide()
            root.addWidget(self.errors)
            self.prog_card, pc = card()
            pc.addWidget(label("PROGRESS", "sectionTitle"))
            self.bar = QProgressBar()
            self.bar.setFixedHeight(10)
            self.bar.setTextVisible(False)
            pc.addWidget(self.bar)
            self.step_box = QVBoxLayout()
            self.step_box.setSpacing(2)
            pc.addLayout(self.step_box)
            self.logv = LogView()
            self.logv.setMinimumHeight(120)
            pc.addWidget(self.logv)
            root.addWidget(self.prog_card)
            self.prog_card.hide()
            self.res_card, rc_ = card()
            rh = QHBoxLayout()
            rh.addWidget(label("RESULTS", "sectionTitle"))
            rh.addStretch(1)
            self.res_pick = QComboBox()
            self.res_pick.setMinimumWidth(240)
            self.res_pick.currentIndexChanged.connect(self.show_result)
            self.filter = QLineEdit()
            self.filter.setPlaceholderText("filter rows…")
            self.filter.setFixedWidth(220)
            self.filter.textChanged.connect(self.apply_filter)
            folder = QPushButton("Show folder")
            folder.clicked.connect(lambda: reveal(self.outdir) if self.outdir else None)
            rh.addWidget(self.res_pick)
            rh.addWidget(self.filter)
            rh.addWidget(folder)
            rc_.addLayout(rh)
            self.table = QTableWidget()
            self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.table.verticalHeader().hide()
            self.table.setMinimumHeight(360)
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
            self.table.horizontalHeader().setStretchLastSection(True)
            rc_.addWidget(self.table)
            self.res_info = label("", "help")
            rc_.addWidget(self.res_info)
            root.addWidget(self.res_card)
            self.res_card.hide()
            root.addStretch(1)
            lay = QVBoxLayout(self)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.addWidget(scroll_page(inner))
            self.plug_checks = []
            self.fill_plugins()

        def os_key(self):
            return ["windows", "linux", "mac"][self.os.currentIndex()]

        def fill_plugins(self):
            while self.plug_box.count():
                it = self.plug_box.takeAt(0)
                if it.widget():
                    it.widget().deleteLater()
            self.plug_checks = []
            for spec, desc, default in PLUGINS[self.os_key()]:
                name = spec.split("|")[0]
                cb = QCheckBox(f"{name.split('.', 1)[1].replace('malware.', '')}  —  {desc}")
                cb.setChecked(default)
                cb.setProperty("spec", spec)
                self.plug_box.addWidget(cb)
                self.plug_checks.append(cb)
            self.note.setText(SYMBOL_NOTE[self.os_key()])
            self.offline.setVisible(self.os_key() == "windows")

        def set_image(self, path):
            self.image.setText(path)

        def image_changed(self):
            p = self.image.text()
            if p:
                self.os.setCurrentIndex({"windows": 0, "linux": 1, "mac": 2}[guess_os(p)])

        def start(self):
            img = self.image.text()
            if not img or not os.path.isfile(img):
                self.errors.setText("Choose a memory image file.")
                self.errors.show()
                return
            self.errors.hide()
            plugins = [cb.property("spec") for cb in self.plug_checks if cb.isChecked()]
            if not plugins:
                self.errors.setText("Pick at least one plugin.")
                self.errors.show()
                return
            out = self.out.text() or os.path.join(os.path.dirname(img), os.path.splitext(os.path.basename(img))[0]
                                                  + "_volatility_" + time.strftime("%Y%m%d-%H%M%S"))
            self.outdir = out
            args = ["--analyze", img, "--out", out, "--os", self.os_key(), "--plugins", ",".join(plugins)]
            if self.symbols.text():
                args += ["--symbols", self.symbols.text()]
            if self.offline.isChecked() and self.os_key() == "windows":
                args.append("--offline")
            for i in reversed(range(self.step_box.count())):
                w = self.step_box.itemAt(i).widget()
                if w:
                    w.deleteLater()
            self.steps = {}
            for spec in plugins:
                s = Step(spec.split("|")[0])
                self.steps[spec.split("|")[0]] = s
                self.step_box.addWidget(s)
            self.bar.setRange(0, len(plugins))
            self.bar.setValue(0)
            self.logv.clear()
            self.prog_card.show()
            self.res_card.hide()
            prog = self_command(args)
            self.proc = QProcess(self)
            self.proc.readyReadStandardOutput.connect(self.read_out)
            self.proc.readyReadStandardError.connect(lambda: self.logv.add(
                bytes(self.proc.readAllStandardError()).decode("utf-8", "replace"), DIM))
            self.proc.finished.connect(self.finished)
            self.proc.start(prog[0], prog[1:])
            self.run_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.status.setText("Hashing the image…")
            self.status.setStyleSheet(f"color:{TEXT};")
            self._buf = ""

        def read_out(self):
            self._buf += bytes(self.proc.readAllStandardOutput()).decode("utf-8", "replace")
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                try:
                    ev = json.loads(line)
                except ValueError:
                    if line.strip():
                        self.logv.add(line, DIM)
                    continue
                t = ev.get("t")
                if t == "plugin_start":
                    key = self._key(ev["plugin"])
                    if key in self.steps:
                        self.steps[key].set("running", "running…")
                    self.status.setText(f"Running {ev['plugin']}  ({ev['index'] + 1}/{ev['total']})")
                    self.logv.add(f"== {ev['plugin']}", BONE)
                elif t == "plugin_end":
                    key = self._key(ev["plugin"])
                    st = ev.get("status")
                    txt = (f"{ev.get('rows', 0)} rows · {ev.get('seconds', 0)}s" if st == "ok"
                           else "not in this Volatility build" if st == "missing" else "failed")
                    if key in self.steps:
                        self.steps[key].set(st, txt)
                    if ev.get("error"):
                        self.logv.add(ev["error"], RED)
                    self.bar.setValue(self.bar.value() + 1)
                elif t == "log":
                    self.logv.add(ev.get("msg", ""), MUTED)
                elif t == "start":
                    self.logv.add(f"Volatility {ev.get('volatility') or '?'} · {ev.get('os')} · {ev.get('image')}", MUTED)

        def _key(self, plugin):
            for k in self.steps:
                if plugin == k or plugin in [s for s in PLUGINS_ALL.get(k, [])]:
                    return k
            return plugin

        def finished(self, code, status):
            self.run_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status.setText("Analysis complete." if code == 0 else "Analysis stopped.")
            self.status.setStyleSheet(f"color:{GREEN if code == 0 else AMBER};")
            self.load_results()

        def stop(self):
            if self.outdir:
                try:
                    os.makedirs(self.outdir, exist_ok=True)
                    open(os.path.join(self.outdir, STOP_FILE), "w").close()
                except OSError:
                    pass
            self.stop_btn.setEnabled(False)
            self.status.setText("Stopping…")

        def kill(self):
            if self.proc and self.proc.state() != QProcess.NotRunning:
                self.stop()

        def load_results(self):
            if not self.outdir or not os.path.isdir(self.outdir):
                return
            files = sorted(f for f in os.listdir(self.outdir) if f.endswith(".csv") and os.path.getsize(os.path.join(self.outdir, f)))
            self.res_pick.blockSignals(True)
            self.res_pick.clear()
            for f in files:
                self.res_pick.addItem(f[:-4], os.path.join(self.outdir, f))
            self.res_pick.blockSignals(False)
            if files:
                self.res_card.show()
                self.show_result()

        def show_result(self):
            import csv
            p = self.res_pick.currentData()
            if not p:
                return
            rows = []
            try:
                with open(p, newline="", encoding="utf-8", errors="replace") as fh:
                    r = csv.reader(fh)
                    header = next(r, [])
                    for i, row in enumerate(r):
                        if i >= 5000:
                            break
                        rows.append(row)
            except OSError:
                return
            self.table.clear()
            self.table.setColumnCount(len(header))
            self.table.setHorizontalHeaderLabels(header)
            self.table.setRowCount(len(rows))
            for i, row in enumerate(rows):
                for j, v in enumerate(row[:len(header)]):
                    self.table.setItem(i, j, QTableWidgetItem(v))
            self.table.resizeColumnsToContents()
            for j in range(self.table.columnCount()):
                if self.table.columnWidth(j) > 420:
                    self.table.setColumnWidth(j, 420)
            self.res_info.setText(f"{len(rows)} row(s) shown{' (first 5000)' if len(rows) >= 5000 else ''} · {p}")
            self.apply_filter()

        def apply_filter(self):
            q = self.filter.text().lower().strip()
            for i in range(self.table.rowCount()):
                if not q:
                    self.table.setRowHidden(i, False)
                    continue
                hit = any(q in (self.table.item(i, j).text().lower() if self.table.item(i, j) else "")
                          for j in range(self.table.columnCount()))
                self.table.setRowHidden(i, not hit)

    PLUGINS_ALL = {spec.split("|")[0]: spec.split("|") for lst in PLUGINS.values() for spec, _, _ in lst}

    # ------------------------------------------------------------------ main window
    class Main(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle(f"{APP_NAME}")
            self.resize(1180, 860)
            self.setMinimumSize(QSize(900, 620))
            root = QWidget()
            root.setObjectName("root")
            h = QHBoxLayout(root)
            h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(0)
            side = QFrame()
            side.setObjectName("sidebar")
            side.setFixedWidth(230)
            sl = QVBoxLayout(side)
            sl.setContentsMargins(0, 22, 0, 16)
            sl.setSpacing(8)
            brand = QHBoxLayout()
            brand.setContentsMargins(18, 0, 18, 10)
            logo = QLabel()
            dpr = self.devicePixelRatioF()
            pm = QPixmap(asset("skull.png"))
            if not pm.isNull():
                pm = pm.scaledToHeight(int(40 * dpr), Qt.SmoothTransformation)
                pm.setDevicePixelRatio(dpr)
                logo.setPixmap(pm)
            brand.addWidget(logo)
            bt = QVBoxLayout()
            bt.setSpacing(0)
            bt.addWidget(label("LANDULL", "brand"))
            bt.addWidget(label("TRIAGE", "brandSub"))
            brand.addLayout(bt)
            brand.addStretch(1)
            sl.addLayout(brand)
            self.nav = QListWidget()
            self.nav.setObjectName("nav")
            for t in ("Collect evidence", "Analyze memory"):
                QListWidgetItem(t, self.nav)
            self.nav.setFixedHeight(90)
            sl.addWidget(self.nav)
            sl.addStretch(1)
            who = label(("Administrator" if PLATFORM == "windows" else "root") if ADMIN else "Standard user", "help")
            who.setContentsMargins(18, 0, 18, 0)
            sl.addWidget(who)
            ab = QPushButton(f"About · v{VERSION}")
            ab.setObjectName("linkButton")
            ab.setCursor(Qt.PointingHandCursor)
            ab.clicked.connect(self.about)
            sl.addWidget(ab, 0, Qt.AlignLeft)
            h.addWidget(side)
            self.stack = QStackedWidget()
            self.collect = CollectPage()
            self.analyze = AnalyzePage()
            self.stack.addWidget(self.collect)
            self.stack.addWidget(self.analyze)
            h.addWidget(self.stack, 1)
            self.setCentralWidget(root)
            self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
            self.nav.setCurrentRow(0)
            self.collect.analyze_image.connect(self.go_analyze)

        def go_analyze(self, path):
            self.analyze.set_image(path)
            self.nav.setCurrentRow(1)

        def about(self):
            QMessageBox.about(self, APP_NAME,
                              f"<b>{APP_NAME}</b> v{VERSION}<br><br>"
                              "Live-response evidence collection and memory analysis for Windows, macOS and Linux.<br><br>"
                              f"<a style='color:#e6e3dd' href='{GITHUB}'>{GITHUB.replace('https://', '')}</a><br><br>"
                              "MIT License. Bundles WinPmem (Apache 2.0), AVML (MIT) and Volatility 3 (VSL). "
                              "Only collect from systems you own or are authorized to examine.")

        def closeEvent(self, e):
            busy = self.collect.is_running() or (self.analyze.proc and self.analyze.proc.state() != QProcess.NotRunning)
            if busy:
                r = QMessageBox.question(self, "Still running",
                                         "A collection or analysis is still running. Stop it and quit?\n\n"
                                         "A collection stops after its current step and still writes its report.")
                if r != QMessageBox.Yes:
                    e.ignore()
                    return
                self.collect.kill()
                self.analyze.kill()
            e.accept()

    QApplication.setApplicationName(APP_NAME)
    QApplication.setOrganizationName("Landull")
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setWindowIcon(QIcon(asset("icon.png")))
    app.setStyleSheet(qss())

    def excepthook(t, v, tb):
        msg = "".join(traceback.format_exception(t, v, tb))
        log("ERROR " + msg)
        if sys.__stderr__:
            sys.__stderr__.write(msg)
        try:
            QMessageBox.critical(None, APP_NAME, f"Something went wrong:\n\n{v}\n\nDetails were written to:\n{log_path()}")
        except Exception:
            pass
    sys.excepthook = excepthook

    win = Main()
    win.show()
    if os.environ.get("LANDULL_SCREENSHOT"):          # automated visual checks
        target = os.environ["LANDULL_SCREENSHOT"]
        page = os.environ.get("LANDULL_SCREENSHOT_PAGE", "")

        def snap():
            if page == "analyze":
                win.nav.setCurrentRow(1)
            QTimer.singleShot(400, lambda: (win.grab().save(target), app.quit()))
        QTimer.singleShot(600, snap)
    log(f"start v{VERSION} frozen={getattr(sys, 'frozen', False)} admin={ADMIN}")
    return app.exec()


# ============================================================== entry
def main():
    sys.path.insert(0, base_dir())
    argv = sys.argv[1:]
    if argv and argv[0] in ("--collect", "--analyze", "--vol", "--raw-copy", "--version"):
        _fix_stdio()
        mode, rest = argv[0], argv[1:]
        if mode == "--version":
            from triage import VERSION
            print(f"LandullTriage {VERSION}")
            return 0
        if mode == "--collect":
            from triage.collect import main as collect_main
            rc = collect_main(rest)
            _restore_owner(rest)
            return rc
        if mode == "--analyze":
            from triage.analyze import main as analyze_main
            return analyze_main(rest)
        if mode == "--vol":
            from triage.analyze import vol_main
            return vol_main(rest)
        if mode == "--raw-copy":   # copy a locked file off the NTFS volume: --raw-copy <src> <dest>
            from triage.ntfsraw import raw_copy
            n = raw_copy(rest[0], rest[1])
            print(f"copied {n} bytes")
            return 0
    return gui_main()


def _restore_owner(args):
    """When the collector ran as root for a normal user, hand the case folder back to that user."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0 or "--config" not in args:
        return
    try:
        cfg_path = args[args.index("--config") + 1]
        with open(cfg_path, encoding="utf-8") as fh:
            cfg = json.load(fh)
        uid, gid = cfg.get("owner_uid"), cfg.get("owner_gid")
        if uid is None or uid == 0:
            return
        case_dir = args[args.index("--case-dir") + 1] if "--case-dir" in args else os.path.dirname(cfg_path)
        targets = [case_dir]
        if os.path.exists(case_dir.rstrip("/") + ".zip"):
            targets.append(case_dir.rstrip("/") + ".zip")
        for t in targets:
            os.lchown(t, uid, gid)
            for dp, dns, fns in os.walk(t):
                for n in dns + fns:
                    try:
                        os.lchown(os.path.join(dp, n), uid, gid)
                    except OSError:
                        pass
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
