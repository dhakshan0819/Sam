#!/usr/bin/env python3
"""
SAM Database Password Manager — Offline Windows local-account password reset tool.

Intended use: forensic / CTF scenarios where you have physical possession of a
machine and explicit authorization to recover access to it (e.g. a locked
laptop handed to you for a security exercise). This tool mounts an NTFS
partition, locates the SAM registry hive, lists local user accounts, and
clears a selected account's password using chntpw.

Requires root privileges (mounting disks, writing to them). Run with:
    sudo python3 sam_manager.py
"""

import sys
import os
import shutil
import subprocess
import datetime
import traceback

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QComboBox, QPushButton, QListWidget, QMessageBox, QLabel, QLineEdit,
    QTextEdit, QGroupBox, QCheckBox, QProgressBar, QSplitter, QFrame
)
from PyQt6.QtCore import Qt, QProcess
from PyQt6.QtGui import QFont, QTextCursor

# ----------------------------------------------------------------------------
# Dependency management (Arch Linux / pacman)
# ----------------------------------------------------------------------------

# Maps the binary we need -> the pacman package that provides it
REQUIRED_TOOLS = {
    "chntpw": "chntpw",
    "lsblk": "util-linux",
    "mount": "util-linux",
    "umount": "util-linux",
    "blkid": "util-linux",
    "ntfs-3g": "ntfs-3g",
}


def find_missing_tools():
    missing = {}
    for binary, pkg in REQUIRED_TOOLS.items():
        if shutil.which(binary) is None:
            missing[binary] = pkg
    return missing


def install_packages(packages, log_callback=None):
    """Install packages via pacman. Must be run as root (the whole app requires root)."""
    pkgs = sorted(set(packages))
    if not pkgs:
        return True, "Nothing to install."
    cmd = ["pacman", "-S", "--needed", "--noconfirm"] + pkgs
    if log_callback:
        log_callback(f"$ {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if log_callback:
            if proc.stdout:
                log_callback(proc.stdout)
            if proc.stderr:
                log_callback(proc.stderr)
        return proc.returncode == 0, proc.stdout + proc.stderr
    except FileNotFoundError:
        return False, "pacman not found — this installer is for Arch-based systems only."
    except subprocess.TimeoutExpired:
        return False, "pacman install timed out."
    except Exception as e:
        return False, str(e)


# ----------------------------------------------------------------------------
# Main window
# ----------------------------------------------------------------------------

class SAMManagerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.mount_point = "/mnt/sam_recovery"
        self.sam_path = ""
        self.backup_dir = os.path.expanduser("~/sam_recovery_backups")
        self.current_partition = ""
        self.is_mounted_rw = False

        self.initUI()
        self.check_root()
        self.check_dependencies()
        self.scan_partitions()

    # -- UI setup -------------------------------------------------------

    def initUI(self):
        self.setWindowTitle("SAM Database Password Manager — Offline Recovery Tool")
        self.setGeometry(100, 100, 900, 700)

        root = QVBoxLayout()

        # Status banner
        self.status_label = QLabel("Initializing...")
        self.status_label.setStyleSheet(
            "padding: 6px; background-color: #333; color: white; font-weight: bold;"
        )
        root.addWidget(self.status_label)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # --- Top panel: controls ---
        top_widget = QWidget()
        top = QVBoxLayout(top_widget)

        # Step 1: Partition
        grp1 = QGroupBox("1. Select Target Partition")
        g1 = QVBoxLayout()
        row1 = QHBoxLayout()
        self.partition_combo = QComboBox()
        row1.addWidget(self.partition_combo, stretch=1)
        self.btn_scan = QPushButton("Rescan Partitions")
        self.btn_scan.clicked.connect(self.scan_partitions)
        row1.addWidget(self.btn_scan)
        g1.addLayout(row1)

        row1b = QHBoxLayout()
        self.btn_mount_ro = QPushButton("Mount Read-Only && Load SAM")
        self.btn_mount_ro.clicked.connect(lambda: self.mount_and_load_sam(readonly=True))
        row1b.addWidget(self.btn_mount_ro)
        self.btn_unmount = QPushButton("Unmount")
        self.btn_unmount.clicked.connect(self.unmount_partition)
        row1b.addWidget(self.btn_unmount)
        g1.addLayout(row1b)
        grp1.setLayout(g1)
        top.addWidget(grp1)

        # Step 2: Users
        grp2 = QGroupBox("2. Detected User Accounts")
        g2 = QVBoxLayout()
        self.user_list = QListWidget()
        g2.addWidget(self.user_list)
        grp2.setLayout(g2)
        top.addWidget(grp2)

        # Step 3: Actions
        grp3 = QGroupBox("3. Password Actions (requires read-write remount)")
        g3 = QVBoxLayout()

        self.chk_backup = QCheckBox("Back up SAM hive before writing (recommended)")
        self.chk_backup.setChecked(True)
        g3.addWidget(self.chk_backup)

        row3 = QHBoxLayout()
        self.btn_remount_rw = QPushButton("Remount Read-Write")
        self.btn_remount_rw.clicked.connect(self.remount_rw)
        row3.addWidget(self.btn_remount_rw)

        self.btn_blank = QPushButton("Clear / Blank Password")
        self.btn_blank.clicked.connect(self.blank_password)
        self.btn_blank.setStyleSheet("font-weight: bold; color: #b00;")
        row3.addWidget(self.btn_blank)
        g3.addLayout(row3)

        self.btn_verify = QPushButton("Verify Password Was Cleared")
        self.btn_verify.clicked.connect(self.verify_password_cleared)
        g3.addWidget(self.btn_verify)

        grp3.setLayout(g3)
        top.addWidget(grp3)

        splitter.addWidget(top_widget)

        # --- Bottom panel: log ---
        bottom_widget = QWidget()
        bottom = QVBoxLayout(bottom_widget)
        bottom.addWidget(QLabel("Activity Log:"))
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFont(QFont("monospace", 9))
        bottom.addWidget(self.log_box)
        splitter.addWidget(bottom_widget)

        splitter.setSizes([480, 220])
        root.addWidget(splitter)

        self.setLayout(root)

    # -- Logging / status -------------------------------------------------

    def log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_box.append(f"[{ts}] {msg}")
        self.log_box.moveCursor(QTextCursor.MoveOperation.End)

    def set_status(self, msg, ok=True):
        self.status_label.setText(msg)
        color = "#2d6a2d" if ok else "#8a1f1f"
        self.status_label.setStyleSheet(
            f"padding: 6px; background-color: {color}; color: white; font-weight: bold;"
        )

    # -- Root / dependency checks ------------------------------------------

    def check_root(self):
        if os.geteuid() != 0:
            QMessageBox.critical(
                self, "Root Required",
                "This tool must be run as root (it mounts disks and edits raw partitions).\n\n"
                "Re-run with: sudo python3 sam_manager.py"
            )
            self.log("ERROR: not running as root.")
            self.set_status("Not running as root — functionality disabled.", ok=False)
            self.setDisabled(True)
            return
        self.log("Running as root: OK.")

    def check_dependencies(self):
        missing = find_missing_tools()
        if not missing:
            self.log("All dependencies present (chntpw, util-linux, ntfs-3g).")
            self.set_status("Ready.")
            return

        pkgs = sorted(set(missing.values()))
        self.log(f"Missing tools: {', '.join(missing.keys())} (packages: {', '.join(pkgs)})")

        reply = QMessageBox.question(
            self, "Missing Dependencies",
            "The following required tools are missing:\n\n"
            + "\n".join(f"  - {b} (package: {p})" for b, p in missing.items())
            + "\n\nInstall them now via pacman?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.set_status("Installing dependencies...")
            ok, output = install_packages(pkgs, log_callback=self.log)
            if ok:
                self.log("Dependency installation succeeded.")
                self.set_status("Ready.")
            else:
                self.log(f"Dependency installation failed:\n{output}")
                self.set_status("Dependency installation failed.", ok=False)
                QMessageBox.critical(self, "Install Failed", "Could not install dependencies. See log.")
        else:
            self.set_status("Missing dependencies — some features will fail.", ok=False)

    # -- Partition scanning -------------------------------------------------

    def scan_partitions(self):
        self.partition_combo.clear()
        try:
            output = subprocess.check_output(
                ["lsblk", "-pnro", "NAME,FSTYPE,SIZE,LABEL"], text=True
            )
            count = 0
            for line in output.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split(None, 3)
                if len(parts) >= 2 and ("ntfs" in parts[1].lower() or "fuseblk" in parts[1].lower()):
                    name, fstype, size = parts[0], parts[1], parts[2]
                    label = parts[3] if len(parts) > 3 else ""
                    display = f"{name} ({size}) {fstype}" + (f" [{label}]" if label else "")
                    self.partition_combo.addItem(display, userData=name)
                    count += 1
            self.log(f"Scan complete: {count} NTFS/fuseblk partition(s) found.")
            if count == 0:
                self.log("No NTFS partitions detected. Ensure the drive is connected.")
        except Exception as e:
            self.log(f"ERROR scanning partitions: {e}")
            QMessageBox.critical(self, "Error", f"Failed to scan partitions: {e}")

    # -- Mount / unmount ------------------------------------------------

    def _current_device(self):
        idx = self.partition_combo.currentIndex()
        if idx < 0:
            return None
        return self.partition_combo.itemData(idx)

    def mount_and_load_sam(self, readonly=True):
        device = self._current_device()
        if not device:
            QMessageBox.warning(self, "Warning", "No partition selected.")
            return

        os.makedirs(self.mount_point, exist_ok=True)

        # Clean unmount of anything currently there first
        subprocess.run(["umount", self.mount_point], stderr=subprocess.DEVNULL)

        mode = "ro" if readonly else "rw"
        self.log(f"Mounting {device} at {self.mount_point} ({mode})...")
        res = subprocess.run(
            ["mount", "-t", "ntfs-3g", "-o", mode, device, self.mount_point],
            capture_output=True, text=True
        )
        if res.returncode != 0:
            self.log(f"Mount failed: {res.stderr.strip()}")
            QMessageBox.critical(self, "Error", f"Failed to mount {device}:\n{res.stderr.strip()}")
            return

        self.current_partition = device
        self.is_mounted_rw = not readonly
        self.log(f"Mounted {device} successfully ({mode}).")

        # Locate SAM hive, case-insensitively
        sam_path = self._find_sam_path()
        if not sam_path:
            self.log("SAM hive not found under Windows/System32/config.")
            QMessageBox.critical(self, "Error", "SAM hive not found on selected partition.")
            return

        self.sam_path = sam_path
        self.log(f"SAM hive located at: {self.sam_path}")
        self.load_users()
        self.set_status(f"Loaded SAM hive from {device} ({mode}).")

    def _find_sam_path(self):
        candidates = [
            os.path.join(self.mount_point, "Windows", "System32", "config", "SAM"),
            os.path.join(self.mount_point, "windows", "system32", "config", "sam"),
            os.path.join(self.mount_point, "WINDOWS", "SYSTEM32", "CONFIG", "SAM"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        # Fall back to a case-insensitive walk (handles unusual mounts)
        config_dir_guess = os.path.join(self.mount_point, "Windows", "System32", "config")
        base = os.path.join(self.mount_point)
        try:
            for root, dirs, files in os.walk(base):
                if root.lower().endswith(os.path.join("system32", "config")):
                    for f in files:
                        if f.lower() == "sam":
                            return os.path.join(root, f)
        except Exception:
            pass
        return None

    def remount_rw(self):
        if not self.current_partition:
            QMessageBox.warning(self, "Warning", "Mount a partition first.")
            return
        self.log(f"Remounting {self.current_partition} as read-write...")
        res = subprocess.run(
            ["mount", "-o", "remount,rw", self.mount_point],
            capture_output=True, text=True
        )
        if res.returncode != 0:
            self.log(f"Remount rw failed: {res.stderr.strip()}")
            QMessageBox.critical(self, "Error", f"Failed to remount read-write:\n{res.stderr.strip()}")
            return
        self.is_mounted_rw = True
        self.log("Remounted read-write successfully.")
        self.set_status(f"{self.current_partition} mounted READ-WRITE — be careful.", ok=False)

    def unmount_partition(self):
        res = subprocess.run(["umount", self.mount_point], capture_output=True, text=True)
        if res.returncode == 0:
            self.log(f"Unmounted {self.mount_point}.")
            self.current_partition = ""
            self.is_mounted_rw = False
            self.sam_path = ""
            self.user_list.clear()
            self.set_status("Unmounted. Ready.")
        else:
            self.log(f"Unmount failed: {res.stderr.strip()}")
            QMessageBox.warning(self, "Warning", f"Unmount failed:\n{res.stderr.strip()}")

    # -- User listing -----------------------------------------------------

    def load_users(self):
        self.user_list.clear()
        if not self.sam_path:
            return
        try:
            cmd = ["chntpw", "-l", self.sam_path]
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
            self.log("---- chntpw -l output ----")
            for line in output.splitlines():
                self.log(line)
            self.log("---------------------------")

            users = self._parse_chntpw_user_list(output)
            if not users:
                self.log("WARNING: no users parsed from chntpw output; check log above for format.")
            for rid, username in users:
                self.user_list.addItem(f"{username} (RID: {rid})")

            if users:
                QMessageBox.information(self, "Success", f"Loaded {len(users)} user account(s).")
        except subprocess.CalledProcessError as e:
            self.log(f"chntpw -l failed: {e.output}")
            QMessageBox.critical(self, "Error", f"Failed to parse SAM: {e.output}")
        except Exception as e:
            self.log(f"ERROR loading users: {e}\n{traceback.format_exc()}")
            QMessageBox.critical(self, "Error", f"Failed to parse SAM: {e}")

    @staticmethod
    def _parse_chntpw_user_list(output):
        """
        chntpw -l typically prints a table like:

        | RID -|---------- Username ------------| Admin? |- Lock? --|
        | 01f4 | Administrator                   | ADMIN  |          |
        | 01f5 | Guest                           |        | dis/lock |
        | 03e8 | bob                              |        |          |

        Parse any line that has >=2 '|'-delimited fields where the first
        looks like a hex RID and the second is a non-empty username.
        """
        users = []
        for line in output.splitlines():
            if "|" not in line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 3:
                continue
            rid_field = parts[1].strip()
            name_field = parts[2].strip()
            if not rid_field or not name_field:
                continue
            # RID field should look hex-ish (e.g. 01f4) — skip header rows
            rid_clean = rid_field.replace("<", "").replace(">", "").strip()
            is_hexish = all(c in "0123456789abcdefABCDEF" for c in rid_clean) and len(rid_clean) >= 3
            if not is_hexish:
                continue
            users.append((rid_clean, name_field))
        return users

    # -- Password actions ---------------------------------------------------

    def blank_password(self):
        if not self.is_mounted_rw:
            QMessageBox.warning(
                self, "Read-Only Mount",
                "The partition is currently mounted read-only. "
                "Click 'Remount Read-Write' before clearing a password."
            )
            return

        selected_item = self.user_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Warning", "Select a user account first.")
            return

        username = selected_item.text().split(" (RID:")[0]

        confirm = QMessageBox.question(
            self, "Confirm",
            f"Clear the password for '{username}'?\n\n"
            "This directly modifies the SAM hive on the mounted disk.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        if self.chk_backup.isChecked():
            if not self._backup_hive():
                reply = QMessageBox.question(
                    self, "Backup Failed",
                    "Backing up the SAM hive failed. Continue without a backup?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return

        try:
            self.log(f"Clearing password for '{username}'...")
            process = subprocess.Popen(
                ["chntpw", "-u", username, self.sam_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            # chntpw interactive menu: '1' = clear password, 'q' = quit edits,
            # 'y' = write hive back to disk. Different versions prompt slightly
            # differently, so we send a generous, newline-terminated sequence.
            stdout, _ = process.communicate(input="1\ny\n", timeout=30)
            self.log("---- chntpw -u output ----")
            for line in stdout.splitlines():
                self.log(line)
            self.log("---------------------------")

            success_markers = ["Hives that have changed", "Write hive files", "has been written"]
            wrote_ok = any(m.lower() in stdout.lower() for m in success_markers)

            if wrote_ok or process.returncode == 0:
                self.log(f"Password cleared for '{username}'.")
                QMessageBox.information(
                    self, "Success",
                    f"Password cleared for {username}!\n\n"
                    "Use 'Verify Password Was Cleared' to double-check, then unmount "
                    "before removing the disk."
                )
            else:
                self.log("chntpw did not report a successful write.")
                QMessageBox.critical(self, "Error", "Failed to update SAM hive — check the log.")
        except subprocess.TimeoutExpired:
            process.kill()
            self.log("ERROR: chntpw timed out.")
            QMessageBox.critical(self, "Error", "chntpw timed out.")
        except Exception as e:
            self.log(f"ERROR: {e}\n{traceback.format_exc()}")
            QMessageBox.critical(self, "Error", f"Execution error: {e}")

    def verify_password_cleared(self):
        selected_item = self.user_list.currentItem()
        if not selected_item or not self.sam_path:
            QMessageBox.warning(self, "Warning", "Select a user and load a SAM hive first.")
            return
        username = selected_item.text().split(" (RID:")[0]
        try:
            output = subprocess.check_output(["chntpw", "-l", self.sam_path], text=True)
            self.log("Re-checked user list after edit:")
            for line in output.splitlines():
                self.log(line)
            QMessageBox.information(
                self, "Verification",
                f"Re-read the SAM hive. Check the log panel for {username}'s current "
                "lock/blank status (chntpw -l does not always show a 'blank' flag "
                "explicitly — boot the target machine to confirm login works)."
            )
        except Exception as e:
            self.log(f"Verification failed: {e}")
            QMessageBox.critical(self, "Error", f"Verification failed: {e}")

    # -- Backup -------------------------------------------------------------

    def _backup_hive(self):
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = os.path.join(self.backup_dir, f"SAM_backup_{ts}")
            shutil.copy2(self.sam_path, dest)
            self.log(f"Backed up SAM hive to {dest}")
            return True
        except Exception as e:
            self.log(f"Backup failed: {e}")
            return False

    # -- Cleanup --------------------------------------------------------

    def closeEvent(self, event):
        if self.current_partition:
            subprocess.run(["umount", self.mount_point], stderr=subprocess.DEVNULL)
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SAMManagerGUI()
    window.show()
    sys.exit(app.exec())
