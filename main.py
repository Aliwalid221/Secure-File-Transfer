import sys
import os
from PyQt5.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PyQt5.QtCore import QLocale, Qt

from db_manager import DatabaseManager
from crypto_engine import CryptoEngine
from dlp_engine import DLPEngine
from sharing_server import SharingServer


QLocale.setDefault(QLocale(QLocale.English, QLocale.UnitedStates))

APP_STYLE = """
QWidget { background: #f4f6f8; color: #1f2937; font: 13px Arial, sans-serif; }
QTabWidget::pane, QGroupBox, QTableWidget { background: #ffffff; border: 1px solid #d9e0ea; border-radius: 8px; }
QTabBar::tab { background: #e8edf3; border: 1px solid #d9e0ea; border-bottom: 0; padding: 10px 18px; margin-right: 4px; border-top-left-radius: 6px; border-top-right-radius: 6px; }
QTabBar::tab:selected { background: #ffffff; color: #0f766e; }
QGroupBox { font-weight: 700; margin-top: 12px; padding-top: 18px; }
QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 6px; }
QLabel#fileLabel { background: #f8fafc; border: 1px solid #d9e0ea; border-radius: 6px; color: #4b5563; padding: 10px 12px; }
QLineEdit, QSpinBox, QTextEdit { background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px; selection-background-color: #99f6e4; }
QLineEdit:focus, QSpinBox:focus, QTextEdit:focus { border: 1px solid #0f766e; }
QPushButton { background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 9px 16px; font-weight: 600; }
QPushButton:hover { background: #f8fafc; border-color: #94a3b8; }
QPushButton#primaryButton { background: #0f766e; border-color: #0f766e; color: #ffffff; }
QPushButton#primaryButton:hover { background: #115e59; }
QTableWidget { alternate-background-color: #f8fafc; gridline-color: #e5e7eb; }
QHeaderView::section { background: #f1f5f9; border: 0; border-right: 1px solid #d9e0ea; color: #334155; font-weight: 700; padding: 8px; }
QStatusBar { background: #ffffff; border-top: 1px solid #d9e0ea; color: #64748b; }
"""


class SecureTransferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Transfer & DLP System")
        self.resize(960, 680)
        self.setMinimumSize(860, 600)
        self.setStyleSheet(APP_STYLE)

        self.db = DatabaseManager()
        self.dlp = DLPEngine(self.db)
        self.server = SharingServer()
        self.server.start()

        self.setup_ui()
        self.db.log_event("APP_STARTUP", details="GUI application started")
        self.statusBar().showMessage("Local sharing server running on http://localhost:5000")

    def setup_ui(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.share_tab = QWidget()
        self.setup_share_tab()
        self.tabs.addTab(self.share_tab, "Encrypt & Share")

        self.decrypt_tab = QWidget()
        self.setup_decrypt_tab()
        self.tabs.addTab(self.decrypt_tab, "Decrypt")

        self.logs_tab = QWidget()
        self.setup_logs_tab()
        self.tabs.addTab(self.logs_tab, "Audit Logs")

        self.policies_tab = QWidget()
        self.setup_policies_tab()
        self.tabs.addTab(self.policies_tab, "DLP Policies")

    def setup_share_tab(self):
        layout = self.create_page_layout(self.share_tab)

        self.file_label = self.add_file_picker(
            layout,
            "1. Select file",
            "No file selected",
            "Select File",
            self.select_file,
        )

        settings_group, settings_layout = self.create_group("2. Security settings")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.expiry_input = QSpinBox()
        self.expiry_input.setLocale(QLocale(QLocale.English, QLocale.UnitedStates))
        self.expiry_input.setRange(1, 1440)
        self.expiry_input.setValue(15)

        settings_layout.addLayout(self.create_form([
            ("Encryption password", self.password_input),
            ("Link expiry (minutes)", self.expiry_input),
        ]))
        layout.addWidget(settings_group)

        result_group, result_layout = self.create_group("3. Encrypt and share")
        self.process_btn = self.create_button("Scan, Encrypt & Generate Link", primary=True)
        self.process_btn.clicked.connect(self.process_and_share)
        result_layout.addLayout(self.button_row(self.process_btn))

        result_layout.addWidget(QLabel("Generated link"))
        self.link_output = QTextEdit()
        self.link_output.setReadOnly(True)
        self.link_output.setMaximumHeight(110)
        result_layout.addWidget(self.link_output)

        self.copy_link_btn = self.create_button("Copy Link")
        self.copy_link_btn.clicked.connect(self.copy_link)
        result_layout.addLayout(self.button_row(self.copy_link_btn))
        layout.addWidget(result_group)
        layout.addStretch()

        self.selected_file = None
        self.current_link = ""

    def setup_decrypt_tab(self):
        layout = self.create_page_layout(self.decrypt_tab)

        self.dec_file_label = self.add_file_picker(
            layout,
            "Encrypted file",
            "No encrypted file selected",
            "Select Encrypted File (.enc)",
            self.select_dec_file,
        )

        decrypt_group, decrypt_layout = self.create_group("Decrypt")
        self.dec_password_input = QLineEdit()
        self.dec_password_input.setEchoMode(QLineEdit.Password)
        decrypt_layout.addLayout(self.create_form([("Decryption password", self.dec_password_input)]))

        self.decrypt_btn = self.create_button("Decrypt File", primary=True)
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        decrypt_layout.addLayout(self.button_row(self.decrypt_btn))
        layout.addWidget(decrypt_group)
        layout.addStretch()

        self.dec_selected_file = None

    def setup_logs_tab(self):
        layout = self.create_page_layout(self.logs_tab)
        self.log_table = QTableWidget()
        self.configure_table(self.log_table, ["Timestamp", "Action", "File", "Status", "Details"])
        layout.addWidget(self.log_table)

        self.refresh_logs_btn = self.create_button("Refresh Logs")
        self.refresh_logs_btn.clicked.connect(self.refresh_logs)
        layout.addLayout(self.button_row(self.refresh_logs_btn))

        self.refresh_logs()

    def setup_policies_tab(self):
        layout = self.create_page_layout(self.policies_tab)
        self.policy_table = QTableWidget()
        self.configure_table(self.policy_table, ["Policy Name", "Type", "Pattern"])
        layout.addWidget(self.policy_table)

        self.refresh_policies()

    def create_page_layout(self, widget):
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        return layout

    def create_group(self, title):
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        layout.setContentsMargins(16, 18, 16, 16)
        layout.setSpacing(12)
        return group, layout

    def add_file_picker(self, page_layout, title, empty_text, button_text, slot):
        group, layout = self.create_group(title)
        label = QLabel(empty_text)
        label.setObjectName("fileLabel")

        button = self.create_button(button_text)
        button.clicked.connect(slot)

        row = QHBoxLayout()
        row.addWidget(label, 1)
        row.addWidget(button)
        layout.addLayout(row)
        page_layout.addWidget(group)
        return label

    def create_form(self, rows):
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignLeft)
        form.setFormAlignment(Qt.AlignTop)
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(12)
        for label, widget in rows:
            form.addRow(label, widget)
        return form

    def create_button(self, text, primary=False):
        button = QPushButton(text)
        if primary:
            button.setObjectName("primaryButton")
        return button

    def button_row(self, button):
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(button)
        return row

    def configure_table(self, table, headers):
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setWordWrap(False)

    def set_selected_file(self, label, file_path):
        label.setText(os.path.basename(file_path))

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Share")
        if file_path:
            self.selected_file = file_path
            self.set_selected_file(self.file_label, file_path)

    def select_dec_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Encrypted File", "", "Encrypted Files (*.enc)")
        if file_path:
            self.dec_selected_file = file_path
            self.set_selected_file(self.dec_file_label, file_path)

    def process_and_share(self):
        if not self.selected_file:
            QMessageBox.warning(self, "Error", "Please select a file first.")
            return

        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter an encryption password.")
            return

        allowed, reason, policy = self.dlp.scan_file(self.selected_file)
        if not allowed:
            QMessageBox.critical(self, "DLP Violation", f"File blocked by DLP Policy: {policy}\n\nReason: {reason}")
            self.refresh_logs()
            return

        encrypted_path = self.selected_file + ".enc"
        try:
            CryptoEngine.encrypt_file(self.selected_file, encrypted_path, password)
            self.db.log_event("ENCRYPTION", filename=self.selected_file, status="SUCCESS", details="File encrypted successfully")
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", str(e))
            self.db.log_event("ENCRYPTION", filename=self.selected_file, status="FAILED", details=str(e))
            return

        expiry_min = self.expiry_input.value()
        link, expiry_at = self.server.generate_link(encrypted_path, expires_in_minutes=expiry_min)
        self.current_link = link
        self.db.log_event("LINK_GENERATED", filename=encrypted_path, status="SUCCESS", details=f"Expires at: {expiry_at}")

        self.link_output.setPlainText(f"Link: {link}\nExpires at: {expiry_at}\nPassword: [Provided by you]")
        QMessageBox.information(self, "Success", "File encrypted and sharing link generated successfully.")
        self.refresh_logs()

    def copy_link(self):
        if not self.current_link:
            self.statusBar().showMessage("No generated link to copy", 3000)
            return

        QApplication.clipboard().setText(self.current_link)
        self.statusBar().showMessage("Link copied", 3000)

    def get_decrypted_output_path(self, encrypted_path):
        base_path = encrypted_path[:-4] if encrypted_path.endswith(".enc") else encrypted_path
        folder = os.path.dirname(base_path)
        filename = os.path.basename(base_path)
        name, extension = os.path.splitext(filename)
        output_path = os.path.join(folder, f"{name}_decrypted{extension}")

        counter = 1
        while os.path.exists(output_path):
            output_path = os.path.join(folder, f"{name}_decrypted_{counter}{extension}")
            counter += 1
        return output_path

    def decrypt_file(self):
        if not self.dec_selected_file:
            QMessageBox.warning(self, "Error", "Please select an encrypted file.")
            return

        password = self.dec_password_input.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter the decryption password.")
            return

        output_path = self.get_decrypted_output_path(self.dec_selected_file)
        success = CryptoEngine.decrypt_file(self.dec_selected_file, output_path, password)
        if success:
            QMessageBox.information(self, "Success", f"File decrypted successfully.\n\nSaved as:\n{output_path}")
            self.db.log_event("DECRYPTION", filename=self.dec_selected_file, status="SUCCESS", details=f"Decrypted to {output_path}")
        else:
            QMessageBox.critical(self, "Error", "Decryption failed. Incorrect password or corrupted file.")
            self.db.log_event("DECRYPTION", filename=self.dec_selected_file, status="FAILED", details="Incorrect password or data tampering detected")

        self.refresh_logs()

    def refresh_logs(self):
        logs = self.db.get_audit_logs()
        self.log_table.setRowCount(len(logs))
        for row, log in enumerate(logs):
            self.log_table.setItem(row, 0, QTableWidgetItem(log[1]))
            self.log_table.setItem(row, 1, QTableWidgetItem(log[2]))
            self.log_table.setItem(row, 2, QTableWidgetItem(log[3] if log[3] else ""))
            self.log_table.setItem(row, 3, QTableWidgetItem(log[4]))
            self.log_table.setItem(row, 4, QTableWidgetItem(log[5] if log[5] else ""))

    def refresh_policies(self):
        policies = self.db.get_active_policies()
        self.policy_table.setRowCount(len(policies))
        for row, policy in enumerate(policies):
            self.policy_table.setItem(row, 0, QTableWidgetItem(policy[0]))
            self.policy_table.setItem(row, 1, QTableWidgetItem(policy[1]))
            self.policy_table.setItem(row, 2, QTableWidgetItem(policy[2]))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setLayoutDirection(Qt.LeftToRight)
    window = SecureTransferApp()
    window.show()
    sys.exit(app.exec_())
