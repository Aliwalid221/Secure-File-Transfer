import re
import os
from db_manager import DatabaseManager

TEXT_EXTENSIONS = {".txt", ".csv", ".json", ".xml", ".log", ".md", ".py", ".js", ".html"}


class DLPEngine:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def scan_file(self, file_path):
        """
        Scans a file for DLP violations.
        Returns (is_allowed, reason, details)
        """
        ext = os.path.splitext(file_path)[1].lower()
        for name, pattern in self.db.get_active_policies(policy_type="extension"):
            if ext == pattern.lower():
                self.db.log_event("DLP_BLOCK", filename=file_path, status="BLOCKED", details=f"Matched policy: {name}")
                return False, f"File type {ext} is restricted by policy: {name}", name

        if ext in TEXT_EXTENSIONS:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for name, pattern in self.db.get_active_policies(policy_type="regex"):
                    if re.search(pattern, content):
                        self.db.log_event("DLP_BLOCK", filename=file_path, status="BLOCKED", details=f"Sensitive data found: {name}")
                        return False, f"Sensitive data found: {name}", name
            except Exception as e:
                self.db.log_event("DLP_SCAN_ERROR", filename=file_path, status="WARNING", details=str(e))
        else:
            self.db.log_event("DLP_SCAN_SKIP", filename=file_path, status="SKIPPED", details="Non-text file type, skipping content scan")

        self.db.log_event("DLP_PASS", filename=file_path, status="ALLOWED", details="No violations found")
        return True, "Passed DLP scan", None
