import os
import secrets
from flask import Flask, send_file, abort
from threading import Thread
from datetime import datetime, timedelta


class SharingServer:
    def __init__(self, port=5000):
        self.app = Flask(__name__)
        self.port = port
        self.shared_files = {}
        self.server_thread = None

        @self.app.route("/download/<token>")
        def download_file(token):
            if token not in self.shared_files:
                abort(404, description="Link invalid or expired.")

            info = self.shared_files[token]
            if datetime.now() > info["expires_at"]:
                del self.shared_files[token]
                abort(403, description="Link has expired.")

            return send_file(info["path"], as_attachment=True, download_name=info["original_name"])

    def generate_link(self, file_path, expires_in_minutes=15):
        token = secrets.token_urlsafe(16)
        expires_at = datetime.now() + timedelta(minutes=expires_in_minutes)
        original_name = os.path.basename(file_path)

        self.shared_files[token] = {
            "path": file_path,
            "expires_at": expires_at,
            "original_name": original_name,
        }

        return f"http://localhost:{self.port}/download/{token}", expires_at

    def run(self):
        self.app.run(host="0.0.0.0", port=self.port, debug=False, use_reloader=False)

    def start(self):
        if self.server_thread is None or not self.server_thread.is_alive():
            self.server_thread = Thread(target=self.run, daemon=True)
            self.server_thread.start()
            print(f"Sharing server started on port {self.port}")
