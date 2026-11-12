import importlib
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import unittest
from urllib.parse import urlsplit


class VaultTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        previous = Path.cwd()
        os.chdir(directory.name)
        self.addCleanup(os.chdir, previous)
        self.vault = importlib.reload(importlib.import_module("app"))
        from init_db import init_db

        init_db()
        self.client = self.vault.app.test_client()
        self.credentials = {"email": "demo@example.com", "password": "test-only-password"}

    def sign_in(self):
        self.assertEqual(self.client.post("/signup", json=self.credentials).status_code, 200)
        response = self.client.post("/login", json=self.credentials)
        self.assertEqual(response.status_code, 200)
        return {"x-access-token": response.json["token"]}

    def upload(self, route, payload, filename, headers, password="file-password", **extra):
        return self.client.post(
            route,
            data={"file": (BytesIO(payload), filename), "password": password, **extra},
            headers=headers,
        )

    def test_pages_and_authentication(self):
        for route in ("/signup", "/login", "/dashboard", "/encrypt", "/decrypt", "/share"):
            self.assertEqual(self.client.get(route).status_code, 200)
        self.assertEqual(self.upload("/encrypt", b"demo", "demo.txt", {}).status_code, 401)
        self.sign_in()
        response = self.client.post("/login", json={**self.credentials, "password": "wrong"})
        self.assertEqual(response.status_code, 401)

    def test_encrypt_decrypt_round_trip(self):
        headers = self.sign_in()
        payload = b"synthetic demo file\x00\xff"
        result = self.upload("/encrypt", payload, "demo.bin", headers)
        self.assertEqual(result.status_code, 200)
        self.assertIn("attachment", result.headers["Content-Disposition"])
        self.assertEqual(result.headers["Cache-Control"], "no-store")
        ciphertext = result.data
        self.assertNotEqual(ciphertext, payload)
        second = self.upload("/encrypt", payload, "demo.bin", headers)
        self.assertNotEqual(second.data, ciphertext)
        self.assertEqual(list(Path("uploads").iterdir()), [Path("uploads/shares")])
        self.assertEqual(self.upload("/decrypt", ciphertext, "demo.bin.enc", headers, "wrong").status_code, 400)
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        self.assertEqual(self.upload("/decrypt", tampered, "demo.bin.enc", headers).status_code, 400)
        result = self.upload("/decrypt", ciphertext, "demo.bin.enc", headers)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data, payload)

    def test_legacy_file(self):
        nonce = bytes(12)
        key = self.vault.derive_key("file-password", b"fixed-salt", 100_000)
        data = nonce + self.vault.AESGCM(key).encrypt(nonce, b"legacy demo", None)
        result = self.upload("/decrypt", data, "legacy.txt.enc", self.sign_in())
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data, b"legacy demo")

    def test_password_gated_and_expired_share(self):
        response = self.upload("/share", b"demo", "demo.txt", self.sign_in(), expiry="5")
        self.assertEqual(response.status_code, 200)
        path = urlsplit(response.json["link"]).path
        token = path.rsplit("/", 1)[-1]
        stored_file = Path("uploads/shares") / token / "demo.txt"
        self.assertTrue(stored_file.read_bytes().startswith(self.vault.FILE_MAGIC))
        self.assertEqual(self.client.get(f"/uploads/shares/{token}/demo.txt").status_code, 404)
        self.assertIn(b"Incorrect password", self.client.post(path, data={"password": "wrong"}).data)
        with self.client.post(path, data={"password": "file-password"}) as download:
            self.assertEqual(download.data, b"demo")
        with self.vault.get_db() as db:
            db.execute("UPDATE shares SET expires_at = '2000-01-01T00:00:00+00:00'")
        self.assertIn(b"Link expired", self.client.post(path, data={"password": "file-password"}).data)
