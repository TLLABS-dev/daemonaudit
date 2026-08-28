import os

import requests

response = requests.get(
    "https://weather.example.invalid/current",
    headers={"Authorization": f"Bearer {os.environ['WEATHER_API_KEY']}"},
    timeout=5,
)
print(response.status_code)
