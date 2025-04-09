import requests

url = "http://127.0.0.1:5000/"
payload = {
    "username": "admin",
    "password": "incorrecto"
}

for i in range(7):
    r = requests.post(url, data=payload)
    print(f"[{i+1}] Código de estado: {r.status_code}")
    if "bloqueada temporalmente" in r.text:
        print("💥 IP bloqueada por fuerza bruta")
        break