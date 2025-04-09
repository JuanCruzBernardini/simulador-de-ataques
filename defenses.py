import time

# Diccionario para registrar intentos por IP
attempts = {}

BLOCK_TIME = 60  # segundos
MAX_ATTEMPTS = 5

def log_login_attempt(ip, success):
    now = time.time()
    if ip not in attempts:
        attempts[ip] = []

    attempts[ip].append(now)

    # Limpiamos intentos viejos
    attempts[ip] = [t for t in attempts[ip] if now - t < BLOCK_TIME]

def check_brute_force(ip):
    now = time.time()
    if ip in attempts:
        recent = [t for t in attempts[ip] if now - t < BLOCK_TIME]
        if len(recent) >= MAX_ATTEMPTS:
            return True
    return False
