from shared.health import start_health_server

# Minimal placeholder agent
if __name__ == "__main__":
    start_health_server()
    print("Referee agent placeholder running — no logic yet.")
    import time
    while True:
        time.sleep(60)
