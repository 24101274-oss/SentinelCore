"""Envía solicitudes de login reales al servicio de prueba de SentinelCore."""

import argparse
import http.client
import json
from secrets import token_urlsafe
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--docker", action="store_true", help="Usa el servicio protected-app de Docker Compose"
    )
    args = parser.parse_args()
    host, port = ("protected-app", 8000) if args.docker else ("127.0.0.1", 8001)
    body = json.dumps({"username": "sc-demo", "password": token_urlsafe(24)})
    connection = http.client.HTTPConnection(host, port, timeout=8)

    try:
        for number in range(1, 9):
            connection.request("POST", "/login", body, {"Content-Type": "application/json"})
            with connection.getresponse() as response:
                response.read()
                print(f"Intento {number}/8: HTTP {response.status}")
                if response.status == 403:
                    print("El servicio protegido rechazó la conexión por bloqueo.")
                    return 0
                if response.status != 401:
                    return 1
            time.sleep(0.3)
    except (OSError, http.client.HTTPException) as error:
        print(f"No se pudo completar el escenario en el laboratorio ({type(error).__name__}).")
        return 1
    finally:
        connection.close()

    print("Los fallos quedaron registrados. En localhost la IP está exceptuada.")
    if args.docker:
        print("No se observó bloqueo. Consulta política, estado de IA y auditoría.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
