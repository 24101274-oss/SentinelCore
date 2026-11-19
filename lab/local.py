"""Inicia los dos servicios de SentinelCore en localhost para el desarrollo."""

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from http.client import HTTPConnection
from ipaddress import IPv4Address, ip_network
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def initialize_environment() -> Path:
    path = ROOT / ".env"
    template = (ROOT / ".env.example").read_text(encoding="utf-8")
    for name in ("INGEST_TOKEN", "ADMIN_TOKEN", "LAB_PASSWORD"):
        template = template.replace(f"{name}=\n", f"{name}={secrets.token_urlsafe(32)}\n", 1)
    try:
        with path.open("x", encoding="utf-8") as env_file:
            env_file.write(template)
        print("Se generó .env con credenciales locales.", flush=True)
    except FileExistsError:
        print("Se usará el archivo .env existente.", flush=True)
    return path


def healthy(port: int) -> bool:
    connection = HTTPConnection("127.0.0.1", port, timeout=0.5)
    try:
        connection.request("GET", "/health")
        return connection.getresponse().status == 200
    except OSError:
        return False
    finally:
        connection.close()


def start_service(
    module: str, port: int, env_file: Path, host: str = "127.0.0.1",
    environment: dict[str, str] | None = None,
) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", module,
            "--host", host, "--port", str(port),
            "--no-proxy-headers", "--env-file", str(env_file),
        ],
        cwd=ROOT,
        env={**os.environ, "BACKEND_URL": "http://127.0.0.1:8000", **(environment or {})},
    )


def lan_configuration(host_ip: str | None = None) -> tuple[str, str, list[str]]:
    """Lee la dirección y la máscara reales de la interfaz que lleva la ruta local."""
    if os.name != "nt":
        raise RuntimeError("En este equipo usa --lan desde Windows para detectar la red.")
    query = (
        "Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | "
        "ForEach-Object { $c=$_; $_.IPv4Address | ForEach-Object { "
        "[pscustomobject]@{address=$_.IPAddress;prefix=$_.PrefixLength;"
        "gateway=$c.IPv4DefaultGateway.NextHop} } } | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", query],
        capture_output=True, text=True, timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        interfaces = json.loads(result.stdout)
        if isinstance(interfaces, dict):
            interfaces = [interfaces]
        candidates = [item for item in interfaces if IPv4Address(item["address"]).is_private]
        if host_ip:
            candidates = [item for item in candidates if item["address"] == host_ip]
        if len(candidates) != 1:
            raise ValueError("selección ambigua")
        chosen = candidates[0]
        address = str(IPv4Address(chosen["address"]))
        network = str(ip_network(f"{address}/{chosen['prefix']}", strict=False))
        exceptions = [str(IPv4Address(item["address"])) for item in interfaces]
        exceptions.extend(str(IPv4Address(item["gateway"])) for item in interfaces)
        return address, network, exceptions
    except (TypeError, ValueError, KeyError) as error:
        raise RuntimeError(
            "No se pudo elegir una interfaz LAN. Usa --lan --host-ip TU_IP_LOCAL "
            "y revisa la conexión Wi-Fi con ipconfig."
        ) from error


def wait_for_health(process: subprocess.Popen, port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        if healthy(port):
            return
        time.sleep(0.15)
    raise RuntimeError(f"El servicio del puerto {port} no inició. Revisa los mensajes de Uvicorn.")


def stop_service(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        # En Windows el ejecutable del entorno virtual puede delegar en un hijo.
        subprocess.run(
            ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
            check=False,
            timeout=5,
        )
    if process.poll() is None:
        process.terminate()
    process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--init-only", action="store_true", help="Solo genera .env si falta.")
    parser.add_argument("--lan", action="store_true", help="Expone el laboratorio a otro dispositivo de la misma red.")
    parser.add_argument("--host-ip", help="Elige la IPv4 de la PC cuando hay varias interfaces LAN.")
    parser.add_argument("--block-seconds", type=int, default=None, help="Duración del bloqueo para esta ejecución.")
    args = parser.parse_args()
    env_file = initialize_environment()
    if args.init_only:
        return 0

    children = []
    try:
        environment = {}
        public_url = "http://127.0.0.1:8001"
        if args.block_seconds is not None:
            if not 5 <= args.block_seconds <= 3600:
                raise RuntimeError("--block-seconds admite entre 5 y 3600 segundos.")
            environment["BLOCK_SECONDS"] = str(args.block_seconds)
        if args.lan:
            from dotenv import dotenv_values

            address, network, exceptions = lan_configuration(args.host_ip)
            existing = dotenv_values(env_file).get("ALLOWLIST", "") or ""
            environment["LAB_CIDRS"] = network
            environment["ALLOWLIST"] = ",".join([existing, *exceptions])
            public_url = f"http://{address}:8001"
            print(f"Red de prueba autorizada: {network}", flush=True)
            print(f"Abre desde el segundo dispositivo: {public_url}/", flush=True)
        environment["PROTECTED_APP_PUBLIC_URL"] = public_url
        for module, port in (("backend.main:app", 8000), ("protected_app.main:app", 8001)):
            probe = socket.socket()
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as error:
                raise RuntimeError(f"El puerto {port} está ocupado. Cierra la ejecución anterior.") from error
            finally:
                probe.close()
            host = "0.0.0.0" if args.lan and port == 8001 else "127.0.0.1"
            child = start_service(module, port, env_file, host, environment)
            children.append(child)
            wait_for_health(child, port)
        print("Panel: http://127.0.0.1:8000/dashboard/", flush=True)
        print("Usa el valor ADMIN_TOKEN de .env para conectar el panel.", flush=True)
        print(f"Aplicación protegida: {public_url}/", flush=True)
        print("Detén los servicios con Ctrl+C.", flush=True)
        while all(child.poll() is None for child in children):
            time.sleep(0.25)
        raise RuntimeError("Uno de los servicios se detuvo.")
    except KeyboardInterrupt:
        # La terminal también entrega Ctrl+C a Uvicorn. Dale tiempo para cerrar SQLite.
        for child in children:
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        return 0
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    finally:
        for child in reversed(children):
            stop_service(child)


if __name__ == "__main__":
    raise SystemExit(main())
