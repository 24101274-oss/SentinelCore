"""Inicia los dos servicios de SentinelCore en localhost para el desarrollo."""

import argparse
import os
import secrets
import subprocess
import sys
import time
from http.client import HTTPConnection
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


def start_service(module: str, port: int, env_file: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", module,
            "--host", "127.0.0.1", "--port", str(port),
            "--no-proxy-headers", "--env-file", str(env_file),
        ],
        cwd=ROOT,
        env={**os.environ, "BACKEND_URL": "http://127.0.0.1:8000"},
    )


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
    args = parser.parse_args()
    env_file = initialize_environment()
    if args.init_only:
        return 0

    children = []
    try:
        for module, port in (("backend.main:app", 8000), ("protected_app.main:app", 8001)):
            if healthy(port):
                raise RuntimeError(f"Ya hay un servicio activo en el puerto {port}.")
            child = start_service(module, port, env_file)
            children.append(child)
            wait_for_health(child, port)
        print("Panel: http://127.0.0.1:8000/dashboard/", flush=True)
        print("Usa el valor ADMIN_TOKEN de .env para conectar el panel.", flush=True)
        print("Demo en otra terminal: python -m lab.demo", flush=True)
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
