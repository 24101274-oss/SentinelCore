# SentinelCore

Prototipo universitario de detección y respuesta ante incidentes en un laboratorio aislado. Este primer avance permite ejecutar un caso real de autenticación fallida y seguirlo desde el servicio protegido hasta el dashboard.

## Ejecutar en Windows

Desde la carpeta del proyecto, en PowerShell con Python 3.14:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m lab.local
```

`lab.local` genera `.env` con dos tokens distintos y una contraseña de prueba si el archivo todavía no existe. Inicia la API y el servicio protegido en `127.0.0.1`, en los puertos 8000 y 8001. Detén ambos con `Ctrl+C`. Guarda `.env` de manera local.

1. Abre [el dashboard](http://127.0.0.1:8000/dashboard/) y conéctalo con el valor `ADMIN_TOKEN` de `.env`.
2. En otra terminal de la misma carpeta, ejecuta seis intentos controlados de inicio de sesión inválido.

   ```powershell
   .\.venv\Scripts\python.exe -m lab.demo
   ```

3. Selecciona el incidente de riesgo alto y abre su evidencia. En una base recién inicializada, deben verse seis eventos y un incidente con seis intentos. En Windows, el origen `127.0.0.1` queda en revisión por tratarse de loopback.

SQLite conserva los eventos e incidentes al reiniciar. El directorio local por defecto es `data/`. Si vuelves a ejecutar la demo, verifica los eventos nuevos y considera los fallos previos que todavía estén dentro de la ventana.

## Laboratorio Docker

Con un motor Docker en ejecución y Compose v2, desde la misma carpeta:

```powershell
python -m lab.local --init-only
docker compose up --build --wait
docker compose run --rm demo
```

Abre el mismo dashboard y usa `ADMIN_TOKEN`. El escenario envía las solicitudes desde `10.231.37.4` a `protected-app`. La red `lab` es interna, el servicio de login solo es accesible dentro de esa red y el puerto del dashboard se publica en loopback. El gateway y los dos servicios pertenecen a la lista de excepciones inicial.

```powershell
docker compose down
```

El volumen `data` conserva SQLite. Evita ejecutar el modo local y Compose al mismo tiempo porque ambos usan el puerto 8000.

## Pruebas de integración

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Las pruebas abren dos servicios temporales en los puertos 18060 y 18061. Comprueban el flujo de login, los umbrales, la ventana de correlación, la lista de excepciones, los permisos, los reintentos de ingesta y el acceso al panel. Usan su propia base temporal.

## Reparto de módulos

| Integrante | Código | Primer avance |
| --- | --- | --- |
| 1 | `protected_app/`, `monitoring/`, `lab/` | Login real y escenario de seis intentos de prueba. |
| 2 | `backend/` | API con autenticación, persistencia, correlación y razón del riesgo. |
| 3 | `frontend/` | Dashboard de solo lectura conectado a la API. |

Los umbrales iniciales son 3 fallos para alerta media y 5 para alta, en una ventana de 60 segundos por IP y servicio. Se pueden configurar en `.env`. Consulta el [contrato REST](docs/api.md). La documentación OpenAPI generada se puede abrir en [la API local](http://127.0.0.1:8000/docs).

El siguiente hito es añadir contención temporal en la aplicación protegida, comprobar el rechazo desde el origen de prueba, restaurar el acceso y registrar la auditoría. El panel inicial usa HTML, CSS y JavaScript para que los tres integrantes puedan probar el flujo con el mismo servidor. La vista se puede migrar a React/Vite cuando se incorporen los controles de respuesta.
