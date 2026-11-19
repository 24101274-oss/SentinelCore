# SentinelCore

Prototipo universitario de detección y respuesta en una aplicación protegida. La demostración usa solicitudes HTTP al login, la IP observada en la conexión, SQLite, contención temporal y evidencia de rechazo y recuperación.

## Demostración entre dos dispositivos

Conecta la PC y el celular u otra PC a la misma Wi-Fi. Ejecuta Iniciar-LAN.cmd o, en PowerShell desde la carpeta del proyecto:

```powershell
.\.venv\Scripts\python.exe -m lab.local --lan --block-seconds 60
```

Para exponer, ejecuta `Iniciar-Presentacion.cmd`. Crea una base propia en `data/sessions/` por cada arranque. La consola imprime el identificador y la ruta de la evidencia. También puedes usar `--presentation` con el comando anterior.

El inicio detecta la IPv4 y la máscara de red, limita la candidatura a bloqueo a esa subred y exceptúa la PC y su gateway. Conserva .env. Si hay varias interfaces, selecciona la dirección de Wi-Fi con --host-ip TU_IP_LOCAL. La consola muestra la dirección que debes abrir en el segundo dispositivo.

1. En la PC abre [el dashboard](http://127.0.0.1:8000/dashboard/) y conéctalo con ADMIN_TOKEN de .env.
2. En el segundo dispositivo abre la dirección del laboratorio que muestra la consola. Pulsa **Probar acceso**. Debe mostrar HTTP 200 y la IP de ese dispositivo.
3. Pulsa la prueba de intentos repetidos. El navegador envía hasta ocho solicitudes de login con contraseña inválida. Tres fallos generan alerta y cinco elevan el riesgo.
4. Una solicitud posterior recibe HTTP 403. El dashboard muestra el bloqueo con evidencia de rechazo y auditoría.
5. En el dashboard pulsa **Restaurar acceso** y confirma. En el segundo dispositivo pulsa **Probar acceso**. HTTP 200 confirma la recuperación.
   En el detalle del incidente puedes pulsar **Descargar evidencia** para guardar un JSON con los eventos, bloqueos y auditoría vinculados. Sus parámetros públicos corresponden a la configuración actual de exportación.
6. Para un segundo escenario elige **Probar varios usuarios**. El motor distingue password spraying cuando observa cinco usuarios distintos y pocos fallos por usuario. Para una ejecución limpia espera que termine la ventana de 60 segundos del primer escenario.
7. También puedes dejar vencer el bloqueo de 60 segundos y pulsar **Probar acceso** para comprobar la recuperación automática.

El backend y el dashboard escuchan en loopback. La aplicación protegida escucha en el puerto 8001 para acceso desde el segundo dispositivo. Si Windows solicita acceso a la red, permite Python en la red de la presentación. Si el celular no carga, confirma la misma Wi-Fi, la dirección impresa y que el router permita comunicación entre clientes.

Detén ambos servicios con Ctrl+C. Cada ejecución conserva la evidencia en data/sentinelcore.db. Las migraciones agregan los campos nuevos a las bases anteriores.

## Instalar desde GitHub

Requiere Python 3.14.

```powershell
git clone https://github.com/24101274-oss/SentinelCore.git
cd SentinelCore
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m lab.local --init-only
```

Se generan dos tokens distintos y una contraseña de laboratorio en .env. El repositorio incluye .env.example con los secretos vacíos.

Para desarrollar solo en la PC:

```powershell
.\.venv\Scripts\python.exe -m lab.local
```

La [aplicación protegida](http://127.0.0.1:8001/) permite probar el login. Loopback está exceptuado de contención. La demo de bloqueo completo se ejecuta desde el segundo dispositivo o desde el contenedor del laboratorio.

## Analista de IA opcional

La integración de Groq del colaborador puede asistir la decisión. Configura en .env una clave propia en AI_API_KEY, AI_ENABLED=true y un AI_MODEL disponible en esa cuenta. Reinicia los servicios. El modelo recibe conteos, tiempos y categoría del patrón. Las IP y los nombres de usuario se conservan localmente.

La auditoría identifica la decisión de IA o la aplicación de reglas cuando falla el proveedor. Alcance, excepciones, duración y límite de bloqueos se revalidan antes de actuar. Con IA desactivada la demo usa los umbrales configurados. Revisa disponibilidad del modelo y clave antes de presentar.

Si el modelo tarda en decidir, espera su registro en el panel y pulsa **Probar acceso** desde el segundo dispositivo. La API recupera decisiones pendientes al iniciar y cada cinco segundos.

## Laboratorio Docker

Con Docker y Compose v2 en ejecución:

```powershell
python -m lab.local --init-only
docker compose up --build --wait
docker compose run --rm demo
```

Las solicitudes salen del contenedor demo con su IP real 10.231.37.4 hacia protected-app. La red lab es interna. El puerto 8000 publica el dashboard en loopback y el 8001 permite abrir el servicio desde la PC. Los datos quedan en el volumen data.

```powershell
docker compose down
```

## Verificación

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Las pruebas usan servicios y SQLite temporales. Cubren permisos, idempotencia, correlación, excepciones, rechazo efectivo, verificación, liberación y expiración. La prueba entre IPs usa una dirección privada real de la PC si existe. Los casos que publican eventos directamente comprueban contratos y reglas.

Consulta el [contrato REST](docs/api.md) y el [guion de presentación](docs/demo.md). La [documentación OpenAPI](http://127.0.0.1:8000/docs) se genera desde el código.

## Alcance demostrable

Los escenarios cubren intentos repetidos y password spraying contra este login. La contención se aplica al acceso de esta aplicación. El estado verificado requiere una observación de HTTP 403 del servicio, y la recuperación requiere una observación posterior de HTTP 200. Otros servicios, familias de amenazas y administración del firewall quedan como líneas futuras.

| Integrante | Módulos |
| --- | --- |
| 1 | protected_app/, monitoring/, lab/ |
| 2 | backend/, correlación, persistencia y analista |
| 3 | frontend/, contención y auditoría |
