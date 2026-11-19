# Contrato REST

Actualizado el 19 de noviembre de 2026.

## Servicio protegido

`POST /login` recibe `{"username":"admin","password":"un-valor-de-prueba"}`. Devuelve `200` para un acceso válido, `401` para un fallo cuya ingesta fue confirmada, `403` si existe un bloqueo activo y `422` para datos malformados. Antes de comprobar las credenciales, consulta la política. Si el backend no confirma la política o recepción de eventos, devuelve `503`. El monitor obtiene la IP de la conexión directa y genera el timestamp en UTC. El arranque deshabilita cabeceras de proxy y el evento guarda solo el usuario y el resultado.

`GET /access` devuelve `200` con `{status,source_ip,target}` si el origen puede acceder. Devuelve `403` cuando está bloqueado y `503` cuando la protección no está disponible. La interfaz de prueba se sirve en `/` desde la propia aplicación.

## Ingesta

`POST /api/events` requiere `Authorization: Bearer <INGEST_TOKEN>`. `Idempotency-Key` es un UUID opcional. El monitor lo genera por cada fallo y lo conserva en su reintento de transporte. Ejemplo de evento:

```json
{
  "event_type": "failed_login",
  "source_ip": "10.231.37.4",
  "target": "servidor-web",
  "timestamp": "2026-11-14T15:30:00Z",
  "metadata": { "username": "admin", "success": false }
}
```

La respuesta `201` contiene `event_id`, `severity` (`low`, `medium` o `high`) e `incident_id` (UUID o `null`). Con el mismo UUID y contenido se obtiene el recibo original. Un UUID reutilizado con otro contenido devuelve `409`. Un evento inválido devuelve `422`.

## Lecturas del dashboard

Estas rutas requieren `Authorization: Bearer <ADMIN_TOKEN>`. El token de ingesta tiene un permiso diferente.

| Método y ruta | Datos |
| --- | --- |
| `GET /api/incidents` | `{items,total}`. Filtros `severity` y `status`, paginación `limit` y `offset`. |
| `GET /api/incidents/{id}` | Incidente más el arreglo `events` con los eventos asociados. `404` si no existe. |
| `GET /api/metrics` | `{events,incidents,alerts,verified_blocks,active_blocks,restored_access}`. `alerts` cuenta incidentes con alerta. Los verificados y restaurados cuentan medidas históricas con evidencia. Los activos cuentan restricciones vigentes. |
| `GET /api/blocks` | Arreglo de los últimos 100 bloqueos, con `verified_at` y `restored_at` opcionales. `active_only=true` filtra vigentes. |
| `GET /api/audit` | Arreglo de registros con actor, acción, hora, origen e incidente. `limit` admite hasta 200. |
| `GET /api/system` | Configuración activa del detector, contención y analista, más la URL pública local del laboratorio. |
| `POST /api/blocks/{id}/release` | Libera un bloqueo activo. La recuperación queda pendiente de una solicitud permitida. |
| `POST /api/incidents/{id}/respond` | Solicita contención manual y revalida alcance, excepciones y límite. |
| `POST /api/incidents/{id}/restore` | Libera las medidas activas asociadas al incidente. |

Cada incidente incluye `id`, `category`, `source_ip`, `target`, `severity`, `status`, `first_seen`, `last_seen`, `event_count`, `attempts`, `recommended_action` y `reason`. `GET /health` es público en ambos servicios y devuelve `{"status":"ok"}`.

## Correlación y estado

- La ventana es móvil y se aplica a una combinación de IP y servicio. Los fallos bajo el umbral medio quedan registrados como eventos.
- Al llegar al umbral medio, el motor genera una alerta (`alert`) y conserva los fallos que la sustentan.
- Al llegar al umbral alto en el mismo grupo, el motor actualiza ese incidente. Los orígenes autorizados pueden quedar como `pending_containment` con la recomendación `temporary_block`.
- Los orígenes excluidos, como loopback y las IP de `ALLOWLIST`, quedan en `review`. `LAB_CIDRS` autoriza únicamente la candidatura a contención dentro de rangos explícitos.
- `attempts` representa el máximo de fallos en una sola ventana. `event_count` cuenta todas las evidencias asociadas al incidente, que pueden cubrir varias ventanas consecutivas.
- `category` distingue `possible_brute_force` de `possible_password_spraying`. El segundo patrón requiere al menos cinco usuarios distintos y hasta dos fallos por usuario en la ventana.

## Comprobación del servicio protegido

`GET /api/blocks/check?source_ip=IP&target=servidor-web` y su alias `/api/access/check` requieren `INGEST_TOKEN`. Devuelven `{blocked,block_id,expires_at}`. Un bloqueo creado queda en `pending_verification` hasta observar un rechazo.

`POST /api/access/observations` requiere `INGEST_TOKEN` y recibe `{source_ip,target,http_status,request_id,block_id}`. `http_status` admite 200 y 403. `request_id` es UUID e idempotente. El servicio genera esta observación con la IP que obtuvo del socket. Para 403 se exige un `block_id` activo y coincidente. Para 200 se exige ausencia de bloqueo activo.

La observación 403 marca `verified_at`, cambia el incidente a `contained` y genera `block_verified` en auditoría. Liberar o vencer una medida cambia a `restoration_pending`. Una observación posterior 200 marca `restored_at`, cambia a `restored` y genera `access_restored`.

## Analista opcional

Con `AI_ENABLED=true`, un candidato puede pasar al analista en segundo plano. Solo recibe categoría, conteos y tiempos. Una respuesta válida propone `block` o `review`. La política se comprueba nuevamente antes de crear la medida. Los errores del proveedor registran `ai_fallback` y vuelven a la regla. La clave permanece en el entorno del servidor.
