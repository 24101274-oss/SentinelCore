# Contrato REST inicial

Fecha de la propuesta: 14 de noviembre de 2026.

## Servicio protegido

`POST /login` recibe `{"username":"admin","password":"un-valor-de-prueba"}`. Devuelve `200` para un acceso válido, `401` para un fallo cuya ingesta fue confirmada y `422` para datos de login malformados. Si el backend no confirma la recepción, devuelve `503`. El monitor obtiene la IP de la conexión directa y genera el timestamp en UTC. El arranque deshabilita cabeceras de proxy y el evento guarda solo el usuario y el resultado.

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

Las tres rutas requieren `Authorization: Bearer <ADMIN_TOKEN>`. El token de ingesta tiene un permiso diferente.

| Método y ruta | Datos |
| --- | --- |
| `GET /api/incidents` | `{items,total}`. Filtros `severity` y `status`, paginación `limit` y `offset`. |
| `GET /api/incidents/{id}` | Incidente más el arreglo `events` con los eventos asociados. `404` si no existe. |
| `GET /api/metrics` | `{events,incidents,alerts,verified_blocks}`. `alerts` cuenta los incidentes con alerta media o alta. `verified_blocks` se mantiene en 0 durante el primer avance. |

Cada incidente incluye `id`, `category`, `source_ip`, `target`, `severity`, `status`, `first_seen`, `last_seen`, `event_count`, `attempts`, `recommended_action` y `reason`. `GET /health` es público en ambos servicios y devuelve `{"status":"ok"}`.

## Correlación y estado

- La ventana es móvil y se aplica a una combinación de IP y servicio. Los fallos bajo el umbral medio quedan registrados como eventos.
- Al llegar al umbral medio, el motor genera una alerta (`alert`) y conserva los fallos que la sustentan.
- Al llegar al umbral alto en el mismo grupo, el motor actualiza ese incidente. Los orígenes autorizados pueden quedar como `pending_containment` con la recomendación `temporary_block`.
- Los orígenes excluidos, como loopback y las IP de `ALLOWLIST`, quedan en `review`. `LAB_CIDRS` autoriza únicamente la candidatura a contención dentro de rangos explícitos.
- `attempts` representa el máximo de fallos en una sola ventana. `event_count` cuenta todas las evidencias asociadas al incidente, que pueden cubrir varias ventanas consecutivas.

`POST /api/incidents/{id}/respond`, `POST /api/incidents/{id}/restore` y `GET /api/access/check` quedan previstos para el siguiente hito.
