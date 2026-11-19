# Validación del 19 de noviembre de 2026

## Suite ejecutada

`python -m unittest discover -s tests -v` terminó con 19 pruebas correctas y cero omisiones, en 24,803 segundos sobre Windows y Python 3.14.

Se comprobaron autenticación, permisos de tokens, idempotencia, ventanas, excepciones, rechazo HTTP 403 ante credenciales correctas cuando existe bloqueo, liberación manual, expiración y evidencia de recuperación. También pasaron migración repetible desde tablas antiguas, respuestas de IA malformadas, fallback ante fallos, límite de bloqueos y recuperación de decisiones interrumpidas.

Los casos de IA usan respuestas controladas de prueba. La ejecución contra Groq queda pendiente de configurar una clave propia y comprobar la disponibilidad del modelo.

## Flujo de navegador ejecutado

Edge se conectó al dashboard por loopback y a la aplicación protegida mediante la IPv4 local real de la PC. El cliente envió solicitudes al login a través de HTTP. La aplicación tomó el origen de la conexión TCP y generó los eventos.

| Escenario | Resultado observado |
| --- | --- |
| Fuerza bruta | Cinco respuestas HTTP 401 y luego HTTP 403. |
| Liberación desde el dashboard | Solicitud administrativa y siguiente acceso HTTP 200. |
| Password spraying | Cinco usuarios distintos, cinco respuestas HTTP 401, categoría específica y luego HTTP 403. |
| Vencimiento del segundo bloqueo | Siguiente acceso HTTP 200 y recuperación registrada. |
| Métricas al terminar | 10 eventos, 2 incidentes, 2 bloqueos verificados, 2 recuperaciones y 0 bloqueos activos. |
| Vistas de 1440 px y 390 px | Flujo operativo, sin errores JavaScript ni desbordamiento horizontal de la página. |

La prueba de navegador usó una base temporal, ventana de tres segundos y bloqueos de doce segundos para acortar la espera. El inicio de presentación usa una ventana de 60 segundos y `--block-seconds 60`.

## Inicio de la presentación

Se ejecutó el iniciador LAN con detección de la subred real, contención automática activa y acceso HTTP 200. Se verificó el cierre de los dos servicios. La PC y el gateway se agregan a las excepciones de esa ejecución.

Quedan por comprobar en el lugar de presentación la conexión desde el segundo dispositivo y los permisos de red de Windows. La prueba de navegador de este registro se ejecutó desde la misma PC. Docker Compose se entrega configurado y su ejecución queda pendiente de un motor Docker disponible.
