# Validación del 19 de noviembre de 2026

## Suite ejecutada

La última ejecución de `python -m unittest discover -s tests -v` terminó con 23 pruebas correctas y cero omisiones, en 25,285 segundos sobre Windows y Python 3.14.

Se comprobaron autenticación, permisos de tokens, idempotencia, ventanas, excepciones, rechazo HTTP 403 ante credenciales correctas cuando existe bloqueo, liberación manual, expiración y evidencia de recuperación. También pasaron migración repetible desde tablas antiguas, respuestas de IA malformadas, fallback ante fallos, límite de bloqueos y recuperación de decisiones interrumpidas.

Los casos de IA usan respuestas controladas de prueba. La clave configurada respondió HTTP 200 a la consulta real de modelos y el modelo seleccionado está disponible. Las decisiones reales del proveedor siguen pendientes de comprobación.

## Ejecución original con reglas

Con IA desactivada, Edge se conectó al dashboard por loopback y a la aplicación protegida mediante la IPv4 local real de la misma PC. El cliente envió solicitudes al login a través de HTTP. La aplicación tomó el origen de la conexión TCP y generó los eventos.

| Escenario | Resultado observado |
| --- | --- |
| Fuerza bruta | Cinco respuestas HTTP 401 y luego HTTP 403. |
| Liberación desde el dashboard | Solicitud administrativa y siguiente acceso HTTP 200. |
| Password spraying | Cinco usuarios distintos, cinco respuestas HTTP 401, categoría específica y luego HTTP 403. |
| Vencimiento del segundo bloqueo | Siguiente acceso HTTP 200 y recuperación registrada. |
| Métricas al terminar | 10 eventos, 2 incidentes, 2 bloqueos verificados, 2 recuperaciones y 0 bloqueos activos. |
| Vistas de 1440 px y 390 px | Flujo operativo, sin errores JavaScript ni desbordamiento horizontal de la página. |

Esta ejecución usó una base temporal, ventana de tres segundos y bloqueos de doce segundos para acortar la espera.

## Nueva ejecución de exportación y espera

Una ejecución posterior en Edge, con IA desactivada, usó una base temporal, ventana de cinco segundos y bloqueos de cuarenta segundos. También se realizó desde la misma PC mediante su IPv4 LAN real. El registro está en `data/evidence/local-validacion.json`.

Se observaron cinco respuestas HTTP 401 y después HTTP 403. Desde el botón **Descargar evidencia** se guardó el JSON de un incidente con cinco eventos, estado `contained` y un bloqueo verificado. Después de liberarlo desde el dashboard y comprobar HTTP 200, se descargó de nuevo con estado `restored` y una recuperación verificada.

La comprobación adicional de espera se ejecutó por loopback, que está exceptuado de bloqueo. El portal envió ocho intentos, consultó acceso quince veces y mostró HTTP 200 al terminar la espera. Los controles volvieron a habilitarse y no se registraron errores de consola. Ambos servicios temporales se detuvieron al finalizar.

## Inicio de la presentación

Se ejecutó el iniciador LAN con detección de la subred real, contención automática activa y acceso HTTP 200. Se verificó el cierre de los dos servicios. La PC y el gateway se agregan a las excepciones de esa ejecución.

También se verificó `--presentation` con una base nueva por sesión, contadores iniciales en cero y conservación del historial anterior. `Iniciar-Presentacion.cmd` usa una ventana de 60 segundos y `--block-seconds 60`.

Quedan por comprobar en el lugar de presentación la conexión desde el segundo dispositivo y los permisos de red de Windows. Las dos ejecuciones de navegador de este registro se realizaron desde la misma PC. Docker Compose se entrega configurado y su ejecución queda pendiente de un motor Docker disponible.
