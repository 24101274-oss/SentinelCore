# Guion de demostración

Preparado para la presentación del 20 de noviembre de 2026. Usa la PC como servidor y un celular u otra PC como cliente de prueba, en la misma Wi-Fi. Inicia `Iniciar-Presentacion.cmd`, conecta el panel con `ADMIN_TOKEN` y abre en el segundo dispositivo la dirección impresa en la consola. Cada arranque crea una sesión de evidencia propia en `data/sessions/`.

## Recorrido para el jurado

1. **Acceso inicial.** «Desde este segundo dispositivo hacemos una solicitud al servicio protegido y obtenemos acceso HTTP 200».
2. **Prueba controlada.** «Enviamos solicitudes de login con credenciales inválidas. Cada respuesta proviene del servidor y cada fallo se registra con la IP y la hora».
3. **Detección.** «SentinelCore agrupa eventos por origen y servicio dentro de 60 segundos. Tres fallos generan alerta y cinco elevan el riesgo».
4. **Contención.** «La política autoriza un bloqueo temporal para este origen. Una nueva solicitud recibe HTTP 403 y el servicio informa esa evidencia al backend».
5. **Explicación.** Abre el incidente y la auditoría. Si existe una decisión del proveedor de IA, muestra su actor y explicación. Con IA desactivada explica la regla que disparó la contención.
6. **Recuperación.** Libera el bloqueo desde el panel. En el segundo dispositivo pulsa **Probar acceso** y muestra HTTP 200 y la evidencia de recuperación.
   Descarga el JSON del incidente con **Descargar evidencia**. Reúne eventos, bloqueos y auditoría, junto con los parámetros públicos actuales al exportar.
7. **Segundo patrón.** Tras una ventana limpia, ejecuta la prueba de varios usuarios y muestra la categoría de password spraying.

Con el analista habilitado, la decisión puede llegar después de terminar la tanda de solicitudes. Espera la decisión visible en la auditoría y pulsa **Probar acceso** para obtener la evidencia de rechazo. El gateway y la PC están exceptuados. Usa como cliente de prueba otro dispositivo cuya IP pertenezca a la subred autorizada.

## Evidencias observables

| Evidencia | Comportamiento comprobable |
| --- | --- |
| IP en el segundo dispositivo e incidente | El origen se obtiene de la conexión TCP. |
| Respuestas HTTP 401 | El login rechazó credenciales recibidas por HTTP. |
| Eventos y razón del incidente | La detección agrupó fallos persistidos. |
| HTTP 403 y verificación del bloqueo | La aplicación protegida ejecutó el rechazo. |
| Auditoría de liberación | La administración retiró la medida. |
| HTTP 200 y recuperación verificada | El cliente volvió a obtener acceso. |
| Actor `ai` con decisión | Se utilizó el analista configurado. |
| Actor `system` | Se ejecutó la regla del backend. |

Los resultados y tiempos que presentes deben salir de la ejecución observada. La demo cubre esta aplicación y los dos patrones de autenticación implementados. Prueba la conexión desde el segundo dispositivo antes de comenzar la exposición.
