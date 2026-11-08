# Diseño: lxi-ipc, lxi-exit y lxi-audit

Fecha: 2026-11-08. Alcance aprobado por el propietario: las piezas comunes de la serie
hasta el final. Cada crate es el código del servicio de origen, sin cambios de comportamiento, con
sus límites como parámetros. Lo demás son decisiones mías y van marcadas.

## lxi-ipc

- Frames con longitud de 4 bytes big-endian y un objeto JSON. `Limits { frame,
  deadline, keys }`; `Limits::SERIES` son los valores de la serie: 4 KiB, 2 s y 16 claves.
- La longitud se valida antes de reservar el cuerpo; el cuerpo vive en `Zeroizing`.
- Claves únicas, nada después del objeto, `exact` para la forma y `text` para cadenas
  acotadas; `scrub(mensaje, campo)` borra un secreto ya usado.
- Lectura, escritura y `connect` sin bloqueo con `poll` y un plazo por frame; un plazo
  vencido es `Protocol`. `connect` deja el socket en `FD_CLOEXEC`.
- `peer_uid` da el UID efectivo del peer (`SO_PEERCRED` en Linux, `getpeereid` en
  macOS); cada servicio decide a quién acepta.

## lxi-exit

- La tabla de la serie (0, 3, 64, 69, 70, 73, 74, 75, 77) como constantes. Cada servicio
  traduce sus propios códigos de error a estos números; *decisión mía:* esa
  traducción no se comparte porque depende de los códigos de cada servicio.

## lxi-audit

- `export(fichero, max, página, fetch)`: crea un fichero nuevo `0600` (nunca toca uno
  existente), escribe las líneas de cada página con su SHA256, hace `sync_all` y borra
  el fichero parcial ante cualquier error. Sin eventos o con más de `max` es `Range`.
- `file_sha256(ruta, límite)` y `sha256_hex`, para comparar con el hash del servidor.
  El fichero se abre con `O_NOFOLLOW | O_NONBLOCK`: un FIFO se rechaza al momento en vez
  de bloquear (la única diferencia buscada respecto al servicio de origen).
- *Decisión mía:* las páginas las da quien llama, así el crate no depende de PostgreSQL
  ni de un esquema; el SQL del sellado sigue en cada servicio.
