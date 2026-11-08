# Lecciones heredadas de la serie

Reglas comunes a los servicios de la serie, sacadas de sus auditorías. Se pueden copiar
en el `AGENTS.md` de un proyecto nuevo.

## Texto y tiempo (regla de toda la serie)

- **UTF-8 y UTC por defecto, configurables** en todos los repositorios de la serie.
- La configuración cambia lo que se **presenta**: zona de sesión, zona o locale de
  ejecución, codificación de un dato. Nunca cambia lo que se guarda ni lo que se
  firma o se hashea, que sigue en UTC y UTF-8 (por ejemplo, una línea canónica de
  auditoría).
- Una zona o codificación no válida es un error de configuración, nunca un valor por
  defecto silencioso. Se valida contra la fuente autorizada: nombres IANA en
  PostgreSQL o `jiff`.
- Donde el formato impone la codificación (JSON = UTF-8, RFC 8259; protocolo de
  `postgres` = `client_encoding` UTF8), esa capa no se configura. La conversión
  (por ejemplo EBCDIC/CCSID de IBM i) va explícita, por campo u objeto, en el borde
  que la necesite.

## Códigos de salida (regla de la serie)

| Código | Significado |
|---|---|
| 0 | Permitido u operación hecha |
| 3 | Denegado: una decisión, nunca un fallo |
| 64 | Entrada o configuración |
| 69 | No disponible para esta petición |
| 70 | El servicio perdió una dependencia crítica (debe salir para que lo reinicie el supervisor) |
| 73 | Conflicto |
| 74 | E/S de salida |
| 75 | Timeout o autenticación técnica reintentable |
| 77 | Autoridad |

Una respuesta de error tiene la misma forma completa que una decisión, con nulos donde no
se sabe.

## Conexión a PostgreSQL

- Validar `host` Y `hostaddr`: la conexión usa `hostaddr` si existe. Rechazar
  configuraciones con solo `hostaddr`. Local: socket Unix. Remoto: TLS verificado
  con CA, nunca texto plano implícito. Un test negativo por cada forma de DSN.
- Timeouts también en el cliente: connect, keepalive y `tcp_user_timeout`.
  El presupuesto del servidor debe ser menor que el plazo que espera el cliente.

## Identidad y autoridad

- El sujeto sale de la sesión autenticada, nunca de un campo del cliente.
- Si actúa en nombre de otro, enviar al usuario original como intermediario y
  auditarlo; no esconderlo tras una identidad técnica.
- Autoridad en una sola fuente: consultar al servicio de autoridad, no crear otra tabla
  de permisos paralela. Lo que se desconoce nunca significa "sin control".
- Guardar roles por OID o comprobar que existen: un rol borrado no puede romper
  consultas ni heredarse al recrearlo.

## Disponibilidad y errores

- Tres resultados distintos en API y exit codes: permitido, denegado y no disponible.
  Una respuesta de error tiene la misma forma completa que una decisión.
- Si se pierde una dependencia crítica (PostgreSQL, el servicio de autoridad), salir con
  código distinto de 0 para que systemd reinicie; nunca quedarse vivo sin poder servir.
- Un error de autenticación propio (401/403 de su token) es reintentable,
  no un rechazo definitivo de las peticiones del usuario.
- Errores con código concreto (entrada, conflicto, autoridad, timeout,
  indisponible), sin secretos.

## Auditoría y recursos

- Acordar el modelo de cuota antes de generar eventos: cuota por sujeto, no global; no
  auditar dos veces la misma decisión; retención explícita.
- Límites por identidad en conexiones, colas y tamaño de petición. `accept()`
  con pausa ante EMFILE, sin bucle de logs.

## Migraciones

- Migraciones aditivas y numeradas, cada una en una transacción. Reejecutar
  el instalador nunca puede deshacer una migración posterior.
- `schema_version` debe comprobar lo que realmente se aplicó (ledger con
  SHA256), no devolver una constante.
- `ADD COLUMN NOT NULL` solo con valor por defecto o sobre tablas vacías comprobadas.

## Pruebas

- Tests de integración contra el PostgreSQL real exigido (16), que se ejecuten
  por defecto o fallen como NOT_RUN, nunca ignorados en silencio.
- Un test positivo por cada camino feliz del cliente, no solo negativos.
- Rutas relativas (`config.json`) aceptadas o rechazadas con un error claro.
- Al mover código de un servicio a un crate común, el comportamiento no cambia: se
  comprueba con los tests del servicio sin modificar y con una comparación diferencial.
