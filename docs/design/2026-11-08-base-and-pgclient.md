# Diseño: base de lxi-commons y lxi-pgclient

Fecha: 2026-11-08. Alcance aprobado por el propietario: la base del repositorio y
`lxi-pgclient`, con el nombre `lxi-commons` y el prefijo `lxi-*`. Lo demás son
decisiones mías y van marcadas.

## 1. Repositorio

- Workspace de Cargo con crates pequeños e independientes. Ningún crate conoce un
  servicio concreto: nada de esquemas `authority` o `exit_policy`.
- El estándar es el de la serie: Rust 1.90 fijado, `forbid` de todos los
  lints de la serie, `cargo-deny`, y gates en macOS ARM64 y Linux AArch64.
- *Decisión mía:* los consumidores dependen por git con el commit fijado
  (`git = "file:///…/lxi-commons", rev = "<commit>"`) más su propio `Cargo.lock`. Nunca
  una ruta suelta ni una rama flotante.
- *Decisión mía:* sin remoto ni publicación al empezar.

## 2. lxi-pgclient

Una fachada síncrona sobre `tokio-postgres`, con su propio runtime de un hilo, porque
los servicios de la serie son síncronos, con hilos.

**Transporte.** `Policy` la elige cada consumidor:

| Campo | Estricta (por defecto) | Consumidor permisivo (ejemplo) |
|---|---|---|
| `loopback_plaintext` | no | sí |
| `private_plaintext` | no | solo con su flag de configuración |
| `unix_peer_uid` | opcional | no |
| `hostaddr` (junto a un host) | sí | no: cualquier `hostaddr` se rechaza |
| `explicit_names` (`user` y `dbname` obligatorios) | sí | no: valen los valores por defecto de libpq |

- Reglas comunes:
  - nunca `hostaddr` sin `host`;
  - un solo host, un solo puerto y un solo `hostaddr`; si hay `hostaddr` (y la política
    lo admite) se valida igual que `host`;
  - socket Unix siempre sin TLS;
  - para cualquier otro destino, TLS verificado contra la CA indicada con
    `SslMode::Require`;
  - las IP no especificadas o multicast se rechazan.
- Con `unix_peer_uid`, antes de hablar PostgreSQL se comprueba el propietario del socket
  y el UID real del peer.
- Sin `unix_peer_uid`, el directorio del socket tiene que ser de root o del usuario del
  servicio, estar en una cadena de confianza (`lxi_files::trusted_dir`) y no ser
  escribible por nadie más, ni con sticky: si no, alguien podría crear antes el socket y
  hacerse pasar por el servidor. Un directorio del usuario `postgres` (como
  `/var/run/postgresql`) exige por tanto fijar el UID del servidor. La conexión de
  cancelación aplica la misma regla. Un consumidor que acepte el riesgo lo declara con
  `Policy.shared_socket_dir` (la política estricta no lo acepta).
- *Decisión mía:* el valor por defecto es el estricto, y un consumidor que necesite
  otra política la elige de forma explícita.

**Plazos.**
- `Budget { connect, statement, total }`: el presupuesto total cuenta desde la apertura
  y no se renueva con cada consulta.
- Cada operación usa `min(statement, restante)` como tiempo de espera del cliente, y fija
  `statement_timeout` en el servidor con el mismo valor.
- *Decisión mía, la mejora sobre los clientes previos:* si vence el plazo del cliente, se manda
  la cancelación del servidor (`cancel_token`) antes de devolver `Timeout`, para que la
  consulta no siga corriendo en PostgreSQL.
- `Session::renew()` abre un presupuesto nuevo, por ejemplo para cada heartbeat, y
  `renew_within(restante)` lo recorta a lo que queda (2026-11-08).

**API.**
- `Session::open(&Settings, Budget) -> Result<(Session, Transport)>`
- `Session::query`, `query_one`, `execute` y `batch_execute`.
- `begin`, `commit` y `rollback`, mediante sentencias explícitas.
- `server_version_num()`.
- Errores tipados: `Configuration`, `Unavailable`, `Timeout` y
  `Server { sqlstate, message }`. El texto del servidor solo lo ve quien llama, que
  decide qué muestra.

**Pool.**
- `Pool::new(settings, budget, max, setup)`; `get()` devuelve una sesión ya preparada
  (`setup` fija los parámetros de sesión y comprueba el contrato del consumidor).
- Una sesión que falla o que vence su plazo no vuelve al pool.
- Tampoco vuelve una sesión con una transacción abierta (`begin` sin `commit` o
  `rollback` con éxito): la siguiente petición nunca hereda su estado. Las transacciones
  se abren con `Session::begin`, no con un `BEGIN` crudo, para que el pool lo sepa.
- Una sesión reutilizada empieza limpia: `DISCARD ALL` (ajustes, roles, objetos
  temporales, sentencias preparadas, locks advisory), los ajustes de este crate otra vez
  y el `setup` del consumidor. Si no se puede limpiar, se descarta y se abre otra.
- `get_within(restante)`: la sesión (y su conexión y `setup`, si es nueva) nunca tiene
  más tiempo que el que le queda a la petición; al volver al pool recupera el
  presupuesto completo.
- *Decisión mía:* `max` está acotado entre 1 y 16, y el pool no espera: si está lleno,
  abre una conexión nueva hasta `max` y después devuelve `Unavailable`.

## 3. Pruebas

- **Unitarias:** la tabla de la política de transporte y los cálculos del presupuesto.
- **Integración** con PostgreSQL 16 en podman: TLS verificado y CA errónea, socket Unix
  con el peer UID correcto y con otro, plazo vencido con cancelación en el servidor (que
  `pg_sleep` deje de aparecer en `pg_stat_activity`), presupuesto total no renovable y
  sesiones del pool que no vuelven tras un error.
- Runner en `tools/run_pg_integration.py`, sin esquema de ningún servicio.

## 4. Siguiente

Las iteraciones siguientes: `lxi-files` (recorrido con `openat`), `lxi-ipc`, `lxi-exit` y
`lxi-audit`.
