# Diseño: lxi-oidc, lxi-pam y lxi-http

Fecha: 2026-11-09. Alcance aprobado por el propietario: M2 del plano de gestión del
broker (`authority-broker`, spec 2026-11-09 §3.2). Código de JSR `3b75827` adaptado sin
tocar JSR, con sus tests portados y sus constantes; lo que cambia va marcado. Plan:
`docs/superpowers/plans/2026-11-09-m2-oidc-pam-http.md`.

## lxi-oidc (de `api-rest/src/auth.rs`)

- `Verifier::new(&Settings, jwks)` / `from_file`: solo algoritmos asimétricos; emisor,
  audiencia, `exp`, `nbf` (60 s de margen), `sub` obligatorio; un token `typ: ID` no es
  de acceso; un usuario sin el claim configurado se rechaza, una aplicación usa `sub`.
- El JWKS se relee en `reload` y con un `kid` desconocido, como mucho cada 30 s; un
  fichero malo deja las claves en uso.
- `Verified { kind, name, sub, groups, expires }` en vez del `Principal` de JSR.
- *Más estricto que JSR:* `exp`, `nbf` e `iat` deben ser segundos enteros no negativos.
  `jsonwebtoken` 9 los lee como `u64` y se salta uno que no puede leer; JSR solo pedía
  un número, y un `nbf` negativo o con decimales pasaba sin comprobarse.
- *Decisión mía:* el aviso de relectura va a una función `with_log` del servicio.

## lxi-pam (de `auth-local/src/lib.rs`)

- `Pam::check`: PAM también para nombres que no existen, `account_management`, y
  rechazo si un módulo cambia `PAM_USER` (S-50). `authenticate` añade la cuenta.
- `Account { name, uid, groups, superuser }`, `lookup` sin PAM ni root.
- `helper`: un ayudante con root para un servicio sin privilegios. Un frame de
  `lxi-ipc` en cada sentido; comprueba el UID del cliente antes de leer y responde solo
  `accepted`, `rejected` o `unavailable`. El cliente comprueba el UID del ayudante
  antes de enviar la contraseña, espera la respuesta 10 s (PAM tarda unos 2 s en
  rechazar) y lee la cuenta él mismo.
- Prueba real en Linux: `tools/run_pam_integration.py` (cuentas desechables, `pam_unix`,
  contraseña aleatoria generada dentro del contenedor). La imagen
  `localhost/lxi-builder:1.90-pam` añade `libpam0g-dev`.

## lxi-http (de `api-rest/src/sessions.rs` y `lib.rs`)

- `Sessions<U: LocalUsers>`: tokens opacos guardados como SHA-256, 30 min de inactividad,
  12 h de vida, 1024 sesiones, 16 por usuario; límites de JSR por dirección (5), por
  usuario (50) y por segundo (100); refresco de cuentas cada 15 s, rechazo a los 180 s
  sin refrescar. La regla de JSR "ni uid 0 ni fuera de un grupo de rol" pasa a
  `LocalUsers::eligible`, que pone el servicio.
- `SignIn::attempt`: el orden de JSR (límites de longitud, throttling, 16 a la vez,
  comprobación bloqueante, todo rechazo a los 4 s, apertura). *Más estricto que JSR:*
  el hueco de PAM va con la conversación, no con la petición; un cliente que se va no
  lo libera mientras PAM sigue.
- `server`: `serve_tls` (rustls con ring, solo HTTP/1.1, 10 s para las cabeceras),
  `limits` (cuerpo de 64 KiB, 64 peticiones a la vez y 429, 30 s hasta la respuesta y
  408, `nosniff`, `no-referrer` y `no-store` salvo que
  el handler elija su caché), `bearer`, `cookie` y `session_cookie` (`HttpOnly; Secure;
  SameSite=Strict; Path=/`). *Decisión mía:* el semáforo de 64 es una capa genérica; en
  JSR estaba en su despacho. *Más estricto que JSR:* sin HTTP/2 (axum-server lo ofrecía
  por ALPN y sus streams no tienen el plazo de cabeceras; hace falta `Server::http1_only`,
  porque el de hyper-util solo sigue detectando el prefacio h2) y con plazo por petición
  (un cuerpo lento retenía un permiso sin límite).

## Límites conocidos

- El suelo de 4 s iguala los rechazos mientras PAM tarde menos; con un PAM más lento en
  las contraseñas malas (`pam_faildelay` alto, LDAP lento) se distinguirían de los
  rechazos rápidos de cuentas no elegibles. Diseño de JSR (S-07).
- `with_lasting_user_failures` (la pasarela de IBM i de JSR) cierra la puerta a nombres
  nuevos con la tabla llena (50 000 nombres); el broker no usa ese modo.
- mTLS para aplicaciones y el binario `ab-pam-helper` son de M3.
