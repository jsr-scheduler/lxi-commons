# Norma de ingeniería Rust de la serie: seguridad, corrección y rendimiento

Aplica a todo el código Rust propio de los crates y servicios de la serie. Es una
política del proyecto basada en las referencias de la sección 9, no una certificación
externa, y no declara implementados sus controles: cada cambio aporta resultados reales.
Aplicar también PANIC_POLICY.md. Las prohibiciones explícitas del propietario prevalecen
sobre excepciones de guías externas.

## 1. Reglas de aceptación

- La corrección funcional, la integridad de datos y la seguridad son obligatorias. El
  rendimiento se demuestra con mediciones reproducibles sin cambiar la semántica.
- Toda funcionalidad no soportada produce un error explícito; nunca un éxito ficticio.
- No cerrar un cambio mientras fallen requisitos esenciales, aunque el fallo esté
  documentado.

## 2. Prohibición de unsafe propio

Todas las raíces de crate propias incluyen `#![forbid(unsafe_code)]`.

- No se permite `unsafe` propio: bloques, funciones, implementaciones o atributos
  inseguros, ni excepciones por FFI, ABI, aliasing o rendimiento. Nada de `transmute`,
  accesos unchecked ni ensamblador.
- La biblioteca estándar y las dependencias pueden contener unsafe interno; `forbid` no
  se propaga a ellas. Inventariar dependencias, features, código nativo y límites de
  confianza; no afirmar que todo el binario está libre de unsafe. Revisar también el
  código de macros y scripts de build.

## 3. Errores y límites

- Errores tipados y `Result` para fallos previsibles de datos, conversiones, overflow,
  división por cero, SQL, red, ficheros y autoridad.
- Prohibidos `unwrap()`, `expect()`, `panic!()`, `todo!()` o `unimplemented!()` en
  producción ante situaciones que provoquen las entradas o el entorno.
- Una invariante interna imposible produce un error interno identificable cuando sea
  viable. No llamar imposible a un caso simplemente no implementado. Las aserciones de
  prueba son admisibles.
- No usar `catch_unwind` como manejo ordinario de errores ni asumir que cubre abortos.
- Propagar errores y comprobar los exit codes de compilación, contenedores y ejecución.
- Limitar tamaños de entrada, profundidad, memoria y operaciones externas según el
  contexto. Ni bucles, ni reintentos, ni cachés ilimitados.
- Aritmética con operaciones comprobadas y conversiones falibles; `overflow-checks =
  true` en release solo como defensa adicional. Nada de float para valores exactos.

## 4. Texto, tiempo y fronteras externas

- UTF-8 por defecto en fuentes, logs e interfaces. CCSID/EBCDIC explícito por campo,
  objeto o sesión; sin sustituciones silenciosas de caracteres.
- Diferenciar bytes, caracteres, posiciones y longitudes; no cortar UTF-8 por un índice
  de bytes arbitrario. Los datos binarios no se convierten como texto.
- UTC para instantes, auditoría y sesiones PostgreSQL; zona y presentación
  configurables (INHERITED_LESSONS.md).
- SQL parametrizado y bindings tipados. No concatenar valores de usuario en SQL ni en
  shell.
- Credenciales fuera de Git y de los logs; errores con contexto suficiente sin revelar
  secretos.

## 5. Rendimiento

- Medir antes de optimizar: throughput, p50/p95/p99, CPU, memoria, asignaciones, IO,
  bloqueos y round trips por recorrido representativo.
- Cachés y pools con límites, invalidación y duración coherentes. No cambiar orden,
  visibilidad o aislamiento para mejorar una métrica.
- Comparar opciones de compilación con mediciones; no usar `target-cpu=native` en
  artefactos distribuidos sin un perfil de despliegue documentado.
- Benchmark sin emulación para afirmar el rendimiento de un destino. Toda mejora
  conserva los tests de corrección.

## 6. Dependencias, builds y plataformas

- Fijar toolchain y dependencias. Conservar Cargo.lock y usar `--locked` en validación.
- Revisar procedencia, licencia, mantenimiento, features, advisories y dependencias
  transitivas (`cargo-deny`). Evitar capacidades o dependencias innecesarias.
- Linux se compila y ejecuta dentro de podman; macOS en el host. Separar
  `CARGO_TARGET_DIR` y salidas por plataforma. Guardar versiones y digest de imágenes.
- No borrar lockfiles para resolver fallos. Los cambios de dependencias son explícitos y
  se vuelven a validar.
- Temporales y evidencias de trabajo en `build/` del proyecto. No tocar recursos de
  podman ajenos.

## 7. Checks mínimos por cambio

Con la toolchain fijada (`tools/check_rust_policy.py` los ejecuta con las barreras `-F`):

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --locked --release
cargo build --locked --release
```

- No debilitar pruebas para obtener PASS ni marcar como pasado un test omitido.
- Registrar comandos, stdout/stderr completos, entorno, retorno y hashes; no ocultar
  fallos con head/tail. Etiquetar NOT_RUN/BLOCKED con su causa. Una revisión estática no
  se registra como ejecución.

## 8. Cierre y Git

- Commit local con código, tests, documentación y evidencia del cambio. Commits y tags
  firmados. Tag anotado solo tras cumplir el cierre.
- No hacer push sin petición del propietario ni mover o borrar tags existentes. Corregir
  cierres históricos con registros nuevos, sin reescribir sus resultados.

## 9. Referencias

| Fuente | Uso |
|---|---|
| [ANSSI Secure Rust Guidelines](https://anssi-fr.github.io/rust-guide/) | Base de seguridad. Nuestra prohibición de unsafe no admite sus excepciones. |
| [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) | APIs, invariantes, errores, documentación y convenciones. |
| [Clippy](https://doc.rust-lang.org/clippy/) | Herramienta oficial de análisis y categorías de lints. |
| [Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html) | Release, overflow, optimización y comportamiento de panic. |
| [Rust forbid](https://doc.rust-lang.org/std/attribute.forbid.html) | Prohibiciones que no se pueden relajar con allow. |
| [The Rust Performance Book](https://nnethercote.github.io/perf-book/) | Referencia complementaria de rendimiento. |
