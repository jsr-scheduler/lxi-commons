# Controles de pánicos y errores controlados

Ampliación de RUST_ENGINEERING.md para todo el código Rust de la serie.

## Propiedad y alcance

Un servicio no debe provocar panic por errores previsibles de datos, conversión,
aritmética, acceso a campos, SQL o servicios. Usar errores tipados `Result` y
propagación con `?`, y salida controlada. No reemplazar unwrap por expect, panic, abort o
un valor por defecto.

Ni Clippy, ni buscar símbolos en un binario, ni el fuzzing, ni nuestros tests demuestran
la ausencia total de pánicos. El análisis de fuentes por regex tampoco es una prueba. Un
símbolo panic presente puede ser inalcanzable; uno ausente no basta ante dependencias,
enlace dinámico y llamadas indirectas. Fijar artefactos, toolchain, features y contratos
para cualquier análisis futuro.

Estados distintos: FAIL cuando se encuentra un fallo; NOT_RUN cuando falta ejecución o
herramienta; CHECKS_PASS cuando pasan controles concretos; NOT_DEMONSTRATED cuando no se
ha demostrado la ausencia de pánicos. PROVEN_UNDER_PROFILE solo podrá emitirlo un
analizador justificado del subconjunto, con informe de alcance, supuestos y cobertura. El
verificador de este repositorio nunca emite ese estado.

## Barreras de compilación

En cada raíz de crate propia:

```rust
#![forbid(unsafe_code, unused_must_use)]
#![forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic,
          clippy::todo, clippy::unimplemented,
          clippy::unreachable, clippy::indexing_slicing, clippy::string_slice,
          clippy::arithmetic_side_effects, clippy::as_conversions,
          clippy::dbg_macro)]
```

Los lints de Clippy requieren ejecutar Clippy; `cargo build` no los ejecuta.
`unknown_lints` debe producir error con la toolchain fijada. No activar el grupo
restriction completo: seleccionar reglas concretas. Prohibido configurar excepciones que
oculten aritmética peligrosa o supresiones globales para aprobar. Un assert de prueba no
demuestra que una operación de producción no pueda fallar.

`tools/check_rust_policy.py` aplica también las prohibiciones con argumentos `-F` al
invocar Clippy. Conserva Cargo.lock, no usa shell, se detiene ante un fallo y guarda
stdout/stderr completos. Aísla `CARGO_TARGET_DIR` por plataforma y manifiesto. Se ejecuta
en macOS y en el builder Linux (`tools/run_linux_policy.py`). No genera el lockfile ni
instala herramientas.

```bash
python3 tools/check_rust_policy.py --project . --manifest Cargo.toml
```

CHECKS_PASS es el éxito de esos controles, no la propiedad no-panic. Para un consumidor
que exija prueba de pánicos, `--require-panic-proof` devuelve 3 aunque pasen los checks,
porque este runner no aporta la demostración. No fabricar un certificado ni retirar el
flag para simularla. Otros códigos: 0 controles ejecutados sin fallo; 1 fallo; 2
requisito, uso o herramienta ausente.

## Cambios de implementación requeridos

- Aritmética mediante checked operations y límites de tipo, incluidas la división por
  cero y la negación del mínimo. El overflow se devuelve como error, no se deja al panic
  de overflow-checks.
- Conversiones falibles comprobadas, acceso con get o alternativa segura y manejo
  explícito de None/Err. Los caminos desconocidos producen un error, nunca cero.
- Escritura de diagnósticos con IO falible gestionada: println/eprintln pueden fallar.
- No usar RefCell::borrow/borrow_mut, lock().unwrap, casts truncantes o APIs con pánico
  sin contrato.
- Revisar las APIs de las dependencias y sus rutas de pánico: las prohibiciones no se
  propagan como garantía a dependencias y biblioteca estándar.
- Límites de recursos, recursión y entradas explícitos. OOM, abortos, señales y fallos
  del sistema no se presentan como errores controlados ni se prometen imposibles.
- No usar panic=abort ni catch_unwind como demostración de la propiedad.

## Pruebas del control

`tools/check_lint_controls.py` ejecuta un fixture positivo y fixtures Rust negativos
reales: unsafe, `Result` ignorado, unwrap, expect, panic/todo/unimplemented/unreachable,
overflow y división, índices y string slicing, `as`, `dbg!`, un `allow` que intenta
relajar `forbid` y un lint desconocido. Cada negativo tiene una causa esperada
identificable; fallar por una dependencia ausente o por sintaxis no cuenta como rechazo
de la regla.
