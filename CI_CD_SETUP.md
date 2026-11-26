# GitHub Actions — Secure Digital Document Vault

Esta configuración agrega QA, análisis de seguridad, revisión de dependencias y empaquetado de releases.

## Archivos incluidos

| Archivo | Función | Cuándo se ejecuta |
|---|---|---|
| `.github/workflows/ci.yml` | Instala el proyecto, comprueba dependencias, compila y ejecuta pytest | Push, PR hacia `main` y ejecución manual |
| `.github/workflows/security.yml` | CodeQL y auditoría de dependencias con `pip-audit` | Push/PR hacia `main`, semanal y manual |
| `.github/workflows/dependency-review.yml` | Detecta dependencias vulnerables agregadas o actualizadas en un PR | Cada PR hacia `main` |
| `.github/workflows/release.yml` | Construye wheel y source distribution y los adjunta al GitHub Release | Publicación de Release |
| `.github/dependabot.yml` | Propone actualizaciones de dependencias Python y GitHub Actions | Semanal |

## Instalación en el repositorio local

Extrae el contenido del ZIP en la raíz del repositorio clonado. Debe quedar esta estructura:

```text
Cryptography-2027-1/
├── .github/
│   ├── dependabot.yml
│   └── workflows/
│       ├── ci.yml
│       ├── security.yml
│       ├── dependency-review.yml
│       └── release.yml
├── src/
├── tests/
├── pyproject.toml
└── ...
```

Después:

```bash
git switch main
git pull origin main
git switch -c ci/github-actions
git add .github CI_CD_SETUP.md
git commit -m "ci: add GitHub Actions for QA and security"
git push -u origin ci/github-actions
```

Abre un Pull Request de `ci/github-actions` hacia `main`. No integres los workflows directamente a `main`.

## Configuración en GitHub

### 1. Actions

En el repositorio: **Settings → Actions → General**.

- Asegúrate de que GitHub Actions esté habilitado.
- En Actions permissions, permite las acciones necesarias para los workflows.
- Si la organización restringe acciones de terceros, autoriza las acciones oficiales usadas aquí: `actions/*` y `github/codeql-action/*`.

### 2. Security

En **Settings → Code security and analysis**:

- Habilita **CodeQL analysis** si la opción está disponible.
- Habilita **Dependency graph**.
- Habilita **Dependabot alerts**.
- Habilita **Dependabot security updates**.

El workflow también ejecuta `pip-audit`; este comando puede fallar si encuentra dependencias vulnerables. Eso es intencional: se debe revisar y actualizar la dependencia afectada, no ignorar el resultado automáticamente.

### 3. QA y protección de ramas

En **Settings → Rules → Rulesets** (o **Settings → Branches → Branch protection rules**, según la interfaz):

Crea una regla para `main`:

- Require a pull request before merging.
- Require approvals: al menos 1.
- Require status checks to pass before merging.
- Selecciona el check del job `Pytest (Python ...)` para las cuatro versiones de Python.
- Selecciona `CodeQL (Python)`, `Audit Python dependencies` y `Review dependency changes` cuando aparezcan después de sus primeras ejecuciones.
- Require conversation resolution.
- Block force pushes y deletion.

No marques como obligatorios nombres de checks que todavía no hayan aparecido en una ejecución real. Primero integra el workflow en una rama, abre un PR y espera a que GitHub registre los checks.

### 4. Deployment

El proyecto actual es una biblioteca/módulo Python académico; no hay un servidor, contenedor ni entorno productivo definido para desplegar una aplicación. Por eso el workflow de Deployment no hace un despliegue ficticio: construye `wheel` y `sdist` y los adjunta a un GitHub Release.

Para probarlo:
1. Integra los workflows y corrige los fallos de CI.
2. Crea un tag versionado, por ejemplo `v0.1.0`.
3. Crea un GitHub Release asociado a ese tag y publícalo.
4. Comprueba que se adjunten los archivos de `dist/`.

No se requieren secretos adicionales para el Release: se utiliza el `GITHUB_TOKEN` con permiso `contents: write` limitado al workflow.

## Estado actual conocido: pytest falla durante la colección

En el ZIP revisado, `python -m pytest -q` falla antes de ejecutar los tests porque `src/encryption/signed_hybrid.py` importa `HEADER` desde `encryption.hybrid_core`, pero ese símbolo no está definido en `hybrid_core.py`. El fallo afecta al menos a `tests/test_d5_security.py` y `tests/test_signed_hybrid.py`.

El primer PR de CI probablemente quedará rojo hasta corregir esa integración D5/D3. No desactives esos tests ni conviertas el fallo en un `continue-on-error`: el check debe proteger `main`.

## Pendientes antes de exigir todos los checks

- Corregir la importación/definición del header D3 y alinear el identificador del esquema: el código implementa X25519, mientras que el mensaje de error de D5 menciona P-256.
- Reconciliar `requirements.txt` con `pyproject.toml`; `pycryptodome` no está declarado en las dependencias del proyecto y debe justificarse o eliminarse.
- Ejecutar localmente `python -m pip install -e ".[test]"` y `python -m pytest -v`.
- Revisar las alertas de CodeQL y `pip-audit`; no aceptar automáticamente las actualizaciones de Dependabot sin revisar sus cambios.

## Nota sobre CI/CD

CI valida automáticamente cada cambio antes de integrar. CD, en este repositorio, queda limitado a generar y publicar artefactos versionados. No hay despliegue continuo a infraestructura porque el repositorio no define un servicio ni un entorno destino.
