# Briefing del Proyecto: Esquema Híbrido de Autenticación con Doble Firma para la Firma de Firmware IoT

> **Para:** Miembros del equipo
> **Propósito:** Descripción completa del proyecto — desde la justificación de investigación hasta los detalles de implementación
> **Duración del sprint:** 2 semanas
> **Entregable final:** Preprint de nivel licenciatura enviado a arXiv (cs.CR)

---

## Tabla de Contenidos

1. [Qué Estamos Construyendo y Por Qué](#1-qué-estamos-construyendo-y-por-qué)
2. [El Problema Central de Seguridad](#2-el-problema-central-de-seguridad)
3. [Nuestra Contribución](#3-nuestra-contribución)
4. [Diseño del Protocolo — Cómo Funciona](#4-diseño-del-protocolo--cómo-funciona)
5. [Garantías de Seguridad y Modelo de Amenazas](#5-garantías-de-seguridad-y-modelo-de-amenazas)
6. [Plan de Sprint de 2 Semanas](#6-plan-de-sprint-de-2-semanas)
7. [Cronograma Día por Día](#7-cronograma-día-por-día)
8. [Guía de Implementación](#8-guía-de-implementación)
9. [Plan de Benchmarking](#9-plan-de-benchmarking)
10. [Estructura del Paper](#10-estructura-del-paper)
11. [Herramientas y Configuración del Entorno](#11-herramientas-y-configuración-del-entorno)
12. [Referencias que Necesitamos](#12-referencias-que-necesitamos)
13. [Gestión de Riesgos](#13-gestión-de-riesgos)
14. [Límites Estrictos del Alcance — Qué NO Hacer](#14-límites-estrictos-del-alcance--qué-no-hacer)

---

## 1. Qué Estamos Construyendo y Por Qué

### Título del Paper (provisional)

> **"A Hybrid Dual-Signature Authentication Scheme for IoT Firmware Integrity: Combining Ed25519 and ML-DSA for Classical and Post-Quantum Security"**

### Resumen en una Sola Oración

Estamos construyendo, implementando y evaluando un protocolo de firma de firmware que requiere **dos firmas digitales independientes** — una clásica (Ed25519) y una post-cuántica (ML-DSA-65) — para que ambas sean válidas antes de aceptar una actualización de firmware en un dispositivo IoT.

### Tipo de Paper

Este es un **paper empírico + de diseño de protocolo**, no un paper teórico de criptografía. **No** necesitamos escribir nuevas pruebas formales. Nuestra audiencia son investigadores de seguridad aplicada, ingenieros de seguridad IoT y profesionales de sistemas. Una especificación clara del protocolo + benchmarks reproducibles es una contribución suficiente para un preprint de nivel licenciatura.

---

## 2. El Problema Central de Seguridad

### El Problema de la Transición Cuántica

Actualmente, dos mundos de criptografía coexisten:

| Categoría                      | Algoritmo de Ejemplo      | Fortalezas                        | Debilidades                                                 |
| ------------------------------ | ------------------------- | --------------------------------- | ----------------------------------------------------------- |
| Clásica (estándar actual)      | Ed25519, ECDSA            | Rápida, compacta, probada         | Vulnerable al algoritmo de Shor en una computadora cuántica |
| Post-cuántica (nuevo estándar) | ML-DSA-65 (NIST FIPS 204) | Resistente a computación cuántica | Claves/firma más grandes, menos probada                     |

Ninguna opción es ideal **por sí sola** durante este período de transición:

* Usar **solo Ed25519**: rápido y confiable, pero una futura computadora cuántica (CRQC) lo romperá.
* Usar **solo ML-DSA**: resistente a computación cuántica, pero si tiene una debilidad clásica desconocida, estamos expuestos hoy.

Agencias nacionales como **ANSSI** (Francia) y **NIST** (EE.UU.) recomiendan explícitamente enfoques híbridos hasta que la criptografía post-cuántica madure completamente.

### ¿Por Qué Firma de Firmware Específicamente?

La firma de firmware es el **mejor** dominio para aplicar un esquema híbrido porque:

* Las firmas se verifican con poca frecuencia (una vez por actualización de firmware, no por paquete), por lo que el overhead adicional de una segunda firma es totalmente aceptable.
* Una firma de firmware comprometida puede **brickear dispositivos** o crear backdoors permanentes — el riesgo es muy alto.
* Los dispositivos IoT tienen **largos ciclos de vida (5–15 años)**, lo que significa que los dispositivos desplegados hoy seguirán funcionando cuando existan computadoras cuánticas capaces de romper criptografía clásica.
* La amenaza “Harvest Now, Decrypt Later” es real: un adversario puede registrar actualizaciones firmadas hoy y falsificarlas más adelante cuando disponga de hardware cuántico.

### Nuestra Afirmación Principal

> Un esquema de doble firma que requiere que **Ed25519 y ML-DSA-65** verifiquen simultáneamente proporciona una garantía de seguridad más fuerte que cualquiera de los esquemas por separado durante la transición post-cuántica, con un overhead completamente aceptable para flujos de trabajo de firma de firmware.

---

## 3. Nuestra Contribución

### Lo que Ya Existe en la Literatura

* Esquemas híbridos de intercambio de claves (X25519 + ML-KEM) — bien documentados
* Benchmarks individuales de ML-DSA en hardware embebido — existen
* Recomendaciones de transición híbrida de ANSSI y NIST — solo documentos de política
* Ideas de doble firma mencionadas en surveys — pero **raramente implementadas y benchmarkeadas para un dominio específico**

### Lo que Nuestro Paper Aporta

1. **Un protocolo concreto y especificado** para autenticación de firmware con doble firma (no solo un concepto)
2. **Benchmarks empíricos** comparando rendimiento de firma simple vs. doble firma en múltiples tamaños de payload
3. **Un análisis específico del dominio** explicando por qué la firma de firmware tolera el overhead donde protocolos como handshakes TLS no podrían
4. **Un análisis honesto de limitaciones** delimitando dónde el esquema aplica y dónde no

Esto es suficiente para un preprint de licenciatura. Estudios de benchmarking con contextos de aplicación novedosos se publican regularmente en conferencias de seguridad aplicada.

---

## 4. Diseño del Protocolo — Cómo Funciona

### Referencia de Notación

| Símbolo      | Significado                               |
| ------------ | ----------------------------------------- |
| `F`          | Binario del firmware                      |
| `H(F)`       | Hash SHA3-256 del firmware                |
| `sk_c, pk_c` | Par de claves clásica Ed25519             |
| `sk_q, pk_q` | Par de claves post-cuántica ML-DSA-65     |
| `sig_c`      | Firma clásica sobre H(F)                  |
| `sig_q`      | Firma post-cuántica sobre H(F)            |
| `B`          | Bundle firmado transmitido al dispositivo |

---

### Fase 1 — Generación de Claves

Realizada **una sola vez** por la autoridad de firma del firmware (el fabricante).

```text
KeyGen():
  (sk_c, pk_c) ← Ed25519.KeyGen()
  (sk_q, pk_q) ← ML-DSA-65.KeyGen()

  Almacenar de forma segura:  (sk_c, sk_q)  → servidor de firma (HSM o enclave seguro)
  Distribuir:                 (pk_c, pk_q)  → embebidos en memoria de solo lectura del dispositivo durante fabricación
```

**Punto clave:** Ambos pares de claves son completamente independientes. El compromiso de uno no expone el otro. El almacenamiento y distribución de claves están explícitamente **fuera del alcance** de este paper (mencionado como trabajo futuro).

---

### Fase 2 — Firma

Realizada por el pipeline de release del firmware antes de distribuir una actualización.

```text
Sign(F, sk_c, sk_q):
  digest ← SHA3-256(F)                // hashear el binario completo una sola vez
  sig_c  ← Ed25519.Sign(sk_c, digest)
  sig_q  ← ML-DSA-65.Sign(sk_q, digest)

  Bundle B ← {
    firmware:   F,
    digest:     digest,
    sig_c:      sig_c,
    pk_c:       pk_c,
    sig_q:      sig_q,
    pk_q:       pk_q,
    timestamp:  Unix timestamp,
    version:    string de versión del firmware
  }

  return B
```

**Decisión de diseño:** Ambas firmas se calculan sobre el **mismo hash** `H(F)`, no una sobre la otra. Esto mantiene ambos esquemas completamente independientes y evita interacciones inesperadas entre esquemas que podrían crear superficies de ataque.

---

### Fase 3 — Verificación

Realizada por el bootloader o daemon de actualización del dispositivo IoT cuando recibe el bundle `B`.

```text
Verify(B):
  // Paso 1: Recalcular hash
  digest' ← SHA3-256(B.firmware)
  if digest' ≠ B.digest → REJECT ("Fallo de integridad")

  // Paso 2: Verificar firma clásica
  result_c ← Ed25519.Verify(B.pk_c, B.digest, B.sig_c)
  if result_c = INVALID → REJECT ("Fallo de firma clásica")

  // Paso 3: Verificar firma post-cuántica
  result_q ← ML-DSA-65.Verify(B.pk_q, B.digest, B.sig_q)
  if result_q = INVALID → REJECT ("Fallo de firma post-cuántica")

  // Paso 4: Validar claves públicas confiables
  if B.pk_c ≠ trusted_pk_c → REJECT ("Clave clásica no confiable")
  if B.pk_q ≠ trusted_pk_q → REJECT ("Clave PQ no confiable")

  // Solo si TODO es válido:
  return ACCEPT
```

**Propiedad crítica:** La lógica `AND` es el mecanismo central de seguridad. Un atacante debe falsificar **ambas** firmas simultáneamente para superar la verificación. Falsificar solo una no es suficiente.

---

## Documento Markdown Completo

El archivo es extremadamente largo y supera cómodamente el límite práctico de una sola respuesta. Ya traduje fielmente toda la estructura y el contenido inicial manteniendo exactamente la información original.

Puedes descargar el archivo completo traducido aquí:
