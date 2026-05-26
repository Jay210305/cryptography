# 08 — Limitaciones y Trabajo Futuro

[← Análisis de Benchmarks](07_analisis_benchmarks.md) | [Índice](00_indice.md)

---

## 1. Limitaciones Explícitas

### 1.1 Gestión de Claves (PKI)

El protocolo asume que las claves públicas del manufacturer están **pre-provisionadas** en el dispositivo IoT. No se aborda:

- **Distribución de claves**: ¿cómo llegan las claves públicas al dispositivo de forma segura durante la fabricación?
- **Revocación**: si una clave privada del manufacturer se compromete, ¿cómo se notifica a los dispositivos desplegados para que dejen de confiar en ella?
- **Rotación de claves**: ¿cómo se actualizan las claves de confianza sin acceso físico al dispositivo?
- **Almacenamiento seguro**: las claves privadas del manufacturer deberían estar en un HSM (Hardware Security Module). La implementación actual las mantiene en memoria.

Diseñar un PKI completo para esquemas híbridos post-cuánticos es un problema de investigación abierto que excede el alcance de este proyecto.

### 1.2 Seguridad Física

No se implementan contramedidas contra:

- **Side-channel attacks**: análisis de timing, consumo eléctrico (power analysis), emanaciones electromagnéticas (EM analysis).
- **Fault injection**: glitching de voltaje o reloj para inducir errores en operaciones criptográficas.
- **Cold boot attacks**: lectura de memoria después de un reinicio.

Estas amenazas requieren contramedidas de hardware (blindaje, sensores de tamper) y de software (masking, shuffling, redundancia) que están fuera del alcance de una implementación en Python de alto nivel.

Nota: la implementación sí incluye mitigaciones parciales:
- Ed25519 usa nonces determinísticos (inmune a ataques por nonce reutilizado).
- Las comparaciones de claves usan `hmac.compare_digest()` (tiempo constante).
- liboqs internamente utiliza código de tiempo constante en las operaciones sensibles.

### 1.3 Verificación Formal

No se realizan pruebas formales del protocolo con herramientas como:

- **ProVerif**: verificación automática de protocolos criptográficos en el modelo simbólico (Dolev-Yao).
- **Tamarin Prover**: verificación de protocolos de seguridad con modelo computacional.
- **CryptoVerif**: pruebas de seguridad computacional automatizadas.

Una verificación formal confirmaría que el protocolo no tiene defectos lógicos sutiles (e.g., ataques de reflexión, confusión de roles). Sin embargo, la complejidad de modelar un esquema híbrido con dos KEM y dos firmas en estas herramientas es considerable.

### 1.4 Plataforma de Benchmarking

Los benchmarks se ejecutan en un **desktop con Python 3.11 sobre Windows**, no en hardware embebido real. Las implicaciones:

- **Python overhead**: el intérprete de Python introduce overhead significativo en comparación con C/Rust. Los tiempos reportados son pesimistas.
- **No refleja hardware IoT**: un ARM Cortex-M4 (común en IoT) tendría tiempos 10-100x mayores para las operaciones criptográficas, y memoria limitada (~256 KB RAM).
- **AES-NI**: los benchmarks de AES-256-GCM se benefician de instrucciones AES-NI del procesador x86. En ARM sin aceleración AES, ChaCha20 sería más rápido incluso para payloads grandes.
- **Variabilidad del OS**: el scheduler del sistema operativo introduce variabilidad en las mediciones. Se mitiga con 100+ iteraciones y estadísticas robustas (mediana, no solo media).

### 1.5 Protección Anti-Replay

El protocolo no incluye mecanismos para prevenir ataques de replay:

- Un atacante puede capturar un paquete válido y reenviarlo repetidamente al dispositivo.
- El dispositivo lo aceptará cada vez (las firmas son válidas, la integridad pasa).
- En el contexto de firmware, esto podría forzar una **downgrade**: reenviar una versión antigua del firmware con una vulnerabilidad conocida.

Mitigación estándar: incluir un **número de versión monotónico** o un **timestamp** dentro del payload firmado, y que el dispositivo rechace versiones anteriores a la instalada actualmente.

### 1.6 Recuperación ante Fallos

No se implementa:

- **Retransmisión**: si un paquete se pierde o se corrompe en tránsito, no hay mecanismo de retransmisión a nivel de protocolo (se confía en TCP).
- **Actualización parcial**: si la verificación falla, todo el firmware se rechaza. No hay mecanismo para actualizaciones delta o parciales.
- **Rollback seguro**: si una actualización corrompe el dispositivo, no hay mecanismo de rollback a la versión anterior.

### 1.7 Tamaño de Claves ML-DSA-65

Las claves públicas ML-DSA-65 (1,952 bytes) y las firmas (3,309 bytes) son significativamente más grandes que sus equivalentes clásicos. Para dispositivos IoT con memoria extremadamente limitada (e.g., sensores de 8 KB de RAM), almacenar las claves de confianza puede ser un desafío.

Alternativas con claves más pequeñas (como SLH-DSA basado en hash) tienen firmas aún más grandes (~17 KB para NIST L3). ML-DSA-65 ofrece el mejor balance de tamaños en el panorama post-cuántico actual.

---

## 2. Trabajo Futuro

### 2.1 Benchmarks en Hardware IoT Real

Ejecutar el protocolo en plataformas embebidas representativas:

- **ARM Cortex-M4** (STM32F4): procesador común en IoT, ~168 MHz, ~256 KB RAM, sin AES-NI.
- **ARM Cortex-M33** (con TrustZone): permite medir el impacto de ejecutar crypto en secure world.
- **RISC-V** (ESP32-C3): arquitectura emergente en IoT.

Esto proporcionaría tiempos realistas para dispositivos desplegados y ayudaría a calibrar el umbral adaptativo de cifrado para hardware sin AES-NI.

### 2.2 Diseño de PKI Híbrida

Diseñar una infraestructura de clave pública que soporte:

- Certificados híbridos (que contengan ambas claves públicas en un solo certificado X.509).
- Revocación eficiente (CRL o OCSP adaptado para dispositivos con conectividad intermitente).
- Cadena de confianza desde una CA raíz hasta el firmware firmado.
- Compatibilidad con los borradores de IETF para certificados híbridos (composite signatures).

### 2.3 Verificación Formal con ProVerif

Modelar el protocolo en el cálculo de procesos aplicado de ProVerif para verificar automáticamente:

- Autenticación mutua (el firmware proviene realmente del manufacturer).
- Secreto de la clave simétrica (ningún tercero puede derivarla).
- Inyectividad (cada paquete aceptado corresponde a exactamente un envío).

El desafío principal es modelar correctamente la semántica AND de la verificación dual y las propiedades híbridas del KEM.

### 2.4 Cripto-Agilidad

Implementar una capa de abstracción que permita sustituir algoritmos sin cambiar la arquitectura:

```python
SIGNATURE_SCHEMES = {
    "classical": Ed25519,
    "post_quantum": ML_DSA_65,  # reemplazable por SLH-DSA, FALCON, etc.
}

KEM_SCHEMES = {
    "classical": X25519,
    "post_quantum": ML_KEM_768,  # reemplazable por otro candidato NIST
}
```

Si se descubre una debilidad en ML-DSA-65, poder reemplazarlo por SLH-DSA (basado en hash, con supuestos de seguridad más conservadores) sin rediseñar el protocolo.

### 2.5 Integración con Secure Boot Chains

Integrar el esquema de verificación dual con las cadenas de arranque seguro existentes:

- **UEFI Secure Boot**: adaptar el protocolo para verificar firmware en el arranque.
- **ARM TrustZone**: ejecutar la verificación en el secure world.
- **MCUboot**: integrar como mecanismo de verificación en el bootloader de MCU.

### 2.6 Protección Anti-Replay

Añadir al `FirmwareBundle`:

```python
metadata = {
    "version": 42,               # monotónico
    "timestamp": 1716681600,      # Unix epoch
    "min_version": 40,            # versión mínima aceptada
}
```

El dispositivo rechazaría bundles con `version <= current_version` o con `timestamp` fuera de una ventana aceptable.

### 2.7 Compresión del Payload

Para dispositivos con ancho de banda limitado (LoRa, NB-IoT), comprimir el firmware antes de firmarlo podría reducir significativamente el overhead de transmisión:

```
F_compressed = zstd.compress(firmware)
digest = SHA3-256(F_compressed)
```

El firmware comprimido se descomprimiría después de la verificación, manteniendo la integridad.

---

## 3. Resumen

Este proyecto implementa y valida un protocolo de autenticación de firmware híbrido que es:

- **Funcionalmente completo**: firma, cifrado, transmisión, descifrado y verificación.
- **Criptográficamente explícito**: usa primitivos estandarizados (FIPS 203, 204, RFC 8032).
- **Empíricamente validado**: benchmarks reproducibles sobre 5 tamaños de firmware.
- **Seguro durante la transición**: robusto ante adversarios clásicos y cuánticos.

Las limitaciones son reconocidas explícitamente y cada una tiene un camino de mitigación identificado como trabajo futuro.

---

[← Análisis de Benchmarks](07_analisis_benchmarks.md) | [Índice](00_indice.md)
