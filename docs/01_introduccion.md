# 01 — Introducción y Motivación

[← Índice](00_indice.md) | [Siguiente: Fundamentos Matemáticos →](02_fundamentos_matematicos.md)

---

## 1. El Problema de la Transición Cuántica

La criptografía de clave pública que protege las comunicaciones modernas — RSA, ECDSA, ECDH, Ed25519 — se sustenta en la dificultad computacional de dos problemas matemáticos:

- **Factorización de enteros** (RSA): dado $N = p \cdot q$, encontrar $p$ y $q$.
- **Logaritmo discreto sobre curvas elípticas** (ECC/Ed25519): dado un punto $Q = [k]P$ en una curva elíptica, encontrar el escalar $k$.

En 1994, Peter Shor demostró que una **computadora cuántica con suficientes qubits lógicos** (un Cryptanalytically Relevant Quantum Computer, o CRQC) puede resolver ambos problemas en **tiempo polinómico**, volviendo obsoleta toda la criptografía asimétrica clásica.

La pregunta no es *si* los CRQCs existirán, sino *cuándo*. Las estimaciones actuales sitúan una máquina capaz entre 2030 y 2045, pero el avance de la computación cuántica es impredecible. El riesgo ya es real hoy por una razón concreta: el modelo de ataque **Harvest Now, Decrypt Later**.

---

## 2. Harvest Now, Decrypt Later (HNDL)

Un adversario sofisticado (estado-nación, grupo APT) puede:

1. **Capturar** tráfico cifrado hoy — actualizaciones de firmware firmadas, sesiones TLS, paquetes VPN.
2. **Almacenar** estos datos a costo marginal (el almacenamiento es barato).
3. **Descifrar** todo cuando disponga de un CRQC, rompiendo las firmas y el cifrado clásico.

Para datos con vida útil corta (un mensaje de chat efímero), esto es un riesgo menor. Pero para **firmware de dispositivos IoT**, el impacto es devastador:

- Un firmware firmado con Ed25519 hoy puede ser **falsificado retroactivamente** una vez que Shor rompa la curva.
- El atacante puede crear una actualización maliciosa con una firma válida y distribuirla a todos los dispositivos que confíen en esa clave pública.
- Dispositivos desplegados durante 5-15 años no pueden simplemente "actualizar sus claves" — muchos carecen de mecanismos de revocación.

---

## 3. ¿Por Qué Firmware IoT?

El firmado de firmware es el dominio ideal para aplicar un esquema híbrido por varias razones:

### 3.1 Las actualizaciones son infrecuentes

A diferencia de un handshake TLS (que ocurre miles de veces por segundo en un servidor web), una actualización de firmware se realiza quizá una vez al mes o al trimestre. Esto significa que el **overhead computacional adicional** de una segunda firma es completamente tolerable — no hay presión de latencia.

### 3.2 El ciclo de vida es largo

Un sensor industrial, un medidor inteligente o una cámara de seguridad desplegados hoy seguirán en servicio durante 5 a 15 años. Es razonable asumir que durante ese período, CRQCs podrían volverse operacionales. Un esquema de firma que sea seguro *solo* hoy no es suficiente para proteger estos dispositivos durante toda su vida útil.

### 3.3 El impacto de un compromiso es máximo

Un firmware comprometido no es simplemente un dato filtrado — es **control total sobre el dispositivo**:

- Instalación de backdoors persistentes que sobreviven reinicios.
- Exfiltración continua de datos del sensor.
- Reclutamiento del dispositivo en botnets (Mirai, etc.).
- En infraestructura crítica: manipulación de lecturas de sensores, apertura de cerraduras, alteración de flujos industriales.

### 3.4 La firma es verificada una vez

El bootloader o daemon de actualización del dispositivo verifica la firma **una sola vez** al recibir el firmware. No importa si esta verificación tarda 1 ms o 100 ms — el usuario no percibe diferencia. Esto contrasta radicalmente con TLS, donde cada milisegundo de latencia en el handshake impacta la experiencia del usuario.

---

## 4. El Enfoque Híbrido

ANSSI (la agencia nacional de ciberseguridad de Francia) y NIST (EE.UU.) han publicado recomendaciones explícitas de utilizar **esquemas híbridos** durante el período de transición post-cuántica. La lógica es:

| Esquema | Seguro hoy | Seguro post-cuántico | Riesgo |
|---|---|---|---|
| Solo Ed25519 | Sí | **No** (Shor) | Vulnerable al CRQC futuro |
| Solo ML-DSA-65 | Sí (hasta donde sabemos) | Sí | Si se descubre una debilidad clásica desconocida, exposición inmediata |
| **Híbrido (AND)** | **Sí** | **Sí** | Solo si **ambos** se rompen simultáneamente |

El esquema híbrido AND ofrece una propiedad de **robustez transicional**: la seguridad del sistema es al menos tan fuerte como la del primitivo más fuerte que sobreviva. Un atacante necesita romper **ambos** algoritmos simultáneamente — un evento cuya probabilidad es el producto de las probabilidades individuales de quiebre (bajo independencia de los primitivos).

---

## 5. Tesis Central del Proyecto

> Un esquema de doble firma que requiere la verificación simultánea de Ed25519 **AND** ML-DSA-65 proporciona garantías de seguridad estrictamente superiores a cualquier esquema individual durante la transición post-cuántica, con un overhead computacional y de ancho de banda que es completamente aceptable para flujos de trabajo de actualización de firmware IoT.

Este proyecto **implementa, demuestra y benchmarkea** dicho esquema. No se limita a la firma: extiende el protocolo con cifrado híbrido en tránsito (X25519 + ML-KEM-768) para proporcionar también **confidencialidad** del firmware durante la transmisión, protegiendo contra escenarios HNDL.

El resultado es un pipeline completo **Sign-then-Encrypt** que:

1. **Firma** el firmware con ambos esquemas (autenticación híbrida).
2. **Cifra** el bundle firmado con un KEM híbrido + AEAD adaptativo (confidencialidad híbrida).
3. **Transmite** el paquete seguro por red TCP.
4. **Descifra** en el receptor.
5. **Verifica** ambas firmas con lógica AND.

Todo esto con código de producción en Python, benchmarks reproducibles sobre 5 tamaños de firmware (1 KB a 10 MB), y validación de red en 3 escenarios (local, LAN, ataque MITM activo).

---

[← Índice](00_indice.md) | [Siguiente: Fundamentos Matemáticos →](02_fundamentos_matematicos.md)
