# 02 — Fundamentos Matemáticos

[← Introducción](01_introduccion.md) | [Índice](00_indice.md) | [Siguiente: Arquitectura del Protocolo →](03_arquitectura_protocolo.md)

---

Este documento describe las matemáticas subyacentes a cada primitivo criptográfico utilizado en el protocolo. Se presenta cada algoritmo con su estructura algebraica, las operaciones involucradas, los tamaños de clave/firma, y la fuente de seguridad.

---

## 1. Ed25519 — Firma Digital Clásica (RFC 8032)

### 1.1 La Curva

Ed25519 opera sobre la **curva de Edwards torcida** (twisted Edwards curve):

$$-x^2 + y^2 = 1 + d \cdot x^2 \cdot y^2$$

donde:

- El campo base es $\mathbb{F}_p$ con $p = 2^{255} - 19$ (un primo de Mersenne generalizado elegido por eficiencia).
- La constante $d = -121665/121666 \pmod{p}$.

Esta curva es birracionalmente equivalente a la curva de Montgomery **Curve25519** ($y^2 = x^3 + 486662x^2 + x$), lo que permite compartir el mismo campo base para firma (Ed25519) e intercambio de clave (X25519).

### 1.2 Estructura del Grupo

Los puntos racionales de la curva sobre $\mathbb{F}_p$ forman un grupo abeliano bajo la ley de adición de Edwards. El grupo tiene orden $E = 8 $\ell$, donde:

$$\ell = 2^{252} + 27742317777372353535851937790883648493$$

es primo. Las operaciones criptográficas se realizan en el **subgrupo de orden primo** $\ell$, generado por un punto base $B$ fijo definido en el estándar.

El **cofactor** $h = 8$ significa que hay 8 puntos de torsión pequeña. La verificación con cofactor ($[8S]B = [8]R + [8H]A$) previene ataques de subgrupo pequeño.

### 1.3 Generación de Claves

1. Se muestrea una semilla aleatoria: $sk \xleftarrow{} 0,1^{256}$ (32 bytes de entropía).
2. Se calcula $H(sk)$ usando SHA-512, produciendo 64 bytes.
3. Los 32 bytes inferiores $H_{lo}(sk)$ se someten a **clamping**: se fuerzan ciertos bits para asegurar que el escalar resultante esté en el subgrupo correcto y tenga propiedades de seguridad constante.
4. El escalar resultante $s$ define la clave pública: $A = [s]B$.


| Elemento                         | Tamaño   |
| -------------------------------- | -------- |
| Clave privada (semilla)          | 32 bytes |
| Clave pública (punto comprimido) | 32 bytes |


### 1.4 Firma

Dado un mensaje $M$ (en nuestro caso, el digest SHA3-256 del firmware):

1. **Nonce determinístico**: $r = H(H_{hi}(sk)  M) \pmod{\ell}$, donde $H_{hi}(sk)$ son los 32 bytes superiores de $H(sk)$. El nonce es determinístico — no depende de un generador de números aleatorios en el momento de firmar, previniendo ataques por nonces débiles o repetidos.
2. **Punto de compromiso**: $R = [r]B$
3. **Desafío**: $e = H(R  A  M) \pmod{\ell}$
4. **Respuesta**: $S = r + e \cdot s \pmod{\ell}$

La firma es el par $(R, S)$ codificado en **64 bytes** (32 para $R$ comprimido + 32 para $S$).

### 1.5 Verificación

El verificador acepta si y solo si:

$$[8S]B = [8]R + [8 \cdot H(R  A  M)]A$$

La verificación es correcta porque:
$$[8S]B = [8(r + eS)]B = [8r]B + [8es]B = [8]R + [8e]A$$

### 1.6 Seguridad

La seguridad de Ed25519 se reduce al **Problema del Logaritmo Discreto sobre Curvas Elípticas** (ECDLP): dado $A = [s]B$, encontrar $s$.

- **Nivel de seguridad clásico**: 128 bits (el mejor ataque conocido, Pollard's rho, requiere $O(\sqrt{\ell}) \approx 2^{126}$ operaciones).
- **Vulnerabilidad cuántica**: el algoritmo de Shor resuelve el ECDLP en tiempo polinómico $O(\log^3 \ell)$ en un CRQC con $\approx 2500$ qubits lógicos para una curva de 256 bits.

---

## 2. ML-DSA-65 — Firma Digital Post-Cuántica (FIPS 204)

### 2.1 Estructura Algebraica

ML-DSA (Module-Lattice Digital Signature Algorithm, anteriormente conocido como CRYSTALS-Dilithium) opera sobre el **anillo de polinomios**:

$$R_q = \mathbb{Z}_q[X] / (X^{256} + 1)$$

donde $q = 8380417$. Cada elemento de $R_q$ es un polinomio de grado a lo sumo 255 con coeficientes en $0, 1, \ldots, q-1$.

El polinomio ciclotómico $X^{256} + 1$ se elige porque:

- Factoriza completamente sobre $\mathbb{Z}_q$ (permitiendo NTT — Number Theoretic Transform — para multiplicación eficiente en $O(n \log n)$).
- La estructura de módulo ($R_q^{k \times \ell}$) proporciona seguridad bajo los problemas Module-LWE y Module-SIS.

### 2.2 Problemas de Seguridad Subyacentes

**Module-LWE (Learning With Errors)**: dado $(\mathbf{A}, \mathbf{b} = \mathbf{A}\mathbf{s} + \mathbf{e})$ donde $\mathbf{A} \in R_q^{k \times \ell}$ es pública, $\mathbf{s} \in R_q^\ell$ es secreta con coeficientes pequeños, y $\mathbf{e} \in R_q^k$ es un vector de error pequeño, distinguir $\mathbf{b}$ de un vector aleatorio uniforme es computacionalmente difícil.

**Module-SIS (Short Integer Solution)**: dado $\mathbf{A}$, encontrar un vector corto $\mathbf{z}$ tal que $\mathbf{A}\mathbf{z} = \mathbf{0} \pmod{q}$ es difícil.

Ambos problemas se consideran **resistentes a ataques cuánticos**: no se conoce un algoritmo cuántico eficiente que los resuelva, en contraste con el ECDLP (Shor) o la factorización (Shor).

### 2.3 Parámetros ML-DSA-65


| Parámetro  | Valor                   | Significado                           |
| ---------- | ----------------------- | ------------------------------------- |
| $q$        | $8380417$               | Módulo del anillo                     |
| $k$        | $6$                     | Dimensión de filas del módulo         |
| $\ell$     | $5$                     | Dimensión de columnas del módulo      |
| $\eta$     | $4$                     | Cota de coeficientes del secreto      |
| $\gamma_1$ | $2^{19}$                | Cota del vector de enmascaramiento    |
| $\gamma_2$ | $(q-1)/32$              | Precisión del redondeo                |
| $\tau$     | $49$                    | Peso de Hamming del desafío           |
| $\beta$    | $\tau \cdot \eta = 196$ | Cota de la norma infinito de la firma |
| Nivel NIST | 3                       | Equivalente a AES-192                 |


### 2.4 Generación de Claves

1. Se muestrea una semilla $\rho \xleftarrow{} 0,1^{256}$ y se expande para generar la matriz pública $\mathbf{A} \in R_q^{k \times \ell}$.
2. Se generan vectores secretos $\mathbf{s}_1 \in R_q^\ell$ y $\mathbf{s}_2 \in R_q^k$ con coeficientes en $[-\eta, \eta]$.
3. Se calcula $\mathbf{t} = \mathbf{A}\mathbf{s}_1 + \mathbf{s}_2$.
4. La clave pública es $pk = (\rho, \mathbf{t})$; la clave secreta es $sk = (\rho, K, \text{tr}, \mathbf{s}_1, \mathbf{s}_2, \mathbf{t}_0)$.


| Elemento      | Tamaño      |
| ------------- | ----------- |
| Clave pública | 1,952 bytes |
| Clave secreta | 4,032 bytes |


### 2.5 Firma (Fiat-Shamir con Abortos)

El proceso de firma utiliza la transformación **Fiat-Shamir con abortos** (rejection sampling), lo que garantiza que la firma no filtre información sobre la clave secreta:

1. Se muestrea un vector de enmascaramiento $\mathbf{y} \xleftarrow{} S_{\gamma_1}^\ell$ (coeficientes uniformes en $[-\gamma_1 + 1, \gamma_1]$).
2. Se calcula $\mathbf{w} = \mathbf{A}\mathbf{y}$ y se extrae la parte alta $\mathbf{w}_1 = \text{HighBits}(\mathbf{w})$.
3. Se calcula el desafío $c = H(\text{tr}  \mathbf{w}_1  M)$ como un polinomio en $R_q$ con exactamente $\tau$ coeficientes $\pm 1$ y el resto 0.
4. Se calcula $\mathbf{z} = \mathbf{y} + c \cdot \mathbf{s}_1$.
5. **Rejection sampling**: si $\mathbf{z}*\infty \geq \gamma_1 - \beta$ o si $\text{LowBits}(\mathbf{A}\mathbf{z} - c\mathbf{t})*\infty \geq \gamma_2 - \beta$, se **aborta y reinicia** desde el paso 1. Esto es crucial: sin rejection sampling, un observador podría extraer información sobre $\mathbf{s}_1$ a partir de múltiples firmas.

La firma resultante es $\sigma = (\tilde{c}, \mathbf{z}, \mathbf{h})$ donde $\mathbf{h}$ son los hints para reconstruir $\mathbf{w}_1$.


| Elemento | Tamaño      |
| -------- | ----------- |
| Firma    | 3,309 bytes |


### 2.6 Verificación

1. Recalcular $\mathbf{w}_1' = \text{UseHint}(\mathbf{h}, \mathbf{A}\mathbf{z} - c\mathbf{t})$.
2. Verificar que $c = H(\text{tr}  \mathbf{w}_1'  M)$.
3. Verificar que $\mathbf{z}_\infty < \gamma_1 - \beta$.

### 2.7 Seguridad

- **NIST Nivel 3**: seguridad equivalente a AES-192, es decir, ~143 bits de seguridad cuántica.
- **Resistente a Shor**: los problemas Module-LWE/SIS sobre reticulados no se ven afectados por los algoritmos cuánticos conocidos.
- El mejor ataque cuántico conocido (algoritmo BKZ con oracle cuántico de Grover) ofrece solo una mejora cuadrática sobre la enumeración clásica, lo que no compromete los parámetros seleccionados.

---

## 3. SHA3-256 — Función Hash (FIPS 202)

### 3.1 Construcción Esponja (Sponge)

SHA3-256 se basa en la función **Keccak** con una construcción de esponja:

- **Estado interno**: 1600 bits organizados como una matriz $5 \times 5 \times 64$.
- **Rate** $r = 1088$ bits: la porción del estado que absorbe/emite datos.
- **Capacity** $c = 512$ bits: la porción del estado que proporciona seguridad (nunca se expone directamente).

La relación es $r + c = 1600$ y el nivel de seguridad es $c/2 = 256$ bits contra preimagen, $c/2 = 256$ contra segunda preimagen, y $\min(c/2, n/2) = 128$ contra colisión (donde $n = 256$ es la longitud del hash).

### 3.2 La Permutación Keccak-f[1600]

La permutación aplica **24 rondas**, cada una compuesta por 5 operaciones:


| Paso     | Operación                                  | Efecto                                    |
| -------- | ------------------------------------------ | ----------------------------------------- |
| $\theta$ | XOR columnar + rotación                    | Difusión lineal entre columnas            |
| $\rho$   | Rotación de bits por carril                | Difusión intra-carril                     |
| $\pi$    | Permutación de posiciones                  | Mezcla inter-carril                       |
| $\chi$   | Transformación no lineal (AND + NOT + XOR) | Confusión (única fuente de no linealidad) |
| $\iota$  | XOR con constante de ronda                 | Rompe simetría entre rondas               |


### 3.3 Propiedades de Seguridad


| Propiedad                       | Complejidad |
| ------------------------------- | ----------- |
| Resistencia a preimagen         | $2^{256}$   |
| Resistencia a segunda preimagen | $2^{256}$   |
| Resistencia a colisión          | $2^{128}$   |


### 3.4 Uso en Este Protocolo

En este proyecto, SHA3-256 se utiliza para:

1. **Hash del firmware**: $\text{digest} = \text{SHA3-256}(F)$ — produce el digest de 32 bytes sobre el cual se calculan ambas firmas.
2. **AAD del cifrado**: $\text{AAD} = \text{SHA3-256}(\text{ephpk}  \text{mlkemct}  \text{cipherid})$ — vincula los parámetros KEM al cifrado AEAD.

La elección de SHA3 sobre SHA2 es deliberada: es consistente con la familia hash interna de ML-DSA (que usa SHAKE, una extensión de Keccak) y proporciona resistencia cuántica para colisiones ($2^{128}$ con Grover, frente a $2^{85}$ de SHA-256 con BHT).

---

## 4. X25519 — Intercambio de Clave Clásico (RFC 7748)

### 4.1 Diffie-Hellman sobre Curve25519

X25519 implementa ECDH (Elliptic Curve Diffie-Hellman) sobre la curva de Montgomery:

$$y^2 = x^3 + 486662x^2 + x \pmod{p}, \quad p = 2^{255} - 19$$

La operación es una **multiplicación escalar de solo coordenada-x** (la "escalera de Montgomery"), lo que la hace eficiente y de tiempo constante.

### 4.2 Protocolo

Dados dos participantes Alice y Bob:

1. Alice genera $sk_A \xleftarrow{} 0,1^{256}$, calcula $pk_A = X25519(sk_A, 9)$ donde $9$ es la coordenada-x del punto base.
2. Bob genera $(sk_B, pk_B)$ análogamente.
3. Shared secret: $ss = X25519(sk_A, pk_B) = X25519(sk_B, pk_A)$.

La igualdad se cumple por conmutatividad: $[sk_A][sk_B]G = [sk_B][sk_A]G$.

### 4.3 Uso en Este Protocolo

En nuestro KEM híbrido, X25519 se usa en modo **efímero-estático**: el emisor genera un par efímero $(ek, ek_{pub})$ y realiza ECDH contra la clave pública estática del receptor:

$$ss_{x25519} = X25519(ek, pk_{receptor})$$

El emisor incluye $ek_{pub}$ en el paquete para que el receptor pueda calcular el mismo shared secret.


| Elemento      | Tamaño   |
| ------------- | -------- |
| Clave pública | 32 bytes |
| Clave privada | 32 bytes |
| Shared secret | 32 bytes |


**Vulnerabilidad cuántica**: como Ed25519, X25519 se basa en ECDLP y es vulnerable a Shor. Por eso se complementa con ML-KEM-768.

---

## 5. ML-KEM-768 — Mecanismo de Encapsulación de Clave Post-Cuántico (FIPS 203)

### 5.1 Estructura

ML-KEM (Module-Lattice Key Encapsulation Mechanism, anteriormente CRYSTALS-Kyber) es un KEM basado en el problema **Module-LWE**, análogo al problema subyacente en ML-DSA pero con parámetros optimizados para encapsulación de clave.

Opera sobre el anillo $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$ con $q = 3329$ y dimensión de módulo $k = 3$.

### 5.2 Parámetros ML-KEM-768


| Parámetro  | Valor  |
| ---------- | ------ |
| $q$        | $3329$ |
| $k$        | $3$    |
| $\eta_1$   | $2$    |
| $\eta_2$   | $2$    |
| $d_u$      | $10$   |
| $d_v$      | $4$    |
| Nivel NIST | 3      |


### 5.3 Operaciones

**KeyGen**:

1. Generar matriz $\mathbf{A} \in R_q^{k \times k}$ de una semilla pública.
2. Muestrear secretos $\mathbf{s}, \mathbf{e}$ con coeficientes pequeños.
3. $pk = (\mathbf{A}, \mathbf{t} = \mathbf{A}\mathbf{s} + \mathbf{e})$, $sk = \mathbf{s}$.

**Encapsulación** (Encaps):

1. Muestrear $\mathbf{r}, \mathbf{e}_1, e_2$ efímeros.
2. $\mathbf{u} = \mathbf{A}^T\mathbf{r} + \mathbf{e}_1$
3. $v = \mathbf{t}^T\mathbf{r} + e_2 + \lceil q/2 \rfloor \cdot m$ donde $m$ es un mensaje interno aleatorio.
4. Ciphertext $ct = (\text{Compress}(\mathbf{u}), \text{Compress}(v))$.
5. Shared secret $K = H(m  H(ct))$.

**Decapsulación** (Decaps):

1. Recuperar $m' = \text{Decompress}(v) - \mathbf{s}^T\text{Decompress}(\mathbf{u})$, redondeando.
2. Re-encapsular con $m'$ y verificar que produce el mismo $ct$.
3. Si coincide: $K = H(m'  H(ct))$. Si no: $K = H(z  H(ct))$ con $z$ secreto (protección contra oráculos de decapsulación — transformación FO).


| Elemento      | Tamaño      |
| ------------- | ----------- |
| Clave pública | 1,184 bytes |
| Clave secreta | 2,400 bytes |
| Ciphertext    | 1,088 bytes |
| Shared secret | 32 bytes    |


### 5.4 Seguridad

- **NIST Nivel 3**: resistente a ataques cuánticos.
- La transformación Fujisaki-Okamoto (FO) convierte el esquema CPA-seguro en **IND-CCA2** (seguridad contra ataques de ciphertext elegido adaptativo).

---

## 6. HKDF-SHA3-256 — Derivación de Clave (RFC 5869 adaptado)

### 6.1 Propósito

En nuestro KEM híbrido, obtenemos **dos** shared secrets independientes:

- $ss_{x25519}$: 32 bytes del ECDH clásico.
- $ss_{mlkem}$: 32 bytes del KEM post-cuántico.

Necesitamos combinarlos en una **única clave simétrica** de 256 bits. HKDF (HMAC-based Key Derivation Function) es el mecanismo estándar para esto.

### 6.2 Construcción Extract-then-Expand

$$\text{PRK} = \text{HMAC-SHA3-256}(\text{salt}, \text{IKM})$$
$$K = \text{HKDF-Expand}(\text{PRK}, \text{info}, L)$$

En nuestra implementación:

- $\text{IKM} = ss_{x25519}  ss_{mlkem}$ (64 bytes concatenados).
- $\text{salt} = \text{None}$ (se usa un salt de ceros implícito).
- $\text{info} = \texttt{"hybrid-firmware-kem-v1"}$ (contexto que vincula la derivación a este protocolo específico).
- $L = 32$ (longitud de la clave derivada en bytes).

### 6.3 Propiedad Clave

La clave derivada $K$ es **computacionalmente indistinguible de una clave aleatoria** mientras al menos uno de los dos shared secrets sea indistinguible de aleatorio. Esto refleja la robustez transicional del esquema: si X25519 es comprometido pero ML-KEM no (o viceversa), $K$ sigue siendo seguro.

---

## 7. Cifrado Autenticado (AEAD) — Adaptativo

### 7.1 ChaCha20-Poly1305 (RFC 8439)

**ChaCha20** es un cifrado de flujo (stream cipher):

- Estado interno de 512 bits: constante (128) + clave (256) + contador (32) + nonce (96).
- 20 rondas de operaciones ARX (Add-Rotate-XOR) sobre el estado.
- Genera un keystream que se XORea con el plaintext.

**Poly1305** es un MAC (Message Authentication Code):

- Evaluación polinomial sobre $\mathbb{F}_{2^{130}-5}$.
- One-time MAC: genera un tag de 128 bits (16 bytes) que es unforgeable bajo la clave derivada.

La combinación AEAD proporciona **confidencialidad + autenticidad** en una sola operación.


| Parámetro            | Valor               |
| -------------------- | ------------------- |
| Clave                | 256 bits            |
| Nonce                | 96 bits (12 bytes)  |
| Tag de autenticación | 128 bits (16 bytes) |


### 7.2 AES-256-GCM (NIST SP 800-38D)

**AES-256** es un cifrado de bloque con bloques de 128 bits y clave de 256 bits, usado en modo CTR (Counter).

**GCM (Galois/Counter Mode)** proporciona AEAD:

- Cifrado: AES-CTR con nonce de 96 bits.
- Autenticación: multiplicación en $GF(2^{128})$ (GHASH).
- Tag de 128 bits.

En procesadores modernos con instrucciones **AES-NI** y **CLMUL**, AES-256-GCM es significativamente más rápido que ChaCha20-Poly1305 para payloads grandes. Sin AES-NI (dispositivos embebidos), ChaCha20 suele ser más eficiente.

### 7.3 Selección Adaptativa

El protocolo selecciona el cifrado según el tamaño del payload:

$$\text{cipher} = \begin{cases} \text{ChaCha20-Poly1305} & \text{si } |\text{payload}| < 100\text{ KB}  \text{AES-256-GCM} & \text{si } |\text{payload}| \geq 100\text{ KB} \end{cases}$$

La lógica es: para payloads pequeños, el overhead fijo de inicialización de AES-GCM es proporcionalmente mayor, y ChaCha20 es más eficiente en software puro. Para payloads grandes, AES-NI hardware domina y AES-GCM logra mayor throughput.

---

## 8. Resumen de Primitivos y Sus Propiedades


| Primitivo     | Base Matemática        | Nivel de Seguridad               | Resistente a Shor              | Tamaño Clave Pública | Tamaño Firma/CT       |
| ------------- | ---------------------- | -------------------------------- | ------------------------------ | -------------------- | --------------------- |
| Ed25519       | ECDLP sobre Curve25519 | 128 bits clásicos                | **No**                         | 32 B                 | 64 B (firma)          |
| ML-DSA-65     | Module-SIS/LWE         | NIST L3 (~143 bits cuánticos)    | **Sí**                         | 1,952 B              | 3,309 B (firma)       |
| SHA3-256      | Esponja Keccak         | 256 bits preimagen, 128 colisión | **Parcial** (Grover $\sqrt{}$) | —                    | 32 B (hash)           |
| X25519        | ECDLP sobre Curve25519 | 128 bits clásicos                | **No**                         | 32 B                 | 32 B (shared secret)  |
| ML-KEM-768    | Module-LWE             | NIST L3                          | **Sí**                         | 1,184 B              | 1,088 B (ciphertext)  |
| HKDF-SHA3-256 | HMAC + esponja         | 256 bits                         | **Sí**                         | —                    | 32 B (clave derivada) |


---

[← Introducción](01_introduccion.md) | [Índice](00_indice.md) | [Siguiente: Arquitectura del Protocolo →](03_arquitectura_protocolo.md)