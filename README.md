# Sistema de Deteccion de Phishing basado en Machine Learning

Sistema de ingenieria de ciberseguridad diseñado para la mitigacion proactiva de amenazas en flujos de correo electronico mediante el protocolo IMAP[cite: 4]. **Hackick** utiliza una arquitectura Sidecar no intrusiva que permite el analisis asincrono de mensajes en tiempo real, garantizando la soberania de los datos y un impacto operativo nulo[cite: 147, 149].

## Introduccion

En la actualidad, el phishing ha evolucionado hacia ataques de precision que utilizan modelos de lenguaje de gran escala (LLM) para generar mensajes altamente personalizados que evaden los mecanismos de deteccion estaticos[cite: 81]. Hackick aborda esta vulnerabilidad mediante un motor de deteccion automatizado que emplea aprendizaje supervisado para identificar caracteristicas estructurales, lexicas y semanticas de correos fraudulentos[cite: 86].

La solucion se fundamenta en una arquitectura Sidecar por copia, la cual opera de forma paralela al flujo principal de entrega de mensajeria sin interferir en la disponibilidad del servicio[cite: 147]. Este enfoque elimina los puntos unicos de falla y las latencias superiores a 200ms asociadas a las arquitecturas de gateway tradicionales[cite: 452, 545].

---

## Diagrama de Flujo

El ciclo de vida del analisis de un correo electronico dentro del sistema sigue una secuencia logica diseñada para la alta disponibilidad y la integridad operativa[cite: 150]:

<img width="768" height="725" alt="flujo" src="https://github.com/user-attachments/assets/24b11da4-aae4-4a3c-bef1-c21c65c69afc" />


1. **Captura:** El motor de red identifica mensajes con el estado `UNSEEN` (No leidos) en el servidor de correo a traves del protocolo IMAP[cite: 253].
2. **Validacion:** Se genera un hash SHA-256 del contenido para verificar si el mensaje ya ha sido procesado previamente, consultando la persistencia local[cite: 257, 259].
3. **Inferencia:** El microservicio analitico en Python procesa el texto y los metadatos, emitiendo un veredicto de riesgo basado en algoritmos Random Forest o SVM[cite: 154].
4. **Inyeccion:** Si se determina que el mensaje es una amenaza, el sistema invoca la logica de re-inyeccion para insertar un banner HTML de advertencia en el cuerpo del correo original[cite: 155].
5. **Registro:** Se actualiza el log de auditoria y la telemetria para su visualizacion en el dashboard de monitoreo[cite: 265, 266].

---

## Arquitectura

El sistema se gestiona mediante el uso de Docker Compose, desplegandose como un ecosistema de microservicios independientes que separa el motor de red, el servicio analitico, la persistencia y la interfaz de usuario[cite: 287, 288].

### Modulos del Sistema

#### 1. Motor de Red e Inyeccion (hackick-go-sidecar)

Modulo desarrollado en Golang seleccionado por su alta eficiencia en el manejo de protocolos de red y capacidad de procesamiento paralelo[cite: 488].

- **Filtrado Selectivo:** Captura únicamente correos no leídos, reduciendo el tráfico de datos en un 70-80%[cite: 253, 254].
- **Operacion No Intrusiva:** La conexión se establece en modo `READ-ONLY`, evitando que el proceso de auditoría altere las banderas del servidor original[cite: 256].
- **Seguridad:** Implementa conexiones cifradas mediante TLS 1.2/1.3 para proteger las credenciales y el contenido en transito[cite: 255].

#### 2. Inteligencia y Entrenamiento (hackick-py-inference)

Constituye el nucleo analitico del sistema, encargado de transformar datos no estructurados en veredictos estadisticos de riesgo[cite: 459].

- **Modelado:** Utiliza Random Forest por su robustez ante ruido y SVM para separacion eficiente en alta dimensionalidad[cite: 235].
- **Procesamiento NLP:** Aplica tecnicas de tokenizacion, eliminacion de stop-words y lematizacion mediante NLTK[cite: 232].
- **Latencia Ultra-baja:** Optimizado para ofrecer respuestas en sub-50ms, evitando que el usuario interactue con el correo antes de la inyeccion de la alerta[cite: 528, 529].

#### 3. Persistencia y Datos (hackick-db-storage)

Utiliza SQLite para garantizar una auditoria tecnica robusta sin la sobrecarga operativa de un servidor de base de datos externo[cite: 268].

- **Idempotencia:** Mediante la indexacion de `message_uid` y `message_hash`, el sistema evita el re-procesamiento de mensajes identicos[cite: 515].
- **Feedback Loop:** Incluye campos para verificacion manual, permitiendo el aprendizaje continuo y la correccion de falsos positivos[cite: 270, 285].

#### 4. Consola de Control (hackick-web-dashboard)

Servicio de observabilidad que expone la telemetria generada en las capas de red y analisis para la toma de decisiones[cite: 521, 522].

- **Heartbeat:** Monitoreo visual del estado de salud de los contenedores Docker[cite: 524].
- **Analitica Dinamica:** Visualizacion en tiempo real de las metricas de Precision, Recall y F1-Score sobre el trafico real[cite: 526, 527].

<img width="1690" height="853" alt="PresentacionCapstone-001" src="https://github.com/user-attachments/assets/2c84e609-3d44-4316-9ffc-785b3a52ed7e" />
MockUp Dashboard

#### 5. Prueba de concepto (POC)

Puede encontrarse en este repositorio dentro del directorio poc/
