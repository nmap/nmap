# NMAP
El repositorio de GitHub que hemos seleccionado es el de NMAP
Nmap es una herramienta de código abierto utilizada en el ámbito de la seguridad informática, su principal funcionalidad es la detección de dispositivos en una red y la identificación de servicios y sistemas operativos que están siendo ejecutados en esos dispositivos, además permite realizar auditorías de seguridad, comprobaciones de puertos abiertos, y análisis de vulnerabilidades. 
La elección de este repositorio para el trabajo en grupo se basa en su relevancia dentro del campo de la ciberseguridad y la administración de redes debido a que nmap ha sido descrito en diversas investigaciones como una de las herramientas más poderosas para la obtención de información sobre redes de manera eficiente (Stallings, 2017). 
También, nmap ha sido objeto de diversos estudios que evidencian su efectividad en la recolección de información precisa de redes complejas (Vacca, 2014). 
Según un estudio realizado por Scarfone et al. (2008), el uso de herramientas de escaneo como nmap puede aumentar en un 20% la eficiencia en la identificación de puertos abiertos en redes complejas permitiendo una detección más rápida de posibles vulnerabilidades. 
Además, según un informe de la National Security Agency (NSA), el uso de nmap en auditorías de seguridad ha demostrado reducir los tiempos de diagnóstico de redes en un 15%, mejorando significativamente la capacidad de respuesta ante posibles amenazas (NSA, 2015).

Nmap (Network Mapper) es una herramienta de código abierto utilizada para la exploración de redes y auditorías de seguridad. Su función principal es realizar escaneos de puertos y detectar servicios activos, lo que permite a los usuarios obtener información sobre los dispositivos conectados, servicios en ejecución y vulnerabilidades potenciales en una red. Es así que Nmap también se utiliza para el mapeo de redes y la identificación de sistemas operativos en los dispositivos detectados.
## Características de Nmap:
Detección de sistemas operativos: Donde emplea técnicas avanzadas de fingerprinting para identificar el sistema operativo y la versión del host objetivo, proporcionando información valiosa para la gestión de redes y la planificación de medidas de seguridad.
Diversidad de métodos de escaneo: Esta herramienta ofrece múltiples técnicas de escaneo, como TCP SYN, UDP, FIN, ACK, que permiten adaptarse a diferentes escenarios y necesidades específicas de evaluación de seguridad.
Automatización con Nmap Scripting Engine (NSE): NSE permite a los usuarios escribir y ejecutar scripts personalizados para automatizar tareas complejas, como la detección de vulnerabilidades específicas y la realización de auditorías de seguridad detalladas. (Haines & Dario, 2003)

"Nmap" herramienta de seguridad de código abierto, la misma que es utilizada para scanear redes y dispositivos para determinar su presencia. Es compatible con sistemas operativos como; Windows, Linux, macOS y Unix. 
Nmap utiliza diferentes técnicas para enviar paquetes a los dispositivos y servidores en una red y analizar las respuestas que recibe. La herramienta puede identificar los servicios y los sistemas operativos que se ejecutan en los dispositivos, así como cualquier firewall o sistema de seguridad que pueda estar protegiendo los dispositivos. 
Tamibién proporciona las direcciones IP, puertos abiertos, las direcciones MAC y otros detalles técnicos de los dispositivos y servidores en la red. Permite evaluar los riesgos potenciales y la seguridad de sus redes, identificar posibles vulnerabilidades y tomar medidas de prevencion sus dispositivos y datos.
En INCEBE   presenta un artículo que indica que es una herramienta ampliamente reconocida en el ámbito de la seguridad informática y la administración de redes. Su popularidad radica en su capacidad para mapear redes y detectar servicios activos en dispositivos conectados. Es importante considerar que desde su creación en 1997, por Gordon Lyon, Nmap ha sido una de las herramientas más confiables para realizar análisis de seguridad, identificar puertos abiertos y servicios disponibles en hosts remotos. A lo largo de los años, la herramienta ha evolucionado y se ha adaptado a las crecientes demandas del campo de la ciberseguridad.

**El motor de scripts de Nmap (NSE)**.- es una de las características más potentes y flexibles de Nmap, que permite ejecutar scripts para la detección de vulnerabilidades, automatización de tareas y explotación básica.

Permite a los usuarios escribir (y compartir) scripts sencillos (utilizando el lenguaje de programación Lua) . ) para automatizar una amplia variedad de tareas de red. Estos scripts se ejecutan en paralelo con la velocidad y eficiencia que se esperan de Nmap. Los usuarios pueden confiar en el creciente y diverso conjunto de scripts distribuidos con Nmap o crear los suyos propios para satisfacer sus necesidades.

Con la opción --script, se pueden utilizar scripts predefinidos en la categoría "vuln" para identificar fallos de seguridad en servicios y sistemas, como nmap --script vuln <IP>. Esto facilita la evaluación de seguridad sin necesidad de herramientas adicionales.

Para reflejar estos diferentes usos y simplificar la elección de los scripts a ejecutar, cada script contiene un campo que lo asocia a una o más categorías. Las categorías definidas actualmente son auth, broadcast, default. discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, y vuln.

Dentro del repositorio de github se pudo encontrar una la rama master una carpeta de nombre "scripts" en el que podemos ver código en python para realizar los siguientes pruebas:
**http-form-brute.nse:** Realiza una auditoría de contraseñas de fuerza bruta contra la autenticación basada en formulario http.
Este script utiliza las bibliotecas unpwdb y brute para adivinar contraseñas. Las aproximaciones correctas se almacenan en el registro de nmap, mediante la biblioteca creds, para que otros scripts las utilicen.
**http-vuln-cve2014-2126.nse:** Detecta si el dispositivo Cisco ASA es vulnerable a la vulnerabilidad de escalada de privilegios ASDM de Cisco ASA.
**iec61850-mms.nse:** Consulta un servidor MMS IEC 61850-8-1. Envía solicitudes de inicio, de identificación y de lectura a LN0 y LPHD.

Por otra parte, el script intenta descubrir automáticamente el método, la acción y los nombres de campo del formulario para adivinar la contraseña. (Use el argumento "path" para especificar la página donde se encuentra el formulario). Si no lo logra, se pueden proporcionar los componentes del formulario mediante los argumentos "method", "path", "uservar" y "passvar". Estos mismos argumentos se pueden usar para anular selectivamente el resultado de la detección.

**Bibliografía**
Vaca, J. R. (2014). The basics of information security: Understanding the fundamentals of InfoSec in theory and practice (2a ed.). Syngress Media.
Stallings, W. (2017). Network security essentials: Applications and standards. Pearson.com. Recuperado el 16 de marzo de 2025, de https://www.pearson.com/en-us/subject-catalog/p/network-security-essentials-applications-and-standards/P200000003333/9780137561650
Scarfone, K. A., Souppaya, M. P., Cody, A., & Orebaugh, A. D. (2008). Technical guide to information security testing and assessment. National Institute of Standards and Technology.
National Security Agency (NSA). (2015). Vulnerability management: Best practices. NSA. Recuperado el 16 de marzo de 2025, de https://www.nsa.gov/
Evolve Academy. (2023). Qué es Nmap y cómo usarlo
https://evolveacademy.es/que-es-nmap-y-como-usarlo-guia-completa-con-ejemplos
Haines, J., Ryder, D.K., Tinnel, L., & Taylor, S. (2003). Validation of sensor alert correlators. IEEE Security & Privacy. Recuperado de
https://ieeexplore.ieee.org/document/1186740
https://nmap.org/book/
https://aprende.academia-ciberseguridad.com/books/herramientas/page/nmap-network-mapper
https://www.incibe.es/tags/Pentesting
https://nmap.org/book/man-nse.html



