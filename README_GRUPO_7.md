# Nmap Overview


```
NMAP funciona para realizar escaneo en todas las redes, su propósito principal es encontrar puertos abiertos y vulnerabilidades, además que posee este tipo de escaneos SYN, TCP, UDP, y SCTP para detectar servicios abiertos en un sistema objetivo.
```

Además, se puede optar por poner velocidad a nmap con la opción `-T5`.

### 🔍 ¿Para qué se usa?
- Identificar dispositivos conectados a una red.
- Detectar puertos abiertos y servicios que están corriendo.
- Determinar versiones de software y sistemas operativos.
- Realizar pruebas de seguridad y detección de vulnerabilidades.

### JUSTIFICACIÓN
El escaneo de redes, ya sea en entornos domésticos o a nivel empresarial, siempre revela puertos abiertos, latencia en la red o incluso vulnerabilidades. En este sentido, es fundamental que el profesional en redes sepa comprender y actuar de manera adecuada para analizar dicha red. Una de las herramientas más antiguas y populares es Nmap, cuyo uso se ha extendido ampliamente en retos de CTF, pentesting y análisis de redes.

Por ejemplo, la empresa CompTIA menciona que: Nmap suele considerarse una herramienta de ciberseguridad, aunque no debe subestimarse su utilidad para la resolución de problemas. Los profesionales y administradores de seguridad utilizan Nmap para diversas tareas. (Garn, 2024)

Además de la cita de arriba tomada de la empresa reconocida como COMPTIA, existe otra empresa como Red Hat que nos brinda información de lo siguiente:

Nmap (Network Mapper) es conocido popularmente como la navaja suiza del administrador de sistemas. Dado que las cosas en una red corporativa no funcionan tan bien como se desea, esos tickets de depuración o de "Guardar" pueden acumularse en el registro de trabajo. (Nandishwar, 2019)

## Aspecto | Descripción
--- | ---
**Nombre** | Nmap (Network Mapper)
**Funcionalidad principal** | Nmap es una herramienta de código abierto utilizada para el escaneo y mapeo de redes. Permite a los profesionales de la seguridad informática identificar dispositivos activos en una red, descubrir puertos abiertos y detectar servicios en ejecución, así como posibles vulnerabilidades.
**Características destacadas** | - Detección de hosts activos: Identifica qué dispositivos están conectados a la red.  
- Escaneo de puertos: Determina qué puertos están abiertos en un host específico.  
- Detección de servicios: Identifica servicios y versiones de software que se ejecutan en puertos abiertos.  
- Detección de sistemas operativos: Estima el sistema operativo y su versión en dispositivos remotos.  
- Scripting Engine (NSE): Permite la ejecución de scripts personalizados para realizar tareas específicas, como la detección de vulnerabilidades conocidas.
**Aplicaciones comunes** | - Seguridad informática: Evaluación de la seguridad de redes y sistemas mediante la identificación de posibles puntos débiles.  
- Administración de redes: Inventario de dispositivos y servicios en una red para su gestión eficiente.  
- Auditorías de cumplimiento: Verificación de configuraciones y políticas de seguridad en entornos corporativos.

Fuente: La información proporcionada en este resumen se basa en el enlace de ScienceDirect sobre la herramienta Nmap.

Nmap no solo es una herramienta de escaneo y mapeo de redes ampliamente reconocida, sino que también ofrece la posibilidad de expandir sus funcionalidades a través de la creación y personalización de scripts. La función NSE de la herramienta Nmap es una potente función que permite a los usuarios automatizar diversas tareas relacionadas con la red. La herramienta incluye una amplia biblioteca de scripts preinstalados, que pueden modificarse para satisfacer las necesidades. (Yashvant Mahadev, 2023, p. 1180)

Gracias a su motor de secuencias de comandos (NSE, por sus siglas en inglés), los usuarios pueden desarrollar scripts propios para automatizar tareas específicas, como la detección de vulnerabilidades, la identificación de servicios ocultos o el análisis profundo de la seguridad en la red.

Nmap, abreviatura de "Network Mapper", es una herramienta de código abierto utilizada para la exploración de redes y auditorías de seguridad. Permite a los administradores de red identificar dispositivos activos en una red, descubrir puertos y servicios abiertos, y detectar vulnerabilidades. Nmap puede adaptarse a las condiciones de la red, incluyendo latencia y congestión, durante un escaneo. ("Nmap: the Network Mapper", s.f.)

## Bibliografía
- Garn, D. (2024, Marzo 6). Blog: Comptia. comptia.org Web site: https://www.comptia.org/blog/what-is-nmap
- Liao, S., Zhou, C., Zhao, Y., & Zhang, Z. (2020). A Comprehensive Detection Approach of Nmap: Principles, Rules and Experiments. International Conference on Cyber-Enabled Distributed Computing and Knowledge Discovery. https://doi.org/10.1109/CyberC49757.2020.00020
- Nandishwar, S. (2019, Agosto 19). RedHat Blog. redhat.com Web site: https://www.redhat.com/en/blog/use-cases-nmap
- Yashvant Mahadev, H. (2023). A Review on Nmap and Its Features. International Research Journal of Engineering and Technology, 10(05 | May 2023), 1176-1180.
- Nmap: the Network Mapper - Free Security Scanner. (s.f.). Nmap. https://nmap.org/



