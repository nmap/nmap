# Nmap - Escáner de Redes y Puertos  

## Descripción  
Nmap (Network Mapper) es una herramienta de código abierto utilizada para el escaneo de redes y puertos. Permite descubrir hosts, servicios y sistemas operativos en una red, facilitando tareas de ciberseguridad y administración.  

## Justificación  
Elegimos este repositorio porque Nmap es una de las herramientas más utilizadas en ciberseguridad. Su importancia está respaldada por múltiples estudios y comunidades de expertos en seguridad.  
- Referencia 1: [Artículo sobre Nmap](https://nmap.org/book/)  


Nuestro grupo trabajará en analizar su código y explorar sus funcionalidades.  

***
## FUNCIONES
Nmap es una herramienta versátil que se utiliza en diversas situaciones, entre las
que destacan:
* Descubrimiento de Redes
* Escaneo de puertos
* Auditoría de seguridad
* Inventario de Red
* Pentesting
* Monitoreo de Red
## CARACTERÍSTICAS
* Escaneo de Puertos: Soporta múltiples técnicas de escaneo (TCP, UDP, SYN,
ACK, etc.).
* Detección de Sistemas Operativos: Utiliza técnicas de "fingerprinting"para
* Identificar el sistema operativo de un dispositivo.
* Compatibilidad Multiplataforma: Funciona en Windows, Linux, macOS y otros
sistemas operativos.
***
## LABORATORIO Nº 4
FACULTATIVO Ataque de inyección SQL, consultando el tipo y la versión de la base de datos MySQL y Microsoft
## LABORATORIO Resuelto
Este laboratorio presenta una vulnerabilidad de inyección SQL en el filtro de categorías de productos. Cuando el usuario selecciona una categoría, la aplicación ejecuta una consulta SQL como la siguiente:
'SELECT * FROM products WHERE category = 'Gifts' AND released = 1--'
Para resolver el laboratorio, realice un ataque de inyección SQL que haga que la aplicación muestre uno o más productos no lanzados.
Ingresamos al portal y damos click en IR AL LABORATORIO, donde se nos despliega la página donde vamos a trabajar, procedemos a escoger la categoría Gifts con el objetivo de que el BURN capture el tráfico que esta página genera.

