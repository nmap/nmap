
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

'SELECT * FROM products WHERE category = 'Gifts' AND released = 1--
Para resolver el laboratorio, realice un ataque de inyección SQL que haga que la aplicación muestre uno o más productos no lanzados.
Ingresamos al portal y damos click en IR AL LABORATORIO, donde se nos despliega la página donde vamos a trabajar, procedemos a escoger la categoría Gifts con el objetivo de que el BURN capture el tráfico que esta página genera.

Una vez capturado el tráfico procedemos a ingresar la solución que el mismo reto nos da:
* Utilice Burp Suite para interceptar y modificar la solicitud que establece el filtro de categoría de producto.
* Determine el número de columnas que devuelve la consulta y cuáles contienen datos de texto. Verifique que la consulta devuelva dos columnas, ambas con texto, utilizando una carga útil como la siguiente en el category parámetro:
'+UNION+SELECT+'abc','def'#
* Utilice la siguiente carga útil para mostrar la versión de la base de datos:
'+UNION+SELECT+@@version,+NULL#
Para poder trabajar con las dos sentenciar primero en el área de REQUEST colocamos el cursor en algún lugar de este sitio y damos click derecho y escogemos la opción que die: SEND TO REPEATER y se nos abre una ventana RESPONSE, nos dirigimos al menú a la opción REPEATER.



