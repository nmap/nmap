# Nmap - Escáner de Redes y Puertos  

## Descripción  
Nmap (Network Mapper) es una herramienta de código abierto utilizada para el escaneo de redes y puertos. Permite descubrir hosts, servicios y sistemas operativos en una red, facilitando tareas de ciberseguridad y administración.  

## Justificación  
Elegimos este repositorio porque Nmap es una de las herramientas más utilizadas en ciberseguridad. Su importancia está respaldada por múltiples estudios y comunidades de expertos en seguridad.  
* Referencia 1: [Artículo sobre Nmap](https://nmap.org/book/)  


Nuestro grupo trabajará en analizar su código y explorar sus funcionalidades.  

## VENTAJAS Y LIMITACIONES
## VENTAJAS

* Gratuito y de Código Abierto: Cualquiera puede usarlo y modificarlo.
* Extensible: Gracias al NSE, se pueden agregar funcionalidades personalizadas.
* Multiplataforma: Funciona en la mayoría de los sistemas operativos.
* Documentación Completa: Cuenta con una amplia documentación y soporte comunitario.

##  LIMITACIONES

* Curva de Aprendiza Eje: Puede ser complejo para usuarios principiantes.
* Falsos Positivos: En algunos casos, puede generar resultados incorrectos.
* Impacto en la Red: Escaneos intensivos pueden afectar el rendimiento de la red.

## FUENTES

[Hackertarget](https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/) /
[Book](https://nmap.org/book/) /
[Nmap](https://nmap.org/book/man-examples.html) /
[NMAP](https://www.udemy.com/courses/search/?src=ukwq=curso+de+Nmap) /
[Security](https://securitytrails.com/blog/nmap-commands)

***
## RETO SQL-INJECTION
***
## SQL-INJECTION
## All labs
## Mystery lab challenge

Try solving a random lab with the title and description hidden. As you'll have no prior knowledge of the type of vulnerability that you need to find and exploit, this is great for practicing recon and analysis.

Take me to the mystery lab challenge.

## SQL injection
# LAB 3
PRACTITIONER SQL injection attack, querying the database type and version on Oracle
Not solved

Para realizar el Reto De SQL-INYECTION primero abrimos el Burp Suite Community Edition, luego desde el Burp lanzamos el navegador e ingresamos a https://portswigger.net/web-security/all-labs y escogemos el reto. 
***
# SQL- INYECCIÓN
## Todos los laboratorios
## Desafío de laboratorio misterioso

Intenta resolver un laboratorio aleatorio con el título y la descripción ocultos. Como no tendrás conocimientos previos sobre el tipo de vulnerabilidad que necesitas encontrar y explotar, esto es ideal para practicar el reconocimiento y el análisis.

Llévame al desafío del laboratorio misterioso

## Inyección SQL
## LABORATORIO Nº 3

FACULTATIVO Ataque de inyección SQL, consultando el tipo y la versión de la base de datos en Oracle

## LABORATORIO Resuelto

Este laboratorio presenta una vulnerabilidad de inyección SQL en el filtro de categorías de productos. Se puede usar un ataque UNION para recuperar los resultados de una consulta inyectada.
Para resolver el laboratorio, muestre la cadena de versión de la base de datos.
Ingresamos al portal y damos click en IR AL LABORATORIO, donde se nos despliega la página donde vamos a trabajar, procedemos a escoger la categoría Gifts con el objetivo de que el BURN capture el tráfico que esta página genera.

![Image](https://github.com/user-attachments/assets/afea2fcf-4a73-4f0c-bfbc-ab6bfb271e2b)
 
Una vez capturado el tráfico procedemos a ingresar la solución que el mismo reto nos da:

* Utilice Burp Suite para interceptar y modificar la solicitud que establece el filtro de categoría de producto.
*	Determine el número de columnas que devuelve la consulta y cuáles contienen datos de texto. Verifique que la consulta devuelva dos columnas, ambas con texto, utilizando una carga útil como la siguiente en el category parámetro: '+UNION+SELECT+'abc','def'+FROM+dual--
*	Utilice la siguiente carga útil para mostrar la versión de la base de datos:
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--

Para poder trabajar con las dos sentenciar primero en el área de REQUEST colocamos el cursor en algún lugar de este sitio y damos click derecho y escogemos la opción que die: SEND TO REPEATER y se nos abre una ventana RESPONSE, nos dirigimos al menú a la opción REPEATER.

 ![Image](https://github.com/user-attachments/assets/a03a25fe-21a4-4162-8fcb-b486d369373e)


 ![Image](https://github.com/user-attachments/assets/4f2d5423-9503-48af-b402-c4a77e5b55d1)

 
Una vez dentro de la opción REPETEAR vamos al código e ingresamos la solución:
Solución 1

![Image](https://github.com/user-attachments/assets/5ab3a675-8329-49b3-9d9a-e998bfbb560a)
 
Procedemos a dar clcik en SEND para que se actualice los registros
Solución 2

![Image](https://github.com/user-attachments/assets/c02f8903-bd9c-4ed2-a0a0-cda0825c5abe)
 
Procedemos a dar clcik en SEND para que se actualice los registros.

## Verificamos que surta efecto los scripts ingresados.

![Image](https://github.com/user-attachments/assets/908bd9b4-a4f2-4dd7-a5f4-fb0cd1c79153)

![Image](https://github.com/user-attachments/assets/f95bb931-b268-46a4-9041-fddd6dac4470)

# RETO CUMPLIDO
 ***
 





