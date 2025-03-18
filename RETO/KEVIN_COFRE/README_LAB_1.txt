APRENDIZ Vulnerabilidad de inyección SQL en la cláusula WHERE que permite la recuperación de datos ocultos

Laboratorio: Vulnerabilidad de inyección SQL en la cláusula WHERE que permite la recuperación de datos ocultos
APRENDIZ

Este laboratorio presenta una vulnerabilidad de inyección SQL en el filtro de categorías de productos. Cuando el usuario selecciona una categoría, la aplicación ejecuta una consulta SQL como la siguiente:
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
Para resolver el laboratorio, realice un ataque de inyección SQL que haga que la aplicación muestre uno o más productos no lanzados.

Ingresamos al portal y damos click en IR AL LABORATORIO, donde se nos despliega la pagina donde vamos a trabajar, procedemos a escoger una de las categorías con el afán de que el BURN capture el tráfico que esta página genera.

 
Una vez capturado el tráfico procedemos a ingresar la solución que el mismo reto nos da: 
1.	Utilice Burp Suite para interceptar y modificar la solicitud que establece el filtro de categoría de producto.
2.	Modificar el category parámetro, dándole el valor '+OR+1=1--
3.	Envíe la solicitud y verifique que la respuesta ahora contenga uno o más productos no lanzados


Damos click en FORWARD y se actualizan las sentencias, quedando solucionado el reto
 
