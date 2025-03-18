
FACULTATIVO Ataque de inyección SQL, consultando el tipo y la versión de la base de datos en Oracle
LABORATORIO Nº3 Resuelto

Este laboratorio presenta una vulnerabilidad de inyección SQL en el filtro de categorías de productos. Se puede usar un ataque UNION para recuperar los resultados de una consulta inyectada.
Para resolver el laboratorio, muestre la cadena de versión de la base de datos.
Ingresamos al portal y damos click en IR AL LABORATORIO, donde se nos despliega la página donde vamos a trabajar, procedemos a escoger la categoría Gifts con el objetivo de que el BURN capture el tráfico que esta página genera.

Imagen 1

Una vez capturado el tráfico procedemos a ingresar la solución que el mismo reto nos da:

Utilice Burp Suite para interceptar y modificar la solicitud que establece el filtro de categoría de producto.
Determine el número de columnas que devuelve la consulta y cuáles contienen datos de texto. Verifique que la consulta devuelva dos columnas, ambas con texto, utilizando una carga útil como la siguiente en el category parámetro: '+UNION+SELECT+'abc','def'+FROM+dual--
Utilice la siguiente carga útil para mostrar la versión de la base de datos:
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--

Para poder trabajar con las dos sentenciar primero en el área de REQUEST colocamos el cursor en algún lugar de este sitio y damos click derecho y escogemos la opción que die: SEND TO REPEATER y se nos abre una ventana RESPONSE, nos dirigimos al menú a la opción REPEATER.

Imagen 2,3

Una vez dentro de la opción REPETEAR vamos al código e ingresamos la solución:
Codigo 1

Procedemos a dar clcik en SEND para que se actualice los registros
Codigo 2

Procedemos a dar clcik en SEND para que se actualice los registros.

Verificamos que surta efecto los scripts ingresados. Imagen 7 y 8