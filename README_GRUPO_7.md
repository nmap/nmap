NMAP
1) NMAP funciona para raelizar escaneo en todas las redes, su proposito principal es encontrar puertos abiertos y vulnerabilidades ademas que posee este tipo de escaneos SYN, TCP, UDP, y SCTP para detectar servicios abiertos en un sistema objetivo.

Ademas se puede optar por poner velocidad a nmap con la opcion -T5
2) 🔍 ¿Para qué se usa?
-Identificar dispositivos conectados a una red.
-Detectar puertos abiertos y servicios que están corriendo.
-Determinar versiones de software y sistemas operativos.
-Realizar pruebas de seguridad y detección de vulnerabilidades.
-Identifica sistemas operativos y versiones de software a través de fingerprinting con -O y -sV
-Se usa en pruebas de penetración para obtener una visión detallada de la superficie de ataque de una red.
-Técnicas de evasión como fragmentación de paquetes (-f), modificación de TTL (--ttl) o camuflaje de origen (-S, -D) para analizar reglas de firewall.
-Se puede ejecutar en modo agente distribuido mediante nmap -iL para escanear múltiples objetivos simultáneamente
4) JUSTIFICACIÓN
Nmap, abreviatura de "Network Mapper", es una herramienta de código abierto utilizada para la exploración de redes y auditorías de seguridad. Permite a los administradores de red identificar dispositivos activos en una red, descubrir puertos y servicios abiertos, y detectar vulnerabilidades. Nmap puede adaptarse a las condiciones de la red, incluyendo latencia y congestión, durante un escaneo.("Nmap: the Network Mapper", s.f.)
El repositorio de Nmap no solo ofrece una herramienta de escaneo de puertos, sino que proporciona un framework avanzado de auditoría de redes y seguridad ofensiva, esencial en cualquier kit de pentesting o administración de redes. Su versatilidad lo hace útil tanto para atacantes éticos como para defensores de ciberseguridad.

6) Referencia:

Nmap: the Network Mapper - Free Security Scanner. (s.f.). Nmap. https://nmap.org/




# Nmap - Network Mapper

Nmap es “Network Mapper”una herramienta de código abierto para la red exploración y auditoría de la seguridad. Fue diseñado para rápidamente escanean grandes redes, aunque funciona bien contra single anfitriones. Nmap utiliza paquetes IP crudos de maneras novedosas para determinar qué Los anfitriones están disponibles en la red, qué servicios (aplicación nombre y versión) que ofrecen esos hosts, qué sistemas operativos (y versiones del sistema operativo) están en ejecución, qué tipo de paquetes filtros/cortales están en uso, y docenas de otros características. Mientras que Nmap se utiliza comúnmente para auditorías de seguridad, muchos sistemas y administradores de redes lo encuentran útil para la rutina tareas como inventario de la red, gestión de la actualización del servicio horarios, y monitorear el tiempo de actividad o servicio
```
- 
**`nmap -A -T4 scanme.nmap.org`**Reporte de escaneo de mapa de Nmap para scanme.nmap.org (74.207.244.221)
El anfitrión se levanta (0.029s latencia).
rDNS récord para 74.207.244.221: li86-221.members.linode.com
No mostrado: 995 puertos cerrados
PORT ESTADO SERVICIO VERSION
22/tcp open ssh OpenSSH 5.3p1 Debian 3ubuntu7 (protocolo 2.0)
* ssh-hostkey: 1024 8d:60:f1:7c:ca:b7:3d:0a:d6:67:54:9d:69:d9:b9:dd (DSA)
No2048 79:f8:09:ac:d4:e2:32:42:10:49:d3:bd:20:82:85:ec (RSA)
80/tcp abierto http Apache httpd 2.2.14 ((Ubuntu))
- Título: Adelante y escanearme.
646/tcp filtrado ldp
1720/tcp filtrado H.323/Q.931
9929/tcp open nping-echo eco de Nping
Tipo de dispositivo: propósito general
Corrida: Linux 2.6. X
OS CPE: cpe:/o:linux:linux-kernel:2.6.39
Detalles del sistema operativo: Linux 2.6.39
Distancia de la red: 11 lúpulo
Información del servicio: OS: Linux; CPE: cpe:/o:linux:kernel

TRACEROUTE (utilización del puerto 53/tcp)
HOP RTT ADDRESS
[Cortar los primeros 10 lúpulo para la brevedad]
11 17.65 ms li86-221.members.linode.com (74.207.244.221)

Maestación hecha: 1 dirección IP (1 host up) escaneada en 14.40 segundos
```

# Referencias  20

- https://nmap.org/book/man.html#man-ex-repscan
- https://www.freecodecamp.org/news/what-is-nmap-and-how-to-use-it-a-tutorial-for-the-greatest-scanning-tool-of-all-time/
