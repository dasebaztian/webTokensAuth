# Key manager
En este proyecto se desarrolló una aplicación web que permite
realizar un proceso de creación de firmas para realizar la firma y
validación de archivos. Todo esto a través de un proceso de registro
de usuarios y creación de firmas digitales elípticas.

## Objetivo
Esto con la finalidad de contar con una plataforma que permita
a los usuarios verificar la autenticidad de archivos compartidos.

## Características
+ Manejo de usuarios.
+ Generación de llaves privadas y públicas, la llave privada se
almacena de manera cifrada, se descifra con la contraseña del usuario.
+ Firma de archivos, los usuarios pueden subir archivos al servidor
para ser firmados (Los archivos no se almacenan) y descargar la firma
del archivo que proporcionarón.
+ Verificación de archivos, los usuarios pueden subir el archivo
y la firma generada, junto al nombre de usuario que lo firmó para
verificar si el archivo es autentico.
+ El sistema es implementado dentro de un servidor Nginx

## Seguridad
+ La clave privada de cada usuario se almacena cifrada.
+ Las contraseñas son guardadas a través de hashing.
+ Las claves son invalidadas despúes de un tiempo configurable.
+ Se toman medidas de seguridad contra ataques de:
	- Inyección SQL
	- XSS
	- CSRF
	- Directory path transversal
+ El sistema funciona gracias a la conexión de base de datos con MariaDB con estrictas medidas de seguridad.

