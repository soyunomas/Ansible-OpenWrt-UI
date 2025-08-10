
# Ansible-OpenWrt-UI

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)![Ansible](https://img.shields.io/badge/Ansible-2.9+-red.svg)![Flask](https://img.shields.io/badge/Flask-2.0+-lightgrey.svg)![License](https://img.shields.io/badge/License-MIT-green.svg)

Panel de control web para gestionar y automatizar routers OpenWrt a través de playbooks de Ansible.

## ✨ Características

*   **Dashboard Visual:** Monitoriza el estado (online/offline) de todos tus routers de un vistazo.
*   **Información Detallada:** Obtén datos clave de cada dispositivo: hostname, modelo, firmware, IP, uptime, uso de memoria, clientes WiFi y más.
*   **Biblioteca de Playbooks:** Ejecuta tareas predefinidas (ver/aplicar actualizaciones, reiniciar servicios, etc.) desde una interfaz amigable.
*   **Ejecución Personalizada:** Sube tus propios playbooks de Ansible y ejecútalos contra un router específico o contra todos.
*   **Sin Terminal:** Realiza operaciones comunes sin necesidad de acceder por SSH a cada dispositivo.

## 🛠️ Tecnologías Utilizadas

*   **Backend:** Python 3, Flask
*   **Automatización:** Ansible
*   **Frontend:** HTML, CSS, JavaScript, Bootstrap 5
  
## 🧠 Filosofía de Diseño: Mínima Huella en el Router

Este panel está diseñado con una premisa fundamental: **no modificar el sistema base de OpenWrt**. Los routers suelen tener un espacio de almacenamiento muy limitado, por lo que instalar un intérprete de Python y las librerías necesarias para que los módulos estándar de Ansible funcionen no es una opción viable ni deseable.

Para lograrlo, toda la comunicación y ejecución de tareas se basa en una estrategia que aprovecha al máximo lo que un sistema OpenWrt ya tiene por defecto: un servidor SSH y un conjunto de herramientas de línea de comandos (como `awk`, `grep`, `sed`, `uci`, etc.).

Esto se consigue aplicando los siguientes principios en todos los playbooks:

1.  **Desactivación de la Recolección de Hechos:** En cada playbook, se especifica `gather_facts: false`. Este paso es crucial, ya que la recolección de hechos (`facts`) es el proceso por el cual Ansible intenta ejecutar un script de Python en el nodo remoto para obtener información del sistema. Al desactivarlo, evitamos el primer requisito de Python.

2.  **Uso Exclusivo del Módulo `ansible.builtin.raw`:** En lugar de módulos como `ansible.builtin.command` o `ansible.builtin.shell` (que también tienen ciertas dependencias), utilizamos `raw`. Este módulo hace lo mínimo indispensable: abre una conexión SSH y ejecuta el comando que le pasamos, devolviendo la salida en crudo. Es la forma más pura de ejecutar un comando remoto, compatible con cualquier dispositivo que tenga un servidor SSH.

3.  **Formato de Salida predecible:** Como se puede ver en el playbook `A_get_device_details.yml`, la lógica no reside en Ansible, sino en el propio comando shell que se ejecuta. Los datos se formatean con un separador simple (ej: `HOSTNAME::router-principal`) para que la aplicación Flask pueda parsear la salida de texto fácilmente sin depender de formatos complejos como JSON, que serían más difíciles de generar con comandos de shell básicos.

#### Ventajas de este enfoque:

*   **Zero-Dependency en el Router:** No necesitas instalar `python`, `scp`, `sftp` ni ningún otro paquete en tus dispositivos OpenWrt. Funciona con una instalación por defecto.
*   **Universalidad:** Es compatible con casi cualquier versión de OpenWrt y otros sistemas embebidos que solo ofrezcan acceso SSH.
*   **Ligereza:** El impacto en el rendimiento y almacenamiento del router es prácticamente nulo.
*   **Seguridad:** No se añaden nuevos servicios ni intérpretes al router, reduciendo la superficie de ataque.

#### Limitaciones a tener en cuenta:

*   **Idempotencia Manual:** El módulo `raw` no es idempotente por naturaleza. A diferencia de los módulos de Ansible (ej: `user`, `copy`), que comprueban el estado antes de realizar una acción, un comando `raw` se ejecutará siempre. La lógica para comprobar si un cambio es necesario debe ser implementada manualmente en el script del propio playbook.
*   **Complejidad en los Playbooks:** Tareas complejas requieren scripts de shell más elaborados, que pueden ser más difíciles de escribir y depurar que un playbook de Ansible estándar.
*   **Fragilidad del "Parseo":** La interfaz gráfica depende de que los comandos devuelvan la información en el formato esperado. Un cambio en la salida de un comando en una futura versión de OpenWrt podría romper la visualización de ese dato hasta que se adapte el playbook.


## 🚀 Instalación y Configuración

Sigue estos pasos para poner en marcha el panel de control en tu máquina local.

### 1. Prerrequisitos

Asegúrate de tener instalado lo siguiente en tu sistema:

*   **Python 3** (versión 3.7 o superior)
*   **Ansible** (versión 2.9 o superior)
*   **Git**

### 2. Clonar el Repositorio

Abre una terminal y clona este repositorio:

```bash
git clone https://github.com/soyunomas/Ansible-OpenWrt-UI.git
cd Ansible-OpenWrt-UI
```

### 3. Instalar Dependencias de Python

El proyecto utiliza Flask. Es una buena práctica usar un entorno virtual.

```bash
# Crear un entorno virtual (opcional pero recomendado)
python3 -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar las dependencias
pip install -r requirements.txt
```

> **Nota:** El archivo `requirements.txt` solo contiene `Flask`. Si no lo tienes, créalo con esa única línea.

### 4. Configurar el Inventario de Routers (`hosts`)

Este es el paso más importante. Debes decirle a Ansible cuáles son tus routers y cómo conectarse a ellos.

Edita el archivo `ansible_project/hosts` y añade tus dispositivos siguiendo este formato:

```ini
# ansible_project/hosts

[routers]
# Sustituye con tus datos reales. Puedes añadir tantos routers como quieras.

# Formato: <nombre_para_la_app> ansible_host=<IP_del_router> ansible_user=<usuario> ansible_ssh_pass=<contraseña>

router_principal      ansible_host=192.168.1.1   ansible_user=root ansible_ssh_pass=tu_password_seguro
router_despacho       ansible_host=192.168.1.50  ansible_user=root ansible_ssh_pass=otra_password
router_salon          ansible_host=192.168.1.51  ansible_user=root ansible_ssh_pass=password_salon
```

**¡ADVERTENCIA DE SEGURIDAD!**
Guardar contraseñas en texto plano es una mala práctica para entornos de producción. Para un uso más seguro, considera usar [claves SSH](https://docs.ansible.com/ansible/latest/user_guide/connection_details.html#setting-the-remote-user-and-password) o [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) para encriptar tus contraseñas.

## ▶️ Uso

Una vez completada la instalación y configuración, ejecuta la aplicación:

```bash
python3 app.py
```

El servidor se iniciará y podrás acceder al panel desde tu navegador en:

**http://127.0.0.1:5000**

¡Y ya está! Ahora deberías ver tus routers en el panel y podrás empezar a interactuar con ellos.

## 📁 Estructura del Proyecto

Aquí tienes una descripción de los archivos y carpetas más importantes:

```
Ansible-OpenWrt-UI/
├── ansible_project/
│   └── hosts                # ¡CRÍTICO! Tu inventario de routers. Aquí defines tus dispositivos.
├── playbook_library/
│   ├── A_get_device_details.yml # Playbook maestro para obtener todos los datos de un dispositivo.
│   └── ...                      # Otros playbooks con tareas predefinidas.
├── templates/
│   ├── devices.html         # Plantilla para la vista principal del dashboard.
│   ├── execute.html         # Plantilla para la página de ejecución de playbooks.
│   └── layout.html          # Plantilla base con el menú y la estructura común.
├── app.py                   # El cerebro de la aplicación. Contiene toda la lógica del backend en Flask.
├── ansible.cfg              # Configuración local de Ansible para asegurar una salida consistente.
└── requirements.txt         # Lista de dependencias de Python para el proyecto.
```

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.
