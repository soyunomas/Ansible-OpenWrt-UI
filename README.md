# Ansible-OpenWrt-UI

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg) ![Ansible](https://img.shields.io/badge/Ansible-2.9+-red.svg) ![Flask](https://img.shields.io/badge/Flask-2.0+-lightgrey.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg)

Panel de control web **seguro** para gestionar, monitorizar y automatizar routers OpenWrt a través de playbooks de Ansible, con una interfaz gráfica intuitiva.

## ✨ Características

*   **Gestión Segura con Autenticación:** Acceso protegido por usuario y contraseña, con posibilidad de cambiar la contraseña y protección contra ataques CSRF.
*   **Dashboard Visual:** Monitoriza el estado (online/offline/host no confiable) de todos tus routers de un vistazo.
*   **Información Detallada:** Obtén datos clave de cada dispositivo: hostname, modelo, firmware, IP, uptime, uso de memoria, configuración WiFi y más, todo en un modal interactivo.
*   **Acciones en Lote:** Aplica cambios a múltiples dispositivos simultáneamente desde una interfaz centralizada. ¡Configura IPs, redes WiFi, cambia la contraseña de root o reinicia routers en masa!
*   **Biblioteca de Playbooks:** Ejecuta tareas predefinidas (ver actualizaciones, listar clientes WiFi, etc.) desde una interfaz amigable.
*   **Ejecución Personalizada:** Sube tus propios playbooks de Ansible y ejecútalos contra un router específico o contra todos.
*   **Gestión de Claves SSH:** La primera vez que te conectas a un router, la interfaz te ayuda a verificar y aceptar su huella digital (fingerprint) de forma segura.
*   **Sin Terminal:** Realiza operaciones comunes sin necesidad de acceder por SSH a cada dispositivo.

## 🛠️ Tecnologías Utilizadas

*   **Backend:** Python 3, Flask, Flask-Login (autenticación), Flask-WTF (seguridad y CSRF)
*   **Automatización:** Ansible
*   **Frontend:** HTML, CSS, JavaScript, Bootstrap 5

## 🧠 Filosofía de Diseño: Mínima Huella en el Router

Este panel está diseñado con una premisa fundamental: **no modificar el sistema base de OpenWrt**. Los routers suelen tener un espacio de almacenamiento muy limitado, por lo que instalar un intérprete de Python no es una opción viable.

Toda la comunicación y ejecución de tareas se basa en aprovechar lo que un sistema OpenWrt ya tiene: un servidor SSH y herramientas de línea de comandos (`uci`, `awk`, `grep`, `sed`, etc.).

Esto se consigue aplicando los siguientes principios en todos los playbooks:

1.  **Desactivación de la Recolección de Hechos (`gather_facts: false`):** Se evita el intento de Ansible de ejecutar scripts de Python en el router.
2.  **Uso Exclusivo del Módulo `ansible.builtin.raw`:** Se envían comandos de shell puros a través de SSH, garantizando la máxima compatibilidad con cualquier dispositivo con SSH.
3.  **Formato de Salida predecible:** Los scripts en los playbooks formatean la salida con un separador simple (ej: `HOSTNAME::router-principal`) para que la aplicación Flask pueda parsearla fácilmente sin depender de JSON.

#### Ventajas de este enfoque:

*   **Zero-Dependency en el Router:** No necesitas instalar `python` ni ningún otro paquete en tus dispositivos OpenWrt.
*   **Universalidad:** Compatible con casi cualquier versión de OpenWrt y otros sistemas embebidos.
*   **Ligereza:** El impacto en el rendimiento y almacenamiento del router es prácticamente nulo.
*   **Seguridad:** No se añaden nuevos servicios al router, reduciendo la superficie de ataque.

#### Limitaciones a tener en cuenta:

*   **Idempotencia Manual:** El módulo `raw` no es idempotente. La lógica para comprobar si un cambio es necesario debe implementarse manualmente en el script del playbook.
*   **Complejidad en los Playbooks:** Tareas complejas requieren scripts de shell más elaborados.
*   **Fragilidad del "Parseo":** La UI depende de que los comandos devuelvan la información en el formato esperado. Un cambio en una futura versión de OpenWrt podría romper la visualización.

## 🚀 Instalación y Puesta en Marcha

Sigue estos pasos para poner en marcha el panel de control en tu máquina local.

### Paso 1: Prerrequisitos

Asegúrate de tener instalado lo siguiente en tu sistema:
*   **Python 3** (versión 3.7 o superior)
*   **Ansible** (versión 2.9 o superior)
*   **Git**

### Paso 2: Clonar el Repositorio

```bash
git clone https://github.com/soyunomas/Ansible-OpenWrt-UI.git
cd Ansible-OpenWrt-UI
```

### Paso 3: Instalar Dependencias de Python

Es una buena práctica usar un entorno virtual.
```bash
# Crear un entorno virtual (opcional pero recomendado)
python3 -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar las dependencias
pip install -r requirements.txt
```
> **Nota:** El archivo `requirements.txt` contiene Flask, Flask-Login, Flask-WTF y filelock.

### Paso 4: Configurar el Inventario de Routers (`hosts`)

Este es un paso fundamental. Edita el archivo `ansible_project/hosts` y añade tus dispositivos siguiendo este formato:

```ini
# ansible_project/hosts

[routers]
# Sustituye con tus datos reales. Puedes añadir tantos routers como quieras.

# Formato: <nombre_para_la_app> ansible_host=<IP_del_router> ansible_user=<usuario> ansible_ssh_pass=<contraseña>

router_principal      ansible_host=192.168.1.1   ansible_user=root ansible_ssh_pass=tu_password_seguro
router_despacho       ansible_host=192.168.1.50  ansible_user=root ansible_ssh_pass=otra_password
```

**¡ADVERTENCIA DE SEGURIDAD!**
Guardar contraseñas en texto plano no es seguro. Para un uso más robusto, considera usar [claves SSH](https://docs.ansible.com/ansible/latest/user_guide/connection_details.html#setting-the-remote-user-and-password) o [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html).

### Paso 5 (Crítico): Crear el Usuario Administrador

Para asegurar la aplicación, primero debes crear una cuenta de administrador. Ejecuta el siguiente script y sigue las instrucciones:

```bash
python3 setup_admin.py
```
Se te pedirá un nombre de usuario y una contraseña, que usarás para acceder al panel.

## ▶️ Ejecución y Acceso

Una vez completada la instalación, ejecuta la aplicación:

```bash
python3 app.py
```

El servidor se iniciará. Accede al panel desde tu navegador en:

**http://127.0.0.1:5000**

Serás redirigido a la página de inicio de sesión. ¡Introduce las credenciales que creaste en el paso 5 y listo!

## 📁 Estructura del Proyecto

```
Ansible-OpenWrt-UI/
├── ansible_project/
│   └── hosts                # ¡CRÍTICO! Tu inventario de routers. ¡DEBES EDITAR ESTE ARCHIVO!
├── playbook_library/
│   ├── A_get_device_details.yml # Playbook maestro para obtener los datos del dashboard.
│   ├── action_*.yml         # Playbooks utilizados por la página "Acciones en Lote".
│   └── ...                  # Otros playbooks para la ejecución manual.
├── templates/
│   ├── devices.html         # Plantilla para el dashboard principal.
│   ├── actions.html         # Plantilla para la página de acciones en lote.
│   ├── execute.html         # Plantilla para la página de ejecución de playbooks.
│   ├── login.html           # Página de inicio de sesión.
│   ├── profile.html         # Página para cambiar la contraseña del usuario.
│   ├── setup.html           # Página que se muestra si no se ha creado un usuario.
│   └── layout.html          # Plantilla base con el menú y la estructura común.
├── app.py                   # El cerebro de la aplicación. Contiene la lógica del backend en Flask,
│                            # incluyendo autenticación, seguridad CSRF y las rutas de la API.
├── setup_admin.py           # Script para crear el primer usuario administrador.
├── ansible.cfg              # Configuración local de Ansible.
├── requirements.txt         # Lista de dependencias de Python para el proyecto.
└── user.json                # Archivo que almacena los datos del usuario (no editar manualmente).
```

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.
