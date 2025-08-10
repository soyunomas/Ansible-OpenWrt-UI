
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
