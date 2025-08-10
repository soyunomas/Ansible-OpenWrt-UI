import os
import subprocess
import uuid
import glob
import re
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename

# --- CONFIGURACIÓN Y FUNCIONES AUXILIARES ---
UPLOAD_FOLDER = 'uploads'
LIBRARY_FOLDER = 'playbook_library'
ALLOWED_EXTENSIONS = {'yml', 'yaml'}
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_library_playbooks():
    playbooks = []
    for extension in ('*.yml', '*.yaml'):
        found_files = glob.glob(os.path.join(LIBRARY_FOLDER, extension))
        playbooks.extend([f for f in found_files if not os.path.basename(f).startswith('A_')])
    return sorted([os.path.basename(p) for p in playbooks])

def parse_inventory():
    inventory_path = os.path.join('ansible_project', 'hosts')
    hosts = []
    try:
        with open(inventory_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('['):
                    hosts.append(line.split()[0])
    except FileNotFoundError:
        print(f"ADVERTENCIA: Inventario no encontrado en {inventory_path}")
    return hosts

def get_ansible_env():
    env = os.environ.copy()
    env['ANSIBLE_STDOUT_CALLBACK'] = 'default'
    env['ANSIBLE_CONFIG'] = os.path.abspath('ansible.cfg')
    return env

# --- RUTAS DE VISTAS HTML ---

@app.route('/')
def index_redirect():
    return redirect(url_for('devices_view'))

@app.route('/devices')
def devices_view():
    return render_template('devices.html')

@app.route('/execute', methods=['GET'])
def execute_view():
    routers = parse_inventory()
    library_playbooks = get_library_playbooks()
    return render_template('execute.html', routers=routers, library_playbooks=library_playbooks)

# --- RUTAS DE LA API (para ser llamadas por JavaScript) ---

@app.route('/api/devices')
def api_get_devices():
    print("--- API CALL: /api/devices ---")
    devices = parse_inventory()
    print(f"Devolviendo: {devices}")
    return jsonify(devices)

@app.route('/api/status/<device_name>')
def api_get_device_status(device_name):
    print(f"--- API CALL (FINAL PARSER): /api/status/{device_name} ---")
    playbook_path = os.path.join(LIBRARY_FOLDER, 'A_get_device_details.yml')
    details = {}
    result = None
    ansible_env = get_ansible_env()

    try:
        command = ['ansible-playbook', '-v', '--limit', device_name, playbook_path]
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30, env=ansible_env)
        
        # Lógica de parseo robusta sin Regex
        json_string = None
        for line in result.stdout.splitlines():
            # Buscamos la línea que contiene el resultado de la tarea
            if line.strip().startswith(f"ok: [{device_name}] =>"):
                # El JSON empieza después del '=>'
                json_string = line.split("=>", 1)[1].strip()
                break # Encontramos lo que buscábamos, salimos del bucle

        if not json_string:
            raise ValueError("No se encontró la línea de resultado JSON ('ok: ... =>') en la salida de Ansible.")

        ansible_task_result = json.loads(json_string)

        if ansible_task_result.get('rc', 0) != 0 or ansible_task_result.get('stderr_lines'):
             # Ignoramos el mensaje "Connection to ... closed." que es normal.
            if not (len(ansible_task_result['stderr_lines']) == 1 and "Connection to" in ansible_task_result['stderr_lines'][0]):
                 error_output = ansible_task_result.get('stderr', 'La tarea raw devolvió un error.')
                 raise ValueError(f"Error en el dispositivo: {error_output}")
        
        raw_output = ansible_task_result.get('stdout', '')

        for line in raw_output.splitlines():
            if "::" in line:
                key, value = line.split('::', 1)
                details[key.strip().lower()] = value.strip()
        
        # Limpieza de datos extraños (ej: WAN_IP con múltiples líneas)
        if details.get('wan_ip'):
            details['wan_ip'] = details['wan_ip'].splitlines()[0]

        if not details.get('ip') or details.get('ip') == 'N/A':
             raise ValueError("El dispositivo no devolvió una IP válida.")

        if details.get('memtotal_kb') and details['memtotal_kb'].isdigit():
            kb = int(details['memtotal_kb'])
            details['mem_total'] = f"{round(kb / 1024)} MB"
        else: details['mem_total'] = 'N/A'

        if details.get('memfree_kb') and details['memfree_kb'].isdigit():
            kb = int(details['memfree_kb'])
            details['mem_free'] = f"{round(kb / 1024)} MB"
        else: details['mem_free'] = 'N/A'
        
        if details.get('dmesg'):
            details['dmesg'] = details['dmesg'].replace('|', '\n')

        details['status'] = 'online'
        print(f"¡¡¡VICTORIA!!! DATOS PARSEADOS CORRECTAMENTE para {device_name}")
        return jsonify(details)

    except (subprocess.CalledProcessError, ValueError, json.JSONDecodeError) as e:
        print(f"ERROR FINAL PROCESANDO {device_name}: {e}")
        if result:
            print("--- STDOUT COMPLETO ---")
            print(result.stdout)
            print("--- STDERR COMPLETO ---")
            print(result.stderr)
            print("--- FIN DE LA SALIDA ---")
        return jsonify({'status': 'offline', 'error': 'Los datos recibidos no son válidos o el host falló.', 'details': str(e)}), 500
    except subprocess.TimeoutExpired:
        print(f"Timeout contactando a {device_name}")
        return jsonify({'status': 'offline', 'error': 'Timeout al contactar el dispositivo.'}), 500
    except Exception as e:
        print(f"Error inesperado en {device_name}: {e}")
        return jsonify({'status': 'offline', 'error': 'Error general del servidor.'}), 500

@app.route('/execute', methods=['POST'])
def execute_playbook():
    routers, library_playbooks = parse_inventory(), get_library_playbooks()
    target = request.form.get('target')
    submit_action = request.form.get('submit_action')
    output, error = "", ""

    if not target:
        error = "Debe seleccionar un objetivo."
        return render_template('execute.html', routers=routers, library_playbooks=library_playbooks, output=output, error=error)

    playbook_path = None
    if submit_action == 'upload':
        if 'playbook_file' not in request.files or not request.files['playbook_file'].filename:
            error = "Debe seleccionar un archivo para subir."
        else:
            file = request.files['playbook_file']
            if allowed_file(file.filename):
                filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
                playbook_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(playbook_path)
            else:
                error = "Tipo de archivo no permitido."
    elif submit_action == 'library':
        playbook_name = request.form.get('playbook_name')
        if playbook_name and playbook_name in get_library_playbooks():
            playbook_path = os.path.join(LIBRARY_FOLDER, playbook_name)
        else:
            error = "Debe seleccionar un playbook válido de la librería."
    else:
        error = "Acción no reconocida."

    if playbook_path and not error:
        output, error = run_ansible_playbook(playbook_path, target)
        if submit_action == 'upload' and os.path.exists(playbook_path):
            os.remove(playbook_path)

    return render_template('execute.html', routers=routers, library_playbooks=library_playbooks, output=output, error=error)

def run_ansible_playbook(playbook_path, target_host):
    try:
        ansible_env = get_ansible_env()
        command = ['ansible-playbook', '-v', '--limit', target_host, playbook_path]
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=90, env=ansible_env)
        return result.stdout, None
    except subprocess.CalledProcessError as e:
        return e.stdout, e.stderr
    except subprocess.TimeoutExpired:
        return "", "Timeout: La ejecución del playbook tardó más de 90 segundos."
    except FileNotFoundError:
        return "", "Error: El comando 'ansible-playbook' no se encuentra."
    except Exception as e:
        return "", f"Ocurrió un error inesperado: {str(e)}"

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    if not os.path.exists(LIBRARY_FOLDER):
        os.makedirs(LIBRARY_FOLDER)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
