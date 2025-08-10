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
        # Excluir playbooks de sistema (A_) y de acciones (action_)
        playbooks.extend([f for f in found_files if not os.path.basename(f).startswith('A_') and not os.path.basename(f).startswith('action_')])
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

@app.route('/actions')
def actions_view():
    routers = parse_inventory()
    return render_template('actions.html', routers=routers)

@app.route('/execute', methods=['GET'])
def execute_view():
    routers = parse_inventory()
    library_playbooks = get_library_playbooks()
    return render_template('execute.html', routers=routers, library_playbooks=library_playbooks)

# --- RUTAS DE LA API (para ser llamadas por JavaScript) ---

@app.route('/api/devices')
def api_get_devices():
    devices = parse_inventory()
    return jsonify(devices)

@app.route('/api/status/<device_name>')
def api_get_device_status(device_name):
    playbook_path = os.path.join(LIBRARY_FOLDER, 'A_get_device_details.yml')
    details = {'radios': []}
    result = None
    ansible_env = get_ansible_env()

    try:
        command = ['ansible-playbook', '-v', '--limit', device_name, playbook_path]
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30, env=ansible_env)
        
        json_string = None
        for line in result.stdout.splitlines():
            if line.strip().startswith(f"ok: [{device_name}] =>"):
                json_string = line.split("=>", 1)[1].strip()
                break
        if not json_string: raise ValueError("No se encontró la línea de resultado JSON.")

        ansible_task_result = json.loads(json_string)

        if ansible_task_result.get('rc', 0) != 0 or ansible_task_result.get('stderr_lines'):
            if not (len(ansible_task_result['stderr_lines']) == 1 and "Connection to" in ansible_task_result['stderr_lines'][0]):
                 raise ValueError(f"Error en el dispositivo: {ansible_task_result.get('stderr', '')}")
        
        raw_output = ansible_task_result.get('stdout', '')

        for line in raw_output.splitlines():
            if "::" in line:
                key, value = line.split('::', 1)
                key = key.strip().lower()
                value = value.strip()
                if key == 'radio_info':
                    # --- INICIO DE LA MODIFICACIÓN ---
                    radio_parts = value.split('|')
                    # Ahora esperamos 4 partes: nombre, generación, ssid y cifrados
                    if len(radio_parts) == 4:
                        radio_name, wifi_gen, ssid, supported_ciphers = radio_parts
                        details['radios'].append({
                            'name': radio_name,
                            'index': int(re.search(r'\d+', radio_name).group()),
                            'generation': wifi_gen,
                            'ssid': ssid,
                            # Convertimos la cadena de cifrados en una lista
                            'supported_ciphers': supported_ciphers.split(',')
                        })
                    # --- FIN DE LA MODIFICACIÓN ---
                else:
                    details[key] = value

        if details.get('wan_ip'): details['wan_ip'] = details['wan_ip'].splitlines()[0]
        if not details.get('ip') or details.get('ip') == 'N/A': raise ValueError("El dispositivo no devolvió una IP válida.")
        
        if details.get('memtotal_kb') and details['memtotal_kb'].isdigit(): details['mem_total'] = f"{round(int(details['memtotal_kb']) / 1024)} MB"
        if details.get('memfree_kb') and details['memfree_kb'].isdigit(): details['mem_free'] = f"{round(int(details['memfree_kb']) / 1024)} MB"
        if details.get('dmesg'): details['dmesg'] = details['dmesg'].replace('|', '\n')
        
        details['status'] = 'online'
        return jsonify(details)

    except subprocess.CalledProcessError as e:
        error_message = 'El host no responde o la ejecución falló.'
        if e.returncode == 4: error_message = "Fallo de autenticación. Revisa la contraseña en el archivo `hosts`."
        return jsonify({'status': 'offline', 'error': error_message, 'details': str(e)}), 500
    except (ValueError, json.JSONDecodeError, AttributeError) as e:
        return jsonify({'status': 'offline', 'error': 'Los datos recibidos del host no son válidos.', 'details': str(e)}), 500
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'offline', 'error': 'Timeout: El dispositivo no respondió a tiempo.'}), 500
    except Exception as e:
        return jsonify({'status': 'offline', 'error': 'Ha ocurrido un error general en el servidor.'}), 500

@app.route('/api/wifi_details/<device_name>/<int:radio_index>', methods=['GET'])
def get_wifi_details(device_name, radio_index):
    playbook_path = os.path.join(LIBRARY_FOLDER, 'action_get_wifi_password.yml')
    extra_vars = {'radio_index': radio_index}
    
    stdout, stderr = run_ansible_playbook(playbook_path, device_name, extra_vars)
    if stderr and "fatal" in stderr.lower():
        return jsonify({'error': 'No se pudieron obtener los detalles de WiFi.', 'details': stderr}), 500
    
    details = {}
    for line in stdout.splitlines():
        if "KEY::" in line:
            details['password'] = line.split("::", 1)[1].strip()
        if "ENCRYPTION::" in line:
            details['encryption'] = line.split("::", 1)[1].strip()

    return jsonify(details)

def run_ansible_playbook(playbook_path, target_host, extra_vars=None):
    try:
        ansible_env = get_ansible_env()
        command = ['ansible-playbook', '-v', '--limit', target_host, playbook_path]
        if extra_vars:
            command.extend(['--extra-vars', json.dumps(extra_vars)])
        
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120, env=ansible_env)
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.stdout, e.stderr
    except subprocess.TimeoutExpired:
        return "", "Timeout: La ejecución tardó más de 120 segundos."
    except FileNotFoundError:
        return "", "Error: 'ansible-playbook' no se encuentra."
    except Exception as e:
        return "", f"Ocurrió un error inesperado: {str(e)}"

@app.route('/api/execute_batch_action', methods=['POST'])
def execute_batch_action():
    data = request.json
    targets = data.get('targets')
    action = data.get('action')
    params = data.get('params', {})

    if not targets or not action:
        return jsonify({'error': 'Faltan los objetivos o la acción.'}), 400

    playbook_map = {
        'reboot': 'action_reboot.yml',
        'set_ipv4': 'action_set_ipv4.yml',
        'set_wifi': 'action_set_wifi.yml',
        'set_root_password': 'action_set_root_password.yml',
        'restart_network': '02_reiniciar_red.yml',
        'restart_wifi': '06_reiniciar_wifi.yml'
    }

    playbook_name = playbook_map.get(action)
    if not playbook_name:
        return jsonify({'error': 'Acción no válida.'}), 400

    playbook_path = os.path.join(LIBRARY_FOLDER, playbook_name)
    target_string = ",".join(targets)

    stdout, stderr = run_ansible_playbook(playbook_path, target_string, params)
    
    return jsonify({
        'output': stdout,
        'error': stderr
    })

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    if not os.path.exists(LIBRARY_FOLDER):
        os.makedirs(LIBRARY_FOLDER)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
