# ==============================================================================
# ==        app.py - VERSIÓN FINAL CON AUTENTICACIÓN Y PROTECCIÓN CSRF        ==
# ==============================================================================
import os
import subprocess
import uuid
import glob
import re
import json
import ipaddress
import shlex
import logging
from filelock import FileLock # Para escritura segura en el archivo de usuario
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect # ### NUEVO ###

# --- CONFIGURACIÓN DE LA APP Y RUTAS DE ARCHIVOS ---
UPLOAD_FOLDER = 'uploads'
LIBRARY_FOLDER = 'playbook_library'
ALLOWED_EXTENSIONS = {'yml', 'yaml'}
USER_FILE = 'user.json'
USER_FILE_LOCK = 'user.json.lock'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# ¡IMPORTANTE! Cambia esto por una cadena larga y aleatoria en producción.
# Puedes generar una con: python -c 'import secrets; print(secrets.token_hex(16))'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'una-clave-secreta-muy-debil-para-desarrollo')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ### NUEVO ### - Inicializar la protección CSRF
csrf = CSRFProtect(app)

# --- CONFIGURACIÓN DE FLASK-LOGIN ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."
login_manager.login_message_category = "info"


# --- CLASE DE USUARIO BASADA EN JSON ---
class User(UserMixin):
    def __init__(self, id='1', username=None, password_hash=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def save(self):
        """Guarda los datos del usuario en el archivo JSON de forma segura."""
        with FileLock(USER_FILE_LOCK):
            with open(USER_FILE, 'w') as f:
                json.dump({'username': self.username, 'password_hash': self.password_hash}, f, indent=4)

    @staticmethod
    def get():
        """Obtiene el usuario desde el archivo JSON."""
        if not os.path.exists(USER_FILE):
            return None
        
        with FileLock(USER_FILE_LOCK):
            try:
                with open(USER_FILE, 'r') as f:
                    data = json.load(f)
                    return User(username=data.get('username'), password_hash=data.get('password_hash'))
            except (json.JSONDecodeError, FileNotFoundError):
                return None


@login_manager.user_loader
def load_user(user_id):
    return User.get()


# --- FUNCIONES AUXILIARES (Sin cambios) ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_library_playbooks():
    playbooks = []
    for extension in ('*.yml', '*.yaml'):
        found_files = glob.glob(os.path.join(LIBRARY_FOLDER, extension))
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
        app.logger.error(f"FATAL: Inventario no encontrado en {inventory_path}")
    return hosts

def get_ansible_env():
    env = os.environ.copy()
    env['ANSIBLE_CONFIG'] = os.path.abspath('ansible.cfg')
    return env

def is_safe_input(input_string, pattern=r'^[a-zA-Z0-9\._-]+$'):
    return isinstance(input_string, str) and re.match(pattern, input_string) is not None

def is_safe_password(password):
    if not isinstance(password, str): return False
    # ### CAMBIO ### - La validación de contraseña ahora es más estricta
    # Usamos una lista blanca de caracteres permitidos. Excluye espacios y caracteres de control.
    if not (8 <= len(password) <= 128): return False
    allowed_chars = r"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    return all(char in allowed_chars for char in password)


def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, TypeError):
        return False

def is_valid_netmask(mask):
    if not isinstance(mask, str): return False
    parts = mask.split('.')
    if len(parts) != 4: return False
    try:
        binary_str = ''.join(bin(int(p))[2:].zfill(8) for p in parts)
        return '01' not in binary_str
    except (ValueError, TypeError):
        return False

def is_safe_ssid(ssid):
    if not isinstance(ssid, str) or not (1 <= len(ssid) <= 32):
        return False
    # Permitimos caracteres comunes en SSIDs, pero bloqueamos deliberadamente
    # los problemáticos para la línea de comandos como ' " ` $ ; | & \
    forbidden_chars = "'\"`$;|&\\"
    return not any(char in forbidden_chars for char in ssid)

def is_safe_wifi_key(key):
    if not isinstance(key, str) or not (8 <= len(key) <= 63):
        return False
    # Misma lógica que el SSID, bloqueamos caracteres peligrosos.
    forbidden_chars = "'\"`$;|&\\"
    return not any(char in forbidden_chars for char in key)

# --- RUTAS DE AUTENTICACIÓN Y GESTIÓN DE USUARIO ---
# No se necesitan cambios significativos aquí, Flask-WTF los protege automáticamente
# si los formularios en las plantillas HTML incluyen el token.
@app.route('/setup')
def setup():
    if User.get():
        return redirect(url_for('login'))
    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('devices_view'))
    
    user = User.get()
    if not user:
        return redirect(url_for('setup'))

    if request.method == 'POST':
        username_form = request.form.get('username')
        password = request.form.get('password')

        if user.username == username_form and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('devices_view'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'success')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        user = User.get()
        if not user.check_password(current_password):
            flash('La contraseña actual es incorrecta.', 'danger')
        elif new_password != confirm_password:
            flash('Las nuevas contraseñas no coinciden.', 'danger')
        elif len(new_password) < 8:
            flash('La nueva contraseña debe tener al menos 8 caracteres.', 'warning')
        elif not is_safe_password(new_password): # ### NUEVO ### Añadimos la validación mejorada
            flash('La nueva contraseña contiene caracteres no permitidos.', 'danger')
        else:
            user.set_password(new_password)
            user.save()
            flash('¡Tu contraseña ha sido actualizada exitosamente!', 'success')
            return redirect(url_for('profile'))

    return render_template('profile.html')


# --- RUTAS PRINCIPALES DE LA APLICACIÓN (PROTEGIDAS) ---
# ... (el resto de rutas GET no necesitan cambios) ...
@app.route('/')
@login_required
def index_redirect():
    return redirect(url_for('devices_view'))

@app.route('/devices')
@login_required
def devices_view():
    return render_template('devices.html')

@app.route('/actions')
@login_required
def actions_view():
    return render_template('actions.html', routers=parse_inventory())

@app.route('/execute', methods=['GET'])
@login_required
def execute_view():
    return render_template('execute.html', routers=parse_inventory(), library_playbooks=get_library_playbooks(), output=None, error=None)

# ### CAMBIO ### - Esta ruta ahora está protegida por CSRF
@app.route('/execute', methods=['POST'])
@login_required
def execute_playbook():
    output, error, playbook_path = None, None, None
    submit_action = request.form.get('submit_action')
    target = request.form.get('target')

    if submit_action == 'library':
        playbook_name = request.form.get('playbook_name')
        if not playbook_name:
            error = "Error: No se seleccionó ningún playbook."
        else:
            safe_playbook_name = secure_filename(playbook_name)
            if safe_playbook_name != playbook_name or not is_safe_input(safe_playbook_name):
                error = "Error de seguridad: Nombre de playbook no válido."
            else:
                library_abs_path = os.path.abspath(LIBRARY_FOLDER)
                playbook_path = os.path.abspath(os.path.join(library_abs_path, safe_playbook_name))
                if not playbook_path.startswith(library_abs_path) or not os.path.exists(playbook_path):
                    error, playbook_path = "Error: Playbook no encontrado o acceso no autorizado.", None
    elif submit_action == 'upload':
        file = request.files.get('playbook_file')
        if not file or file.filename == '':
            error = 'Error: No se ha seleccionado ningún archivo.'
        elif allowed_file(file.filename):
            filename = secure_filename(file.filename)
            playbook_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(playbook_path)
        else:
            error = "Error: El tipo de archivo no está permitido."
    else:
        error = "Error: Acción de formulario no válida."

    if playbook_path and not error:
        raw_output, raw_error = run_ansible_playbook(playbook_path, target)
        output = raw_output.replace('\r', '') if raw_output else None
        error = raw_error.replace('\r', '') if raw_error else None

    return render_template('execute.html', routers=parse_inventory(), library_playbooks=get_library_playbooks(), output=output, error=error)


# --- RUTAS DE API (PROTEGIDAS) ---
# ... (Las rutas GET de la API no necesitan cambios)
@app.route('/api/devices')
@login_required
def api_get_devices():
    return jsonify(parse_inventory())

# ... (El resto de funciones como get_host_ip, get_ssh_fingerprint y api_get_device_status no cambian)
def get_host_ip_from_inventory(device_name):
    inventory_path = os.path.join('ansible_project', 'hosts')
    try:
        with open(inventory_path, 'r') as f:
            for line in f:
                if line.strip().startswith(device_name):
                    match = re.search(r'ansible_host=(\S+)', line)
                    if match:
                        return match.group(1)
    except FileNotFoundError:
        return None
    return None

def get_ssh_fingerprint(hostname):
    try:
        keyscan_proc = subprocess.run(['ssh-keyscan', '-t', 'rsa', hostname], capture_output=True, text=True, check=True, timeout=10)
        raw_key = keyscan_proc.stdout.strip()
        if not raw_key:
            return None, None
            
        keygen_proc = subprocess.run(['ssh-keygen', '-lf', '-'], input=raw_key, capture_output=True, text=True, check=True)
        fingerprint = keygen_proc.stdout.strip()
        return raw_key, fingerprint
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        app.logger.error(f"No se pudo obtener la huella de {hostname}: {e}")
        return None, None

@app.route('/api/status/<device_name>')
@login_required
def api_get_device_status(device_name):
    inventory_hosts = parse_inventory()
    if device_name not in inventory_hosts:
        return jsonify({'status': 'offline', 'error': 'Dispositivo no encontrado en el inventario.'}), 404

    playbook_path = os.path.join(LIBRARY_FOLDER, 'A_get_device_details.yml')
    details = {'radios': [], 'interfaces': []}
    ansible_env = get_ansible_env()

    try:
        command = ['ansible-playbook', '-v', '--limit', device_name, playbook_path]
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30, env=ansible_env)

        if "Host Key checking is enabled" in result.stdout:
            host_ip = get_host_ip_from_inventory(device_name)
            if not host_ip:
                return jsonify({'status': 'offline', 'error': 'No se pudo encontrar la IP del host en el inventario.'}), 500

            raw_key, fingerprint = get_ssh_fingerprint(host_ip)
            if not fingerprint:
                return jsonify({'status': 'offline', 'error': f'El host en {host_ip} no responde a la petición de clave SSH.'}), 500

            return jsonify({
                'status': 'untrusted_host',
                'error': 'La clave del host ha cambiado o es la primera vez que se conecta.',
                'fingerprint': fingerprint,
                'raw_key': raw_key,
                'hostname': host_ip,
                'inventory_name': device_name
            }), 200

        if "ERROR!" in result.stdout or result.returncode != 0:
            error_message = "Ansible reportó un error de ejecución."
            if "Authentication failed" in result.stderr or result.returncode == 4: error_message = "Fallo de autenticación."
            elif result.returncode != 0 and "ERROR!" not in result.stdout: error_message = 'El host no responde (Timeout o inalcanzable).'
            
            app.logger.error(f"Error de Ansible para {device_name}: {error_message}\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")
            return jsonify({'status': 'offline', 'error': error_message, 'ansible_stdout': result.stdout, 'ansible_stderr': result.stderr}), 500

        json_string = None
        for line in result.stdout.splitlines():
            if line.strip().startswith(f"ok: [{device_name}] =>"):
                json_string = line.split("=>", 1)[1].strip()
                break
        if not json_string: raise ValueError("No se encontró la línea de resultado JSON en la salida de Ansible.")
        
        ansible_task_result = json.loads(json_string)
        raw_output = ansible_task_result.get('stdout', '')

        for line in raw_output.splitlines():
            if "::" in line:
                key, value = line.split('::', 1)
                key, value = key.strip().lower(), value.strip()
                
                if key == 'interface_info' and '|' in value and '/' in value:
                    iface_name, ip_cidr = value.split('|', 1)
                    ip, cidr_prefix = ip_cidr.split('/', 1)
                    bits = int(cidr_prefix)
                    mask_int = (0xffffffff << (32 - bits)) & 0xffffffff
                    mask = '.'.join([str((mask_int >> i) & 0xff) for i in [24, 16, 8, 0]])
                    details['interfaces'].append({'name': iface_name, 'ip': ip, 'mask': mask})
                
                # ### CAMBIO CLAVE ###: El parser ahora espera 6 campos (5 separadores '|')
                elif key == 'radio_info' and value.count('|') >= 5:
                    radio_name, wifi_gen, ssid, encryption, wifi_key, supported_ciphers = value.split('|', 5)
                    details['radios'].append({
                        'name': radio_name, 
                        'index': int(re.search(r'\d+', radio_name).group()), 
                        'generation': wifi_gen, 
                        'ssid': ssid, 
                        'encryption': encryption,          # <-- ¡Ahora se añade el cifrado!
                        'key': wifi_key,                    # <-- ¡Y la clave!
                        'supported_ciphers': supported_ciphers.split(',')
                    })
                else:
                    details[key] = value

        if not details.get('interfaces'):
            raise ValueError("El dispositivo no devolvió ninguna interfaz de red válida.")

        if details.get('memtotal_kb', '').isdigit(): details['mem_total'] = f"{round(int(details['memtotal_kb']) / 1024)} MB"
        if details.get('memfree_kb', '').isdigit(): details['mem_free'] = f"{round(int(details['memfree_kb']) / 1024)} MB"
        if details.get('dmesg'): details['dmesg'] = details['dmesg'].replace('|', '\n')
        details['status'] = 'online'
        details['inventory_name'] = device_name
        details['hostname'] = details.get('hostname', device_name)
        return jsonify(details)

    except (ValueError, json.JSONDecodeError, AttributeError) as e:
        app.logger.error(f"Error de parseo para el dispositivo {device_name}: {str(e)}")
        return jsonify({'status': 'offline', 'error': 'Los datos recibidos del dispositivo no son válidos.'}), 500
    except Exception as e:
        app.logger.error(f"Error general en la API para {device_name}: {str(e)}")
        return jsonify({'status': 'offline', 'error': 'Ha ocurrido un error inesperado en el servidor.'}), 500

# ### CAMBIO ### - Esta ruta ahora está protegida por CSRF
@app.route('/api/trust_host', methods=['POST'])
@login_required
def trust_host():
    data = request.json
    raw_key = data.get('raw_key')

    if not raw_key or '\n' in raw_key or '\r' in raw_key:
        return jsonify({'success': False, 'error': 'Clave proporcionada no válida.'}), 400

    try:
        home_dir = os.path.expanduser('~')
        ssh_dir = os.path.join(home_dir, '.ssh')
        known_hosts_path = os.path.join(ssh_dir, 'known_hosts')

        if not os.path.exists(ssh_dir):
            os.makedirs(ssh_dir, mode=0o700)
        
        with open(known_hosts_path, 'a') as f:
            f.write(raw_key + '\n')

        app.logger.info(f"Clave para {raw_key.split()[0]} añadida a known_hosts.")
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"No se pudo escribir en known_hosts: {e}")
        return jsonify({'success': False, 'error': 'Error del servidor al intentar guardar la clave.'}), 500

def run_ansible_playbook(playbook_path, target_host, extra_vars=None):
    valid_hosts_lower = [h.lower() for h in parse_inventory()] + ['all']
    targets = target_host.split(',')
    
    if not all(target.strip().lower() in valid_hosts_lower for target in targets):
        return "", f"Error de seguridad: El objetivo '{target_host}' contiene uno o más hosts no válidos."

    try:
        command = ['ansible-playbook', '--limit', target_host, playbook_path]
        if extra_vars:
            # ### CAMBIO ### Usar shlex.quote para cada valor en extra_vars como defensa en profundidad
            # Aunque la validación es la defensa principal, esto nunca está de más.
            safe_extra_vars = {}
            for key, value in extra_vars.items():
                if isinstance(value, str):
                    safe_extra_vars[key] = shlex.quote(value)
                else: # Mantener otros tipos (listas, booleanos) como están
                    safe_extra_vars[key] = value
            command.extend(['--extra-vars', json.dumps(safe_extra_vars)])
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120, env=get_ansible_env())
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.stdout, e.stderr
    except Exception as e:
        app.logger.error(f"Error inesperado ejecutando playbook {playbook_path} en {target_host}: {e}")
        return "", f"Error inesperado del servidor: {str(e)}"

# ### CAMBIO ### - Esta ruta ahora está protegida por CSRF
@app.route('/api/execute_batch_action', methods=['POST'])
@login_required
def execute_batch_action():
    data = request.json
    action, targets, params = data.get('action'), data.get('targets'), data.get('params', {})
    if not targets or not action:
        return jsonify({'error': 'Faltan los objetivos o la acción.'}), 400

    playbook_map = {
        'reboot': 'action_reboot.yml',
        'set_interfaces': 'action_set_one_interface.yml',
        'set_wifi': 'action_set_wifi.yml', # ### CAMBIO ### - Usamos nuestro nuevo playbook
        'set_root_password': 'action_set_root_password.yml',
        'restart_network': '02_reiniciar_red.yml',
    }
    
    if action == 'set_interfaces':
        # ... (lógica de esta acción sin cambios)
        changes = params.get('changes', [])
        if not isinstance(changes, list) or not changes:
            return jsonify({'error': "No se proporcionaron cambios de interfaz."}), 400
        
        for change in changes:
            iface, ip, mask = change.get('iface'), change.get('ip'), change.get('mask')
            if not is_safe_input(iface):
                return jsonify({'error': f"El nombre de interfaz '{iface}' contiene caracteres peligrosos."}), 400
            if not is_valid_ipv4(ip) or not is_safe_input(ip):
                return jsonify({'error': f"La IP '{ip}' no es válida o contiene caracteres peligrosos."}), 400
            if not is_valid_netmask(mask) or not is_safe_input(mask, r'^[0-9\.]+$'):
                return jsonify({'error': f"La máscara '{mask}' no es válida o contiene caracteres peligrosos."}), 400

        full_stdout, full_stderr = "", ""
        playbook_path = os.path.join(LIBRARY_FOLDER, playbook_map['set_interfaces'])
        
        for change in changes:
            extra_vars = {"iface_name": change.get('iface'), "ip": change.get('ip'), "mask": change.get('mask')}
            stdout, stderr = run_ansible_playbook(playbook_path, change.get('device'), extra_vars)
            full_stdout += f"--- Resultado para {change.get('device')} en {change.get('iface')} ---\n{stdout}\n"
            if stderr:
                full_stderr += f"--- Error para {change.get('device')} en {change.get('iface')} ---\n{stderr}\n"

        return jsonify({'output': full_stdout, 'error': full_stderr})

    # ### NUEVO ### - Lógica segura y funcional para 'set_wifi'
    elif action == 'set_wifi':
        ALLOWED_ENCRYPTIONS = [
            'sae', 'sae-mixed',
            'psk2', 'psk2+tkip', 'psk2+tkip+ccmp',
            'psk-mixed', 'psk-mixed+tkip', 'psk-mixed+tkip+ccmp',
            'psk', 'psk+tkip', 'psk+tkip+ccmp',
            'wep-open', 'wep-shared',
            'owe',
            'none'
        ]
        
        changes = params.get('changes', [])
        if not isinstance(changes, list) or not changes:
            return jsonify({'error': "No se proporcionaron cambios de WiFi."}), 400
        
        # Bucle de validación ESTRICTA. Si algo falla, se rechaza toda la petición.
        for change in changes:
            ssid, key, encryption = change.get('ssid'), change.get('key'), change.get('encryption')

            if not is_safe_ssid(ssid):
                return jsonify({'error': f"El SSID '{ssid}' no es válido. Contiene caracteres prohibidos o longitud incorrecta."}), 400
            
            if encryption not in ALLOWED_ENCRYPTIONS:
                return jsonify({'error': f"El tipo de cifrado '{encryption}' no está permitido."}), 400

            # La clave solo es obligatoria si el cifrado no es 'none'
            if encryption != 'none':
                if not is_safe_wifi_key(key):
                    return jsonify({'error': "La contraseña WiFi no es válida. Debe tener entre 8 y 63 caracteres y no puede contener símbolos como ', \", $, ;, etc."}), 400
            else:
                # Si es 'none', nos aseguramos de que la clave sea una cadena vacía para el playbook.
                change['key'] = ''

        # Si todas las validaciones pasan, ejecutamos el playbook.
        # Pasamos la lista completa de cambios como 'radios'. El playbook se encargará de iterar.
        playbook_path = os.path.join(LIBRARY_FOLDER, playbook_map['set_wifi'])
        extra_vars = { "radios": changes }
        
        # 'run_ansible_playbook' ya aplica shlex.quote como defensa en profundidad.
        stdout, stderr = run_ansible_playbook(playbook_path, ",".join(targets), extra_vars)
        return jsonify({'output': stdout.replace('\r', ''), 'error': stderr.replace('\r', '')})
        
    elif action == 'set_root_password':
        password = params.get('new_root_password', '')
        if not is_safe_password(password): 
            return jsonify({'error': "La contraseña no es válida. Debe tener entre 8 y 128 caracteres y solo puede contener letras, números y los siguientes símbolos: !@#$%^&*()-_=+"}), 400
        
        playbook_path = os.path.join(LIBRARY_FOLDER, playbook_map[action])
        stdout, stderr = run_ansible_playbook(playbook_path, ",".join(targets), params)
        return jsonify({'output': stdout.replace('\r', ''), 'error': stderr.replace('\r', '')})
    
    else:
        playbook_name = playbook_map.get(action)
        if not playbook_name: return jsonify({'error': 'Acción no válida.'}), 400
        playbook_path = os.path.join(LIBRARY_FOLDER, playbook_name)
        stdout, stderr = run_ansible_playbook(playbook_path, ",".join(targets), params)
        return jsonify({'output': stdout.replace('\r', ''), 'error': stderr.replace('\r', '')})


# --- BLOQUE DE INICIO ---
if __name__ == '__main__':
    for folder in [UPLOAD_FOLDER, LIBRARY_FOLDER]:
        if not os.path.exists(folder):
            os.makedirs(folder)
    app.run(host='0.0.0.0', port=5000, debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')
