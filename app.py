# ==============================================================================
# ==        app.py - VERSIÓN FINAL, COMPLETA Y FUNCIONAL                      ==
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
from filelock import FileLock
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect

# --- CONFIGURACIÓN DE LA APP Y RUTAS DE ARCHIVOS ---
UPLOAD_FOLDER = 'uploads'
LIBRARY_FOLDER = 'playbook_library'
ALLOWED_EXTENSIONS = {'yml', 'yaml'}
USER_FILE = 'user.json'
USER_FILE_LOCK = 'user.json.lock'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'una-clave-secreta-muy-debil-para-desarrollo')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."
login_manager.login_message_category = "info"

# --- CLASE DE USUARIO ---
class User(UserMixin):
    def __init__(self, id='1', username=None, password_hash=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)
    def save(self):
        with FileLock(USER_FILE_LOCK):
            with open(USER_FILE, 'w') as f:
                json.dump({'username': self.username, 'password_hash': self.password_hash}, f, indent=4)
    @staticmethod
    def get():
        if not os.path.exists(USER_FILE): return None
        with FileLock(USER_FILE_LOCK):
            try:
                with open(USER_FILE, 'r') as f:
                    data = json.load(f)
                    return User(username=data.get('username'), password_hash=data.get('password_hash'))
            except (json.JSONDecodeError, FileNotFoundError): return None

@login_manager.user_loader
def load_user(user_id): return User.get()

# --- FUNCIONES AUXILIARES ---
def allowed_file(filename): return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def get_library_playbooks():
    playbooks = []
    for ext in ('*.yml', '*.yaml'):
        found = glob.glob(os.path.join(LIBRARY_FOLDER, ext))
        playbooks.extend([f for f in found if not os.path.basename(f).startswith(('A_', 'action_'))])
    return sorted([os.path.basename(p) for p in playbooks])
def parse_inventory():
    hosts = []
    try:
        with open(os.path.join('ansible_project', 'hosts'), 'r') as f:
            for line in f:
                if line.strip() and not line.strip().startswith(('#', '[')): hosts.append(line.split()[0])
    except FileNotFoundError: app.logger.error("FATAL: Inventario no encontrado.")
    return hosts
def get_ansible_env():
    env = os.environ.copy()
    env['ANSIBLE_CONFIG'] = os.path.abspath('ansible.cfg')
    return env
def is_safe_input(s, pattern=r'^[a-zA-Z0-9\._-]+$'): return isinstance(s, str) and re.match(pattern, s) is not None
def is_safe_password(p): return isinstance(p, str) and 8 <= len(p) <= 128 and all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+" for c in p)
def is_valid_ipv4(ip):
    try: ipaddress.IPv4Address(ip); return True
    except (ipaddress.AddressValueError, TypeError): return False
def is_valid_netmask(mask):
    if not isinstance(mask, str) or mask.count('.') != 3: return False
    try: return '01' not in ''.join(bin(int(p))[2:].zfill(8) for p in mask.split('.'))
    except (ValueError, TypeError): return False
def is_safe_ssid(s): return isinstance(s, str) and 1 <= len(s) <= 32 and not any(c in "'\"`$;|&\\" for c in s)
def is_safe_wifi_key(k): return isinstance(k, str) and 8 <= len(k) <= 63 and not any(c in "'\"`$;|&\\" for c in k)

# --- RUTAS DE AUTENTICACIÓN Y PERFIL ---
@app.route('/setup')
def setup():
    if User.get(): return redirect(url_for('login'))
    return render_template('setup.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('devices_view'))
    user = User.get()
    if not user: return redirect(url_for('setup'))
    if request.method == 'POST':
        if user.username == request.form.get('username') and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(request.args.get('next') or url_for('devices_view'))
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
        user = User.get()
        if not user.check_password(request.form.get('current_password')): flash('La contraseña actual es incorrecta.', 'danger')
        elif request.form.get('new_password') != request.form.get('confirm_password'): flash('Las nuevas contraseñas no coinciden.', 'danger')
        elif not is_safe_password(request.form.get('new_password')): flash('La nueva contraseña no es válida (8-128 caracteres, sin símbolos extraños).', 'danger')
        else:
            user.set_password(request.form.get('new_password')); user.save()
            flash('¡Contraseña actualizada con éxito!', 'success')
            return redirect(url_for('profile'))
    return render_template('profile.html')

# --- RUTAS PRINCIPALES DE LA APLICACIÓN ---
@app.route('/')
@login_required
def index_redirect(): return redirect(url_for('devices_view'))
@app.route('/devices')
@login_required
def devices_view(): return render_template('devices.html')
@app.route('/actions')
@login_required
def actions_view(): return render_template('actions.html', routers=parse_inventory())
@app.route('/execute', methods=['GET', 'POST'])
@login_required
def execute_view():
    output, error, p_path = None, None, None
    if request.method == 'POST':
        target = request.form.get('target')
        action = request.form.get('submit_action')
        if action == 'library':
            p_name = secure_filename(request.form.get('playbook_name'))
            p_path = os.path.join(LIBRARY_FOLDER, p_name)
            if not os.path.exists(p_path): error, p_path = "Playbook no encontrado.", None
        elif action == 'upload':
            file = request.files.get('playbook_file')
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                p_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(p_path)
            else: error = "Archivo no permitido o no seleccionado."
        if p_path and not error:
            raw_out, raw_err = run_ansible_playbook(p_path, target)
            output, error = (raw_out.replace('\r', '') if raw_out else None), (raw_err.replace('\r', '') if raw_err else None)
    return render_template('execute.html', routers=parse_inventory(), library_playbooks=get_library_playbooks(), output=output, error=error)

# --- RUTAS DE API ---
@app.route('/api/devices')
@login_required
def api_get_devices(): return jsonify(parse_inventory())
def get_host_ip_from_inventory(device_name):
    try:
        with open(os.path.join('ansible_project', 'hosts'), 'r') as f:
            for line in f:
                if line.strip().startswith(device_name):
                    match = re.search(r'ansible_host=(\S+)', line)
                    if match: return match.group(1)
    except FileNotFoundError: return None
    return None
def get_ssh_fingerprint(hostname):
    try:
        keyscan = subprocess.run(['ssh-keyscan', '-t', 'rsa', hostname], capture_output=True, text=True, check=True, timeout=10)
        if not keyscan.stdout.strip(): return None, None
        keygen = subprocess.run(['ssh-keygen', '-lf', '-'], input=keyscan.stdout, capture_output=True, text=True, check=True)
        return keyscan.stdout.strip(), keygen.stdout.strip()
    except Exception as e: app.logger.error(f"Error en get_ssh_fingerprint para {hostname}: {e}"); return None, None
@app.route('/api/status/<device_name>')
@login_required
def api_get_device_status(device_name):
    if device_name not in parse_inventory(): return jsonify({'status': 'offline', 'error': 'Dispositivo no en inventario.'}), 404
    playbook_path = os.path.join(LIBRARY_FOLDER, 'A_get_device_details.yml')
    details = {'radios': [], 'interfaces': []}
    try:
        cmd = ['ansible-playbook', '-v', '--limit', device_name, playbook_path]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=30, env=get_ansible_env())
        if "Host Key checking is enabled" in result.stdout:
            host_ip = get_host_ip_from_inventory(device_name)
            if not host_ip: return jsonify({'status': 'offline', 'error': 'No se pudo encontrar la IP del host.'}), 500
            raw_key, fingerprint = get_ssh_fingerprint(host_ip)
            if not fingerprint: return jsonify({'status': 'offline', 'error': f'Host {host_ip} no responde.'}), 500
            return jsonify({'status': 'untrusted_host', 'error': 'Verificación de host requerida.', 'fingerprint': fingerprint, 'raw_key': raw_key, 'hostname': host_ip, 'inventory_name': device_name}), 200
        if "ERROR!" in result.stdout or result.returncode != 0:
            err_msg = "Error de ejecución de Ansible."
            if "Authentication failed" in result.stderr or "FAILED!" in result.stdout: err_msg = "Fallo de autenticación."
            elif result.returncode != 0: err_msg = 'El host no responde (Timeout).'
            app.logger.error(f"Error Ansible para {device_name}:\nSTDOUT:{result.stdout}\nSTDERR:{result.stderr}")
            return jsonify({'status': 'offline', 'error': err_msg, 'ansible_stdout': result.stdout, 'ansible_stderr': result.stderr}), 500
        json_str = next((line.split("=>", 1)[1].strip() for line in result.stdout.splitlines() if line.strip().startswith(f"ok: [{device_name}] =>")), None)
        if not json_str: raise ValueError("No se encontró salida JSON en Ansible.")
        raw_output = json.loads(json_str).get('stdout', '')
        for line in raw_output.splitlines():
            if "::" in line:
                key, value = map(str.strip, line.split('::', 1))
                if key.lower() == 'interface_info' and '|' in value and '/' in value:
                    iface_name, ip_cidr = value.split('|', 1)
                    ip, cidr = ip_cidr.split('/', 1)
                    mask_int = (0xffffffff << (32 - int(cidr))) & 0xffffffff
                    mask = '.'.join([str((mask_int >> i) & 0xff) for i in [24, 16, 8, 0]])
                    details['interfaces'].append({'name': iface_name, 'ip': ip, 'mask': mask})
                elif key.lower() == 'radio_info' and value.count('|') >= 6:
                    r_name, r_gen, r_ssid, r_enc, r_key, r_ciphers, r_sec = value.split('|', 6)
                    details['radios'].append({'name': r_name, 'index': r_sec, 'generation': r_gen, 'ssid': r_ssid, 'encryption': r_enc, 'key': r_key, 'supported_ciphers': r_ciphers.split(',')})
                else: details[key.lower()] = value
        if not details.get('interfaces'): raise ValueError("No se devolvieron interfaces válidas.")
        details.update({'status': 'online', 'inventory_name': device_name, 'hostname': details.get('hostname', device_name)})
        return jsonify(details)
    except Exception as e:
        app.logger.error(f"Excepción en api_get_device_status para {device_name}: {e}", exc_info=True)
        return jsonify({'status': 'offline', 'error': 'Error interno del servidor.'}), 500
@app.route('/api/trust_host', methods=['POST'])
@login_required
def trust_host():
    raw_key = request.json.get('raw_key')
    if not raw_key or '\n' in raw_key: return jsonify({'success': False, 'error': 'Clave no válida.'}), 400
    try:
        known_hosts_path = os.path.expanduser('~/.ssh/known_hosts')
        os.makedirs(os.path.dirname(known_hosts_path), mode=0o700, exist_ok=True)
        with open(known_hosts_path, 'a') as f: f.write(raw_key + '\n')
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500
def run_ansible_playbook(playbook_path, target, extra_vars=None):
    if not all(t.strip().lower() in [h.lower() for h in parse_inventory()] + ['all'] for t in target.split(',')):
        return "", f"Error de seguridad: '{target}' no es un objetivo válido."
    try:
        cmd = ['ansible-playbook', '--limit', target, playbook_path]
        if extra_vars: cmd.extend(['--extra-vars', json.dumps(extra_vars)])
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120, env=get_ansible_env())
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e: return e.stdout, e.stderr
    except Exception as e: return "", f"Error de servidor ejecutando playbook: {e}"
@app.route('/api/execute_batch_action', methods=['POST'])
@login_required
def execute_batch_action():
    data = request.json
    action, targets, params = data.get('action'), data.get('targets'), data.get('params', {})
    if not action or not targets: return jsonify({'error': 'Faltan parámetros.'}), 400
    playbook_map = {'reboot': 'action_reboot.yml', 'set_interfaces': 'action_set_one_interface.yml', 'set_wifi': 'action_set_wifi.yml', 'set_root_password': 'action_set_root_password.yml', 'restart_network': '02_reiniciar_red.yml'}
    playbook_name = playbook_map.get(action)
    if not playbook_name: return jsonify({'error': 'Acción no válida.'}), 400
    playbook_path = os.path.join(LIBRARY_FOLDER, playbook_name)
    
    # --- INICIO DE LA MODIFICACIÓN ---
    # Normalizamos las variables para los playbooks que esperan una lista de cambios.
    if action == 'set_wifi':
        extra_vars = {"radios": params.get('changes')}
    elif action == 'set_interfaces':
        extra_vars = {"changes": params.get('changes')}
    else:
        extra_vars = params
    # --- FIN DE LA MODIFICACIÓN ---

    stdout, stderr = run_ansible_playbook(playbook_path, ",".join(targets), extra_vars)
    return jsonify({'output': stdout.replace('\r', ''), 'error': stderr.replace('\r', '')})

# --- BLOQUE DE INICIO ---
if __name__ == '__main__':
    for folder in [UPLOAD_FOLDER, LIBRARY_FOLDER]:
        if not os.path.exists(folder): os.makedirs(folder)
    app.run(host='0.0.0.0', port=5000, debug=True)
