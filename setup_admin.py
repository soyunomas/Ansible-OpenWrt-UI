import json
from getpass import getpass
from werkzeug.security import generate_password_hash
from filelock import FileLock

USER_FILE = 'user.json'
USER_FILE_LOCK = 'user.json.lock'

def main():
    print("--- Configuración del Administrador de Ansible-OpenWrt-UI ---")
    
    if os.path.exists(USER_FILE):
        print("\nADVERTENCIA: Ya existe un archivo de usuario.")
        overwrite = input("¿Deseas reemplazarlo? Se perderá el acceso con la contraseña anterior. (s/N): ")
        if overwrite.lower() != 's':
            print("Operación cancelada.")
            return

    username = input("Introduce el nombre de usuario para el administrador: ")
    if not username:
        print("El nombre de usuario no puede estar vacío.")
        return

    password = getpass("Introduce la contraseña (mínimo 8 caracteres): ")
    password_confirm = getpass("Confirma la contraseña: ")

    if password != password_confirm:
        print("Las contraseñas no coinciden.")
        return
    
    if len(password) < 8:
        print("La contraseña debe tener al menos 8 caracteres.")
        return

    password_hash = generate_password_hash(password)
    user_data = {
        'username': username,
        'password_hash': password_hash
    }

    try:
        with FileLock(USER_FILE_LOCK):
            with open(USER_FILE, 'w') as f:
                json.dump(user_data, f, indent=4)
        print(f"\n¡Éxito! El usuario administrador '{username}' ha sido configurado en {USER_FILE}.")
        print("Ya puedes iniciar la aplicación con 'python app.py'.")
    except Exception as e:
        print(f"\nError: No se pudo escribir el archivo de usuario. {e}")

if __name__ == '__main__':
    import os
    main()
