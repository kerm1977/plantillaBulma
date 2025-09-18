# Importaciones necesarias para la manipulación de la base de datos y Bcrypt
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------------------------------------
#              Funciones de la Base de Datos
# ----------------------------------------------------

def create_user_table(conn):
    """
    Crea la tabla 'users' en la base de datos si no existe.
    
    Args:
        conn (sqlite3.Connection): El objeto de conexión a la base de datos.
    """
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                primer_apellido TEXT NOT NULL,
                segundo_apellido TEXT NOT NULL,
                usuario TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                telefono TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                rol TEXT NOT NULL DEFAULT 'Usuario Regular'
            )
        ''')
        conn.commit()
        print("Tabla 'users' creada o ya existe.")
    except sqlite3.Error as e:
        print(f"Error al crear la tabla: {e}")

def add_new_user(form_data):
    """
    Añade un nuevo usuario a la base de datos.

    Genera un nombre de usuario a partir de las iniciales y encripta la contraseña.
    
    Args:
        form_data (dict): Un diccionario con los datos del formulario de registro.
        
    Returns:
        sqlite3.Row or str or None: El registro del nuevo usuario si se crea correctamente,
                                     o un mensaje de error si falla.
    """
    try:
        # Importación diferida para evitar dependencia circular.
        from app import get_db_connection, bcrypt 
        
        # Obtener y limpiar datos del formulario
        nombre = form_data.get('nombre', '').strip().title()
        primer_apellido = form_data.get('primer_apellido', '').strip().title()
        segundo_apellido = form_data.get('segundo_apellido', '').strip().title()
        email = form_data.get('email', '').strip().lower()
        telefono = form_data.get('telefono', '').strip()
        password = form_data.get('password', '')
        verificar_password = form_data.get('verificar_password', '')

        # Validación: El nombre y el primer apellido no pueden estar vacíos
        if not nombre or not primer_apellido:
            print("Error: El nombre y el primer apellido no pueden estar vacíos.")
            return "Error: El nombre y el primer apellido no pueden estar vacíos."
        
        # Validación básica de datos
        if not all([nombre, primer_apellido, segundo_apellido, email, telefono, password, verificar_password]):
            print("Error: Todos los campos son obligatorios.")
            return "Error: Todos los campos son obligatorios."

        if password != verificar_password:
            print("Error: Las contraseñas no coinciden.")
            return "Error: Las contraseñas no coinciden."
            
        # Validación de teléfono: solo números y 8 dígitos
        if not re.match(r'^\d{8}$', telefono):
            print("Error: El teléfono debe contener exactamente 8 dígitos numéricos.")
            return "Error: El teléfono debe contener exactamente 8 dígitos numéricos."

        # Generar nombre de usuario de forma automática
        # Se toma la primera letra del nombre, el primer apellido completo y el segundo apellido completo
        # Se añaden los últimos 4 dígitos del teléfono para hacerlo más único
        username_part1 = nombre[0] if nombre else ''
        username_part2 = primer_apellido.replace(' ', '')
        username_part3 = segundo_apellido.replace(' ', '')
        usuario = f"{username_part1}{username_part2}{username_part3}{telefono[-4:]}".lower()
        
        # Encriptar la contraseña
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO users (nombre, primer_apellido, segundo_apellido, usuario, email, telefono, password) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (nombre, primer_apellido, segundo_apellido, usuario, email, telefono, hashed_password)
        )
        conn.commit()
        
        # Obtener el registro del usuario recién insertado
        user_id = cursor.lastrowid
        new_user = cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        
        conn.close()
        return new_user

    except sqlite3.IntegrityError as e:
        if "usuario" in str(e):
            return "Error: El nombre de usuario ya está registrado."
        elif "email" in str(e):
            return "Error: El correo electrónico ya está registrado."
        elif "telefono" in str(e):
            return "Error: El teléfono ya está registrado."
        else:
            return "Error: El correo electrónico, usuario o teléfono ya están registrados."
    except Exception as e:
        print(f"Error inesperado al registrar el usuario: {e}")
        return "Error inesperado al registrar el usuario. Por favor, inténtelo de nuevo más tarde."

def find_user_by_id(user_id):
    """
    Busca un usuario en la base de datos por su ID.
    
    Args:
        user_id (int): El ID del usuario.
        
    Returns:
        sqlite3.Row or None: El registro del usuario si se encuentra, de lo contrario None.
    """
    try:
        from app import get_db_connection
        conn = get_db_connection()
        user_data = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        return user_data
    except Exception as e:
        print(f"Error al buscar usuario por ID: {e}")
        return None

def verify_user(user_input, password):
    """
    Verifica las credenciales de inicio de sesión de un usuario.
    
    Busca al usuario por su nombre de usuario, correo electrónico o teléfono.
    
    Args:
        user_input (str): Nombre de usuario, email o teléfono del usuario.
        password (str): La contraseña proporcionada por el usuario.
        
    Returns:
        sqlite3.Row or None: El registro del usuario si las credenciales son válidas,
                              de lo contrario None.
    """
    try:
        from app import get_db_connection, bcrypt
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Busca por usuario, email o teléfono
        user_data = cursor.execute(
            "SELECT * FROM users WHERE usuario = ? OR email = ? OR telefono = ?",
            (user_input.lower(), user_input.lower(), user_input)
        ).fetchone()
        
        conn.close()
        
        if user_data:
            # Compara la contraseña encriptada
            if bcrypt.check_password_hash(user_data['password'], password):
                return user_data
        
        return None
        
    except Exception as e:
        print(f"Error al verificar el usuario: {e}")
        return None
