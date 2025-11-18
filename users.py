# Importaciones necesarias para la manipulación de la base de datos y Bcrypt
import sqlite3
import re
import os
from werkzeug.security import generate_password_hash, check_password_hash
# Importamos la instancia de bcrypt desde app.py (esto es necesario para usar bcrypt aquí)
try:
    from app import bcrypt, UserMixin  
except ImportError:
    # Manejo si se ejecuta users.py directamente, aunque en Flask se recomienda el import circular
    # Definimos una clase UserMixin localmente para evitar errores de importación en este contexto
    class UserMixin:
        def is_authenticated(self):
            return True
        def is_active(self):
            return True
        def is_anonymous(self):
            return False
        def get_id(self):
            return str(self.id)
    pass 

# ----------------------------------------------------
#              Funciones de la Base de Datos
# ----------------------------------------------------

# Archivo de bandera para verificar si la tabla ya fue creada
TABLE_CREATED_FLAG = 'database/.table_users_created'
SUPERUSER_EMAIL = 'kenth1977@gmail.com'

def create_user_table(conn):
    """
    Crea la tabla 'users' en la base de datos si no existe.
    
    Args:
        conn (sqlite3.Connection): El objeto de conexión a la base de datos.
    """
    try:
        # Verificar si el archivo de bandera ya existe
        if not os.path.exists(TABLE_CREATED_FLAG):
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario TEXT UNIQUE NOT NULL,
                    nombre TEXT NOT NULL,
                    primer_apellido TEXT NOT NULL,
                    segundo_apellido TEXT,
                    email TEXT UNIQUE NOT NULL,
                    telefono TEXT,
                    password_hash TEXT NOT NULL,
                    rol TEXT NOT NULL DEFAULT 'Usuario', -- Roles: Superusuario, Administrador, Usuario
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            
            # Crear el superusuario por defecto si no existe
            user_data = get_user_by_email(SUPERUSER_EMAIL)
            if not user_data:
                # Usar una contraseña segura por defecto para el primer arranque
                default_password = 'Password123' 
                hashed_password = bcrypt.generate_password_hash(default_password).decode('utf-8')
                
                cursor.execute('''
                    INSERT INTO users (usuario, nombre, primer_apellido, segundo_apellido, email, telefono, password_hash, rol)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', ('superuser', 'Kenth', 'Villalobos', 'Ramirez', SUPERUSER_EMAIL, '8888-8888', hashed_password, 'Superusuario'))
                conn.commit()
                print(f"Superusuario '{SUPERUSER_EMAIL}' creado con contraseña por defecto: '{default_password}'")
            
            # Crear el archivo de bandera
            os.makedirs(os.path.dirname(TABLE_CREATED_FLAG), exist_ok=True)
            with open(TABLE_CREATED_FLAG, 'w') as f:
                f.write('Tabla users creada')
            
            print("Tabla 'users' creada y Superusuario verificado/creado.")
            
    except sqlite3.Error as e:
        print(f"Error de SQLite al crear la tabla 'users' o superusuario: {e}")
    except Exception as e:
        print(f"Error inesperado al crear la tabla 'users' o superusuario: {e}")


def get_db_connection():
    """
    Establece una conexión a la base de datos SQLite.
    
    Returns:
        sqlite3.Connection: El objeto de conexión.
    """
    DB_PATH = 'database/db.db'
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Permite acceder a las columnas por nombre
    return conn

# ----------------------------------------------------
#               Clase User para Flask-Login
# ----------------------------------------------------

class User(UserMixin):
    """Clase para representar a un usuario autenticado en Flask-Login."""
    def __init__(self, id, usuario, nombre, primer_apellido, segundo_apellido, email, telefono, password_hash, rol):
        self.id = id
        self.usuario = usuario
        self.nombre = nombre
        self.primer_apellido = primer_apellido
        self.segundo_apellido = segundo_apellido
        self.email = email
        self.telefono = telefono
        self.password_hash = password_hash
        self.rol = rol

    def get_id(self):
        """Devuelve el ID de usuario como cadena para Flask-Login."""
        return str(self.id)


def get_user_by_id(user_id):
    """
    Busca un usuario por su ID y devuelve una instancia de User o None.
    
    Args:
        user_id (int): El ID del usuario.
        
    Returns:
        User or None: Instancia de User o None si no se encuentra.
    """
    try:
        conn = get_db_connection()
        user_data = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        
        if user_data:
            return User(
                id=user_data['id'],
                usuario=user_data['usuario'],
                nombre=user_data['nombre'],
                primer_apellido=user_data['primer_apellido'],
                segundo_apellido=user_data['segundo_apellido'],
                email=user_data['email'],
                telefono=user_data['telefono'],
                password_hash=user_data['password_hash'],
                rol=user_data['rol']
            )
        return None
    except Exception as e:
        print(f"Error al obtener usuario por ID {user_id}: {e}")
        return None


def get_user_by_email(email):
    """
    Busca un usuario por su email y devuelve los datos brutos.
    
    Args:
        email (str): El email del usuario.
        
    Returns:
        sqlite3.Row or None: Los datos del usuario o None si no se encuentra.
    """
    try:
        conn = get_db_connection()
        user_data = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()
        return user_data
    except Exception as e:
        print(f"Error al obtener usuario por email {email}: {e}")
        return None


# ----------------------------------------------------
#                  Funciones de Lógica
# ----------------------------------------------------

def validate_password(password):
    """
    Valida la complejidad de la contraseña.
    - Mínimo 8 caracteres.
    - Al menos una letra mayúscula.
    - Al menos una letra minúscula.
    - Al menos un número.
    
    Args:
        password (str): La contraseña a validar.
        
    Returns:
        bool: True si es válida, False en caso contrario.
        str: Mensaje de error si es inválida, cadena vacía si es válida.
    """
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe contener al menos una letra mayúscula."
    if not re.search(r'[a-z]', password):
        return False, "La contraseña debe contener al menos una letra minúscula."
    if not re.search(r'[0-9]', password):
        return False, "La contraseña debe contener al menos un número."
        
    return True, ""


def register_user(usuario, nombre, primer_apellido, segundo_apellido, email, telefono, password):
    """
    Registra un nuevo usuario en la base de datos.
    
    Args:
        usuario (str): Nombre de usuario.
        nombre (str): Nombre real.
        primer_apellido (str): Primer apellido.
        segundo_apellido (str): Segundo apellido (opcional).
        email (str): Email.
        telefono (str): Teléfono (opcional).
        password (str): Contraseña sin hashear.
        
    Returns:
        tuple: (bool, str) - Éxito/Fallo y mensaje.
    """
    try:
        # 1. Validar la contraseña
        is_valid, msg = validate_password(password)
        if not is_valid:
            return False, msg

        conn = get_db_connection()
        
        # 2. Verificar si el email o el usuario ya existen
        if get_user_by_email(email):
            conn.close()
            return False, 'Error: El email ya está registrado.'
        
        # Verificar si el nombre de usuario ya existe
        if conn.execute("SELECT id FROM users WHERE usuario = ?", (usuario,)).fetchone():
            conn.close()
            return False, 'Error: El nombre de usuario ya está en uso.'

        # 3. Hashear la contraseña
        # Asegúrate de que bcrypt esté disponible
        if 'bcrypt' not in globals() and 'bcrypt' not in locals():
            try:
                from app import bcrypt 
            except ImportError:
                print("Error: La instancia de bcrypt no está disponible en users.py")
                conn.close()
                return False, 'Error interno: El módulo de encriptación no está disponible.'
                
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # 4. Insertar el nuevo usuario
        conn.execute('''
            INSERT INTO users (usuario, nombre, primer_apellido, segundo_apellido, email, telefono, password_hash, rol)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (usuario, nombre, primer_apellido, segundo_apellido, email, telefono, hashed_password, 'Usuario'))
        
        conn.commit()
        conn.close()
        
        return True, 'Usuario creado exitosamente.'
        
    except sqlite3.Error as e:
        print(f"Error de SQLite al registrar usuario: {e}")
        return False, 'Error de base de datos al registrar usuario.'
    except Exception as e:
        print(f"Error inesperado al registrar usuario: {e}")
        return False, 'Error inesperado al intentar registrar usuario.'


def update_user(user_id, nombre, primer_apellido, segundo_apellido, email, telefono, rol=None):
    """
    Actualiza los datos de un usuario existente.
    
    Args:
        user_id (int): ID del usuario a actualizar.
        nombre (str): Nombre.
        primer_apellido (str): Primer apellido.
        segundo_apellido (str): Segundo apellido.
        email (str): Email.
        telefono (str): Teléfono.
        rol (str, optional): Rol del usuario (solo si se necesita actualizar).
        
    Returns:
        tuple: (bool, str) - Éxito/Fallo y mensaje.
    """
    try:
        conn = get_db_connection()
        
        # 1. Verificar si el nuevo email ya existe en otro usuario
        existing_user = conn.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, user_id)).fetchone()
        if existing_user:
            conn.close()
            return False, 'Error: El nuevo email ya pertenece a otra cuenta.'

        # 2. Construir la consulta de actualización
        params = [nombre, primer_apellido, segundo_apellido, email, telefono]
        query = "UPDATE users SET nombre = ?, primer_apellido = ?, segundo_apellido = ?, email = ?, telefono = ?"

        if rol is not None:
            query += ", rol = ?"
            params.append(rol)
            
        query += " WHERE id = ?"
        params.append(user_id)
        
        # 3. Ejecutar la actualización
        conn.execute(query, params)
        conn.commit()
        conn.close()
        
        return True, 'Información de usuario actualizada exitosamente.'
        
    except sqlite3.Error as e:
        print(f"Error de SQLite al actualizar usuario ID {user_id}: {e}")
        return False, 'Error de base de datos al actualizar usuario.'
    except Exception as e:
        print(f"Error inesperado al actualizar usuario ID {user_id}: {e}")
        return False, 'Error inesperado al intentar actualizar usuario.'


def get_all_users():
    """
    Obtiene todos los usuarios de la base de datos, ordenados por nombre.
    
    Returns:
        list: Lista de objetos sqlite3.Row con los datos de los usuarios.
    """
    try:
        conn = get_db_connection()
        users_data = conn.execute("SELECT id, usuario, nombre, primer_apellido, segundo_apellido, email, telefono, rol FROM users ORDER BY nombre, primer_apellido").fetchall()
        conn.close()
        return users_data
    except Exception as e:
        print(f"Error al obtener todos los usuarios: {e}")
        return []


def delete_user(user_id):
    """
    Elimina un usuario de la base de datos por su ID.
    
    Args:
        user_id (int): ID del usuario a eliminar.
        
    Returns:
        tuple: (bool, str) - Éxito/Fallo y mensaje.
    """
    try:
        conn = get_db_connection()
        # Verificar si el usuario existe antes de intentar eliminar
        user_data = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user_data:
            conn.close()
            return False, 'Error: Usuario no encontrado.'
        
        # Eliminar el usuario
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        return True, 'Usuario eliminado exitosamente.'
        
    except sqlite3.Error as e:
        print(f"Error de SQLite al eliminar usuario ID {user_id}: {e}")
        return False, 'Error de base de datos al eliminar usuario.'
    except Exception as e:
        print(f"Error inesperado al eliminar usuario ID {user_id}: {e}")
        return False, 'Error inesperado al intentar eliminar usuario.'


def change_user_password(user_id, old_password, new_password):
    """
    Cambia la contraseña de un usuario.
    
    Args:
        user_id (int): ID del usuario a modificar.
        old_password (str): Contraseña actual del usuario.
        new_password (str): Nueva contraseña.
        
    Returns:
        tuple: (bool, str) - Éxito/Fallo y mensaje.
    """
    try:
        # 1. Validar la nueva contraseña
        is_valid, msg = validate_password(new_password)
        if not is_valid:
            return False, msg

        conn = get_db_connection()
        
        # Obtener datos del usuario, incluyendo el hash de la contraseña
        user_data = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
        
        if not user_data:
            conn.close()
            return False, 'Error: Usuario no encontrado.'

        # Asegúrate de que bcrypt esté disponible
        if 'bcrypt' not in globals() and 'bcrypt' not in locals():
            try:
                from app import bcrypt # Intento de importación final
            except ImportError:
                print("Error: La instancia de bcrypt no está disponible en users.py")
                conn.close()
                return False, 'Error interno: El módulo de encriptación no está disponible.'
        
        hashed_password_db = user_data['password_hash']
        
        # 2. Verificar la contraseña actual
        if not bcrypt.check_password_hash(hashed_password_db, old_password):
            conn.close()
            return False, 'Error: La contraseña actual es incorrecta.'
            
        # 3. Hashear la nueva contraseña
        new_hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        # 4. Actualizar la contraseña en la base de datos
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hashed_password, user_id))
        conn.commit()
        conn.close()
        
        return True, 'Contraseña actualizada exitosamente. Por favor, vuelve a iniciar sesión.'
        
    except Exception as e:
        # En caso de error inesperado, registrarlo
        print(f"Error al actualizar la contraseña del usuario ID {user_id}: {e}")
        return False, 'Error inesperado al intentar actualizar la contraseña.'