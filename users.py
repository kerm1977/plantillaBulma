# Importaciones necesarias para la manipulación de la base de datos y Bcrypt
import sqlite3
import re
import os
from werkzeug.security import generate_password_hash, check_password_hash
from app import bcrypt  # Importamos la instancia de bcrypt desde app.py

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
            
            # Crear el archivo de bandera para indicar que la tabla ya fue creada
            with open(TABLE_CREATED_FLAG, 'w') as f:
                f.write('Tabla creada')
                
            # Insertar un usuario administrador por defecto
            # Este es un buen punto para que un usuario pueda probar la funcionalidad de administrador
            hashed_password = bcrypt.generate_password_hash("admin123").decode('utf-8')
            conn.execute(
                "INSERT INTO users (nombre, primer_apellido, segundo_apellido, usuario, email, telefono, password, rol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ('Admin', 'PrimerApellido', 'SegundoApellido', 'admin', 'admin@example.com', '12345678', hashed_password, 'Administrador')
            )
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
        from app import get_db_connection
        
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
            return "Error: El nombre y el primer apellido son obligatorios."
        
        # Validación de campos obligatorios
        if not all([nombre, primer_apellido, segundo_apellido, email, telefono, password, verificar_password]):
            return "Error: Todos los campos son obligatorios."

        if password != verificar_password:
            return "Error: Las contraseñas no coinciden."
            
        # Validación de teléfono: solo números y 8 dígitos
        if not re.match(r'^\d{8}$', telefono):
            return "Error: El teléfono debe contener exactamente 8 dígitos numéricos."
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Generar nombre de usuario de forma automática con un sufijo incremental
        base_username = f"{nombre[0]}{primer_apellido}{segundo_apellido}".lower()
        username_to_check = base_username
        counter = 1

        while True:
            # Comprobar si el nombre de usuario ya existe en la base de datos
            cursor.execute("SELECT 1 FROM users WHERE usuario = ?", (username_to_check,))
            if not cursor.fetchone():
                # El nombre de usuario es único, podemos usarlo
                break
            # Si existe, agregar un número para intentar de nuevo
            username_to_check = f"{base_username}{counter}"
            counter += 1
        
        # Encriptar la contraseña
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        try:
            # Ahora, insertar el usuario con el nombre de usuario ya validado
            cursor.execute(
                "INSERT INTO users (nombre, primer_apellido, segundo_apellido, usuario, email, telefono, password) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (nombre, primer_apellido, segundo_apellido, username_to_check, email, telefono, hashed_password)
            )
            conn.commit()
            
            # Obtener el registro completo del usuario recién insertado
            new_user = conn.execute("SELECT * FROM users WHERE usuario = ?", (username_to_check,)).fetchone()
            
            conn.close()
            return new_user

        except sqlite3.IntegrityError as e:
            # Manejo de errores específico para email y teléfono
            error_message = str(e)
            if "email" in error_message:
                return "Error: El correo electrónico ya está registrado."
            elif "telefono" in error_message:
                return "Error: El teléfono ya está registrado."
            else:
                print(f"Error de integridad inesperado: {e}")
                return "Error inesperado al registrar el usuario. Por favor, inténtelo de nuevo más tarde."
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

def find_all_users():
    """
    Busca todos los usuarios en la base de datos.
    
    Returns:
        list: Una lista de objetos sqlite3.Row con todos los usuarios.
    """
    try:
        from app import get_db_connection
        conn = get_db_connection()
        users_data = conn.execute("SELECT * FROM users").fetchall()
        conn.close()
        return users_data
    except Exception as e:
        print(f"Error al buscar todos los usuarios: {e}")
        return []

def update_user(user_id, form_data):
    """
    Actualiza la información de un usuario en la base de datos.
    
    Args:
        user_id (int): El ID del usuario a actualizar.
        form_data (dict): Diccionario con los datos del formulario de edición.
        
    Returns:
        sqlite3.Row or str: El registro del usuario actualizado o un mensaje de error.
    """
    try:
        from app import get_db_connection
        conn = get_db_connection()
        
        # Obtener los datos del formulario de forma segura y validar que no estén vacíos
        nombre = form_data.get('nombre', '').strip().title()
        primer_apellido = form_data.get('primer_apellido', '').strip().title()
        segundo_apellido = form_data.get('segundo_apellido', '').strip().title()
        email = form_data.get('email', '').strip().lower()
        telefono = form_data.get('telefono', '').strip()
        rol = form_data.get('rol', '').strip()

        # Validación de campos obligatorios
        if not nombre:
            return "Error: El nombre es obligatorio."
        if not primer_apellido:
            return "Error: El primer apellido es obligatorio."
        if not segundo_apellido:
            return "Error: El segundo apellido es obligatorio."
        if not email:
            return "Error: El correo electrónico es obligatorio."
        if not telefono:
            return "Error: El teléfono es obligatorio."
        if not rol:
            return "Error: El rol es obligatorio."
            
        # Validación de teléfono
        if not re.match(r'^\d{8}$', telefono):
            return "Error: El teléfono debe contener exactamente 8 dígitos numéricos."
            
        # Verificar si el correo o teléfono ya existen en otro usuario
        existing_user = conn.execute("SELECT id FROM users WHERE (email = ? OR telefono = ?) AND id != ?", (email, telefono, user_id)).fetchone()
        if existing_user:
            return "Error: El correo electrónico o el teléfono ya están en uso por otro usuario."
            
        cursor = conn.cursor()
        
        # No permitir el cambio de rol si es el superusuario fijo
        user_to_edit = find_user_by_id(user_id)
        if user_to_edit and user_to_edit['email'] == SUPERUSER_EMAIL and rol != 'Superusuario':
            return "Error: No se puede cambiar el rol del superusuario principal."
            
        cursor.execute(
            "UPDATE users SET nombre = ?, primer_apellido = ?, segundo_apellido = ?, email = ?, telefono = ?, rol = ? WHERE id = ?",
            (nombre, primer_apellido, segundo_apellido, email, telefono, rol, user_id)
        )
        conn.commit()
        
        updated_user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        
        return updated_user

    except Exception as e:
        print(f"Error al actualizar el usuario: {e}")
        return "Error inesperado al actualizar el usuario. Por favor, inténtelo de nuevo más tarde."
        
def delete_user_by_id(user_id):
    """
    Elimina un usuario de la base de datos por su ID.
    
    Args:
        user_id (int): El ID del usuario a eliminar.
        
    Returns:
        tuple: (True, mensaje de éxito) si se elimina correctamente, o (False, mensaje de error) si falla.
    """
    try:
        from app import get_db_connection
        conn = get_db_connection()
        
        # No permitir la eliminación del único superusuario o si es el superusuario principal
        user_to_delete = find_user_by_id(user_id)
        if user_to_delete and user_to_delete['email'] == SUPERUSER_EMAIL:
            conn.close()
            return False, 'No puedes eliminar al superusuario principal.'

        result = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        if result.rowcount == 1:
            return True, 'Usuario eliminado exitosamente.'
        else:
            return False, 'Usuario no encontrado.'
    except Exception as e:
        print(f"Error al eliminar usuario: {e}")
        return False, 'Error inesperado al eliminar el usuario.'

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
        
        # Normalizar el input del usuario
        user_input = user_input.strip()

        # Usar expresiones regulares para determinar el tipo de entrada
        is_email = re.match(r'^[^@]+@[^@]+\.[^@]+$', user_input)
        is_phone = re.match(r'^\d{8}$', user_input)
        
        # Preparar la consulta de la base de datos basada en el tipo de entrada
        query = ""
        params = ()
        if is_email:
            query = "SELECT * FROM users WHERE email = ?"
            params = (user_input.lower(),)
        elif is_phone:
            query = "SELECT * FROM users WHERE telefono = ?"
            params = (user_input,)
        else: # Si no es un email o un teléfono, se asume que es un nombre de usuario
            query = "SELECT * FROM users WHERE usuario = ?"
            params = (user_input.lower(),)
        
        if not query:
            return None
            
        user_data = cursor.execute(query, params).fetchone()
        conn.close()
        
        if user_data:
            # Compara la contraseña encriptada
            if bcrypt.check_password_hash(user_data['password'], password):
                return user_data
        
        return None
        
    except Exception as e:
        print(f"Error al verificar el usuario: {e}")
        return None

def make_admin_by_email(email):
    """
    Convierte a un usuario existente en administrador buscándolo por correo electrónico.
    
    Args:
        email (str): El correo electrónico del usuario a convertir.
        
    Returns:
        tuple: (True, mensaje de éxito) si la actualización es exitosa, 
               o (False, mensaje de error) si el usuario no es encontrado.
    """
    try:
        from app import get_db_connection
        conn = get_db_connection()
        
        # Buscar el usuario por su correo electrónico
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if user:
            # Actualizar el rol del usuario a 'Administrador'
            conn.execute("UPDATE users SET rol = 'Administrador' WHERE email = ?", (email,))
            conn.commit()
            conn.close()
            return True, f'El usuario con el correo {email} ha sido convertido en Administrador.'
        else:
            conn.close()
            return False, f'Error: No se encontró ningún usuario con el correo {email}.'
            
    except Exception as e:
        print(f"Error al actualizar el rol del usuario: {e}")
        return False, 'Error inesperado al intentar actualizar el rol del usuario.'
        
def make_superuser_by_email(email):
    """
    Convierte a un usuario existente en superusuario buscándolo por correo electrónico.
    
    Args:
        email (str): El correo electrónico del usuario a convertir.
        
    Returns:
        tuple: (True, mensaje de éxito) si la actualización es exitosa, 
               o (False, mensaje de error) si el usuario no es encontrado.
    """
    try:
        from app import get_db_connection
        conn = get_db_connection()
        
        # Buscar el usuario por su correo electrónico
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if user:
            # Actualizar el rol del usuario a 'Superusuario'
            conn.execute("UPDATE users SET rol = 'Superusuario' WHERE email = ?", (email,))
            conn.commit()
            conn.close()
            return True, f'El usuario con el correo {email} ha sido convertido en Superusuario.'
        else:
            conn.close()
            return False, f'Error: No se encontró ningún usuario con el correo {email}.'
            
    except Exception as e:
        print(f"Error al actualizar el rol del usuario: {e}")
        return False, 'Error inesperado al intentar actualizar el rol del usuario.'
