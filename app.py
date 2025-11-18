# Importaciones necesarias para la aplicación Flask
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, g, session
from flask_bcrypt import Bcrypt
import sqlite3
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Importa las funciones del módulo de users.py
import users as user_module

# ----------------------------------------------------
#               Configuración de la Aplicación
# ----------------------------------------------------

# Inicializa la aplicación Flask
app = Flask(__name__, static_folder='static', template_folder='templates')

# Configuración de la aplicación
app.secret_key = os.urandom(24)  # Clave secreta para las sesiones
app.config.update(
    SESSION_COOKIE_NAME='plantilla_session',
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hora
    SESSION_COOKIE_SECURE=False,      # Cambiar a True en producción con HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_REFRESH_EACH_REQUEST=True
)

# Inicializa Bcrypt para el hash de contraseñas
bcrypt = Bcrypt(app)

# Configura Flask-Login para el manejo de sesiones de usuario
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # La vista a la que redirige si no está logueado
login_manager.login_message_category = 'warning'
login_manager.login_message = 'Por favor, inicia sesión para acceder a esta página.'

# ----------------------------------------------------
#              Configuración de la Base de Datos
# ----------------------------------------------------


# Variable para almacenar la ruta de la base de datos
DB_PATH = 'database/db.db'

def get_db_connection():
    """
    Establece una conexión a la base de datos SQLite y configura el acceso a las filas por nombre.
    """
    # Asegúrate de que el directorio exista
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row # Permite acceder a las columnas por nombre
    return conn

# ----------------------------------------------------
#               Clase de Usuario
# ----------------------------------------------------

class User(UserMixin):
    """
    Clase de usuario para Flask-Login.
    """
    def __init__(self, id, usuario, nombre, primer_apellido, segundo_apellido, email, telefono, rol, password_hash=None):
        self.id = id
        self.usuario = usuario
        self.nombre = nombre
        self.primer_apellido = primer_apellido
        self.segundo_apellido = segundo_apellido
        self.email = email
        self.telefono = telefono
        self.rol = rol
        self.password_hash = password_hash

    # Método requerido por Flask-Login para obtener el ID de usuario
    def get_id(self):
        return str(self.id)

# ----------------------------------------------------
#               Funciones de Usuario y Login
# ----------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    """
    Cargador de usuario para Flask-Login.
    """
    if not user_id or not str(user_id).isdigit():
        print(f"ID de usuario inválido: {user_id}")
        return None
    
    try:
        # Usar la función get_user_by_id del módulo users
        user_dict = user_module.get_user_by_id(user_id)
        
        if not user_dict:
            print(f"No se encontró el usuario con ID: {user_id}")
            return None
            
        # Verificar que los campos requeridos estén presentes
        if 'id' not in user_dict or not user_dict['id']:
            print(f"Datos de usuario incompletos para ID: {user_id}")
            return None
            
        # Crear una instancia de User con los datos del diccionario
        user = User(
            id=user_dict['id'],
            usuario=user_dict.get('usuario', ''),
            nombre=user_dict.get('nombre', ''),
            primer_apellido=user_dict.get('primer_apellido', ''),
            segundo_apellido=user_dict.get('segundo_apellido', ''),
            email=user_dict.get('email', ''),
            telefono=user_dict.get('telefono', ''),
            rol=user_dict.get('rol', 'Usuario'),
            password_hash=user_dict.get('password_hash')
        )
        
        print(f"Usuario cargado exitosamente: {user.id} - {user.email}")
        return user
        
    except Exception as e:
        print(f"Error en load_user para ID {user_id}: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

@app.before_request
def create_tables():
    """
    Asegura que la tabla de usuarios exista antes de la primera solicitud.
    """
    conn = get_db_connection()
    user_module.create_user_table(conn)
    conn.close()


# ----------------------------------------------------
#                   Rutas de la Aplicación
# ----------------------------------------------------

@app.route('/')
def index():
    """
    Ruta principal (Home).
    """
    # Si el usuario está autenticado, redirige a 'dashboard', sino a 'login'.
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Ruta para el inicio de sesión.
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Por favor ingresa tu correo electrónico y contraseña.', 'danger')
            return render_template('login.html')
            
        try:
            # Verificar si es el superusuario
            if email == 'kenth1977@gmail.com':
                print("Intento de inicio de sesión como superusuario detectado")
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
                    existing_user = cursor.fetchone()
                    
                    # Convertir a diccionario para manejo más seguro
                    user_dict = None
                    if existing_user:
                        user_dict = dict(zip([column[0] for column in cursor.description], existing_user))
                        print(f"Datos del superusuario encontrados: {user_dict}")
                    else:
                        print("No se encontró el superusuario en la base de datos")
                    
                    if not user_dict:
                        # Crear el superusuario si no existe
                        try:
                            hashed_password = bcrypt.generate_password_hash('CR129x7848n').decode('utf-8')
                            cursor.execute('''
                                INSERT INTO users (usuario, email, password_hash, rol, nombre, primer_apellido)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (
                                'kenth1977',  # Nombre de usuario
                                email,
                                hashed_password,
                                'Superusuario',  # Rol de superusuario
                                'Kent',         # Nombre
                                'Admin'         # Apellido
                            ))
                            conn.commit()
                            print("Superusuario creado exitosamente")
                            # Obtener el ID del usuario recién creado
                            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
                            existing_user = cursor.fetchone()
                            user_dict = dict(zip([column[0] for column in cursor.description], existing_user))
                        except Exception as e:
                            flash(f'Error al crear el superusuario: {str(e)}', 'danger')
                            return render_template('login.html')
                    
                    try:
                        print("Verificando credenciales del superusuario...")
                        
                        # Verificar la contraseña directamente (solo para superusuario)
                        if password != 'CR129x7848n':
                            flash('Contraseña incorrecta para el superusuario.', 'danger')
                            print("Contraseña incorrecta para el superusuario")
                            return render_template('login.html')
                        
                        print("Contraseña correcta, actualizando rol si es necesario...")
                        
                        # Asegurarse de que el rol sea Superusuario
                        if 'rol' not in user_dict or user_dict.get('rol') != 'Superusuario':
                            print("Actualizando rol a Superusuario...")
                            cursor.execute("""
                                UPDATE users 
                                SET rol = 'Superusuario'
                                WHERE email = ?
                            """, (email,))
                            conn.commit()
                            user_dict['rol'] = 'Superusuario'
                        
                        print("Creando objeto User...")
                        # Crear objeto User para el superusuario
                        user = User(
                            id=user_dict.get('id'),
                            usuario=user_dict.get('usuario', 'kenth1977'),
                            nombre=user_dict.get('nombre', 'Kent'),
                            primer_apellido=user_dict.get('primer_apellido', 'Admin'),
                            segundo_apellido=user_dict.get('segundo_apellido', ''),
                            email=email,
                            telefono=user_dict.get('telefono', ''),
                            rol='Superusuario',
                            password_hash=user_dict.get('password_hash', '')
                        )
                        
                        print("Cerrando cualquier sesión existente...")
                        # Forzar cierre de cualquier sesión existente
                        logout_user()
                        
                        print("Iniciando nueva sesión...")
                        # Iniciar sesión con el usuario
                        login_user(user, remember=True)
                        
                        # Configurar la sesión
                        from flask import session
                        session.permanent = True
                        
                        print(f"Sesión de superusuario iniciada: {user.id} - {user.email}")
                        print(f"Usuario autenticado: {current_user.is_authenticated}")
                        
                        flash('¡Bienvenido Superusuario!', 'success')
                        next_page = request.args.get('next') or url_for('dashboard')
                        print(f"Redirigiendo a: {next_page}")
                        return redirect(next_page)
                        
                    except Exception as e:
                        flash(f'Error al verificar la contraseña del superusuario: {str(e)}', 'danger')
                        return render_template('login.html')

            # Para usuarios normales
            with get_db_connection() as conn:
                user_data = user_module.get_user_by_email(email, conn)
                
                if user_data:
                    # Convertir a diccionario para manejo más seguro
                    user_dict = dict(zip(user_data.keys(), user_data)) if user_data else None
                    
                    if not user_dict or 'password_hash' not in user_dict or not user_dict['password_hash']:
                        flash('Error en la configuración de la cuenta. Por favor, contacte al administrador.', 'danger')
                        return render_template('login.html')
                    
                    # Verificar el formato del hash de la contraseña
                    password_hash = user_dict['password_hash']
                    if not isinstance(password_hash, str) or not password_hash.startswith(('$2b$', '$2a$')):
                        # Si el hash no es válido, forzar el restablecimiento de la contraseña
                        flash('Se requiere restablecer la contraseña. Por favor, contacte al administrador.', 'danger')
                        return render_template('login.html')
                    
                    try:
                        # Verificar la contraseña
                        if bcrypt.check_password_hash(password_hash, password):
                            # Reconstruir el objeto User solo si la contraseña es correcta
                            try:
                                user = User(
                                    id=user_dict.get('id'),
                                    usuario=user_dict.get('usuario', ''),
                                    nombre=user_dict.get('nombre', ''),
                                    primer_apellido=user_dict.get('primer_apellido', ''),
                                    segundo_apellido=user_dict.get('segundo_apellido', ''),
                                    email=email,
                                    telefono=user_dict.get('telefono', ''),
                                    rol=user_dict.get('rol', 'Usuario'),
                                    password_hash=password_hash
                                )
                                
                                # Verificar que el usuario tenga un ID válido
                                if not user.id:
                                    flash('Error: ID de usuario no válido.', 'danger')
                                    return render_template('login.html')
                                
                                # Intentar hacer login
                                # Forzar el cierre de cualquier sesión existente
                                logout_user()
                                
                                # Iniciar nueva sesión
                                login_user(user, remember=True)
                                
                                # Configurar la sesión para que dure más tiempo
                                session.permanent = True
                                
                                print(f"Usuario autenticado: {user.id} - {user.email}")
                                print(f"Sesión iniciada: {current_user.is_authenticated}")
                                
                                # Verificar si el usuario está autenticado antes de redirigir
                                if current_user.is_authenticated:
                                    flash('Inicio de sesión exitoso.', 'success')
                                    next_page = request.args.get('next')
                                    return redirect(next_page or url_for('dashboard'))
                                else:
                                    flash('Error al iniciar sesión. Por favor, intente nuevamente.', 'danger')
                                    return render_template('login.html')
                                
                            except Exception as e:
                                print(f"Error al crear el objeto User: {str(e)}")
                                flash('Error al iniciar sesión. Por favor, intente nuevamente.', 'danger')
                                return render_template('login.html')
                        else:
                            flash('Contraseña incorrecta.', 'danger')
                    except ValueError as e:
                        if 'Invalid salt' in str(e):
                            flash('Error en la configuración de la contraseña. Por favor, contacte al administrador.', 'danger')
                        else:
                            flash(f'Error al verificar la contraseña: {str(e)}', 'danger')
                            
                else:
                    flash('No se encontró ninguna cuenta con ese correo electrónico.', 'danger')
        
        except Exception as e:
            flash(f'Error al iniciar sesión: {str(e)}', 'danger')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """
    Ruta para cerrar la sesión.
    """
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Ruta del panel de control.
    """
    # Obtener estadísticas de usuarios
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Obtener total de usuarios
    cursor.execute("SELECT COUNT(*) FROM users")
    total_usuarios = cursor.fetchone()[0]
    
    # Obtener conteo por roles
    cursor.execute("SELECT rol, COUNT(*) as count FROM users GROUP BY rol")
    role_counts = cursor.fetchall()
    
    # Inicializar contadores
    admin_count = 0
    superuser_count = 0
    user_count = 0
    
    # Procesar los resultados
    for role, count in role_counts:
        if role == 'Administrador':
            admin_count = count
        elif role == 'Superusuario':
            superuser_count = count
        else:
            user_count += count  # Sumar otros roles a usuarios normales
    
    conn.close()
    
    return render_template('dashboard.html',
                         total_usuarios=total_usuarios,
                         admin_count=admin_count,
                         superuser_count=superuser_count,
                         user_count=user_count)

@app.route('/perfil')
@login_required
def perfil():
    """
    Ruta para ver el perfil del usuario actual.
    """
    # current_user es proporcionado por Flask-Login
    return render_template('perfil.html', user=current_user)

@app.route('/usuarios', methods=['GET'])
@login_required
def usuarios():
    """
    Ruta para listar todos los usuarios (solo si el rol es Admin o Superusuario).
    """
    if current_user.rol not in ['Administrador', 'Superusuario']:
        flash('Acceso denegado: Se requiere un rol de Administrador o Superusuario.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    users_list = user_module.get_all_users(conn)
    conn.close()
    
    # Mapea los campos de la base de datos a los parámetros del constructor de User
    users_objects = []
    for user_data in users_list:
        user_dict = dict(user_data)
        # Asegurarse de que todos los campos requeridos estén presentes
        user_obj = User(
            id=user_dict['id'],
            usuario=user_dict.get('usuario', ''),
            nombre=user_dict.get('nombre', ''),
            primer_apellido=user_dict.get('primer_apellido', ''),
            segundo_apellido=user_dict.get('segundo_apellido', ''),
            email=user_dict.get('email', ''),
            telefono=user_dict.get('telefono', ''),
            rol=user_dict.get('rol', 'Usuario'),
            password_hash=user_dict.get('password_hash')
        )
        users_objects.append(user_obj)

    return render_template('ver_usuarios.html', users=users_objects)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    """
    Ruta para que los nuevos usuarios se registren.
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Recolectar datos del formulario
        data = {
            'usuario': request.form.get('usuario'),
            'nombre': request.form.get('nombre'),
            'primer_apellido': request.form.get('primer_apellido'),
            'segundo_apellido': request.form.get('segundo_apellido', ''),
            'email': request.form.get('email'),
            'telefono': request.form.get('telefono', ''),
            'password': request.form.get('password'),
            'rol': 'Usuario',  # Rol por defecto para nuevos registros
        }

        # Validar y crear usuario
        is_created, message = user_module.create_new_user(data, bcrypt)

        if is_created:
            flash(message, 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'danger')
            
    return render_template('registro.html')

@app.route('/usuarios/crear', methods=['GET', 'POST'])
@login_required
def crear_usuarios():
    """
    Ruta para que los administradores creen nuevos usuarios.
    Solo accesible para administradores.
    """
    if current_user.rol not in ['Administrador', 'Superusuario']:
        flash('Acceso denegado: Se requiere un rol de Administrador o Superusuario para crear usuarios.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Recolectar datos del formulario
        data = {
            'usuario': request.form.get('usuario'),
            'nombre': request.form.get('nombre'),
            'primer_apellido': request.form.get('primer_apellido'),
            'segundo_apellido': request.form.get('segundo_apellido', ''),
            'email': request.form.get('email'),
            'telefono': request.form.get('telefono', ''),
            'password': request.form.get('password'),
            'rol': request.form.get('rol', 'Usuario'),  # Rol por defecto
        }

        # Validar y crear usuario
        is_created, message = user_module.create_new_user(data, bcrypt)

        if is_created:
            flash(message, 'success')
            return redirect(url_for('usuarios'))
        else:
            flash(message, 'danger')
            
    return render_template('crear_usuarios.html')

@app.route('/usuarios/<int:user_id>/editar', methods=['GET', 'POST'])
@login_required
def editar_usuario(user_id):
    """
    Ruta para editar el perfil de un usuario específico.
    Solo el dueño del perfil o un Admin/Superusuario puede editar.
    """
    conn = get_db_connection()
    user_data = user_module.get_user_by_id(conn, user_id)
    conn.close()

    if not user_data:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('usuarios'))

    user_to_edit = User(**user_data)
    is_owner = current_user.id == user_to_edit.id
    is_authorized = is_owner or current_user.rol in ['Administrador', 'Superusuario']

    if not is_authorized:
        flash('Acceso denegado: No tienes permiso para editar este perfil.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Recolectar datos del formulario (la contraseña no se edita aquí)
        data = {
            'nombre': request.form.get('nombre'),
            'primer_apellido': request.form.get('primer_apellido'),
            'segundo_apellido': request.form.get('segundo_apellido'),
            'email': request.form.get('email'),
            'telefono': request.form.get('telefono'),
            # El rol solo se actualiza si NO es el dueño y tiene permisos (Admin/Superuser)
            'rol': request.form.get('rol') if not is_owner and current_user.rol in ['Administrador', 'Superusuario'] else user_to_edit.rol
        }

        # Si el usuario es Superusuario y está editando a otro Superusuario, 
        # y no es el dueño, se le bloquea el cambio de rol
        if user_to_edit.rol == 'Superusuario' and user_to_edit.id != current_user.id and current_user.rol != 'Superusuario':
            data['rol'] = user_to_edit.rol # Mantener el rol original

        is_updated, message = user_module.update_user_profile(user_id, data)

        if is_updated:
            # Si el usuario se edita a sí mismo, debe recargarse el objeto current_user en la sesión
            if is_owner:
                # Flask-Login recargará el usuario en la próxima solicitud (llama a load_user)
                pass 
            flash(message, 'success')
            return redirect(url_for('perfil') if is_owner else url_for('usuarios'))
        else:
            flash(message, 'danger')
    
    # Para GET o error de POST, renderiza el formulario con los datos actuales
    return render_template('editar_usuarios.html', user=user_to_edit, is_owner=is_owner)

@app.route('/usuarios/<int:user_id>/detalle')
@login_required
def detalle_usuario(user_id):
    """
    Ruta para ver los detalles de un usuario.
    Solo Admin/Superusuario o el dueño del perfil pueden ver los detalles.
    """
    conn = get_db_connection()
    user_data = user_module.get_user_by_id(conn, user_id)
    conn.close()

    if not user_data:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('usuarios'))

    user_detail = User(**user_data)
    is_authorized = current_user.id == user_detail.id or current_user.rol in ['Administrador', 'Superusuario']

    if not is_authorized:
        flash('Acceso denegado: No tienes permiso para ver este perfil.', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('detalle_usuarios.html', user=user_detail)

@app.route('/usuarios/<int:user_id>/eliminar', methods=['POST'])
@login_required
def eliminar_usuario(user_id):
    """
    Ruta para eliminar un usuario (solo Superusuario).
    """
    if current_user.rol != 'Superusuario':
        flash('Acceso denegado: Solo un Superusuario puede eliminar usuarios.', 'danger')
        return redirect(url_for('dashboard'))

    if user_id == current_user.id:
        flash('No puedes eliminar tu propia cuenta mientras estás logueado.', 'danger')
        return redirect(url_for('usuarios'))

    is_deleted, message = user_module.delete_user(user_id)

    if is_deleted:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    
    return redirect(url_for('usuarios'))

@app.route('/cambiar_password', methods=['GET', 'POST'])
@login_required
def cambiar_password():
    """
    Ruta para que el usuario actual cambie su propia contraseña.
    """
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')
        user_id = current_user.id

        # 1. Validar que la nueva contraseña y la confirmación coincidan
        if new_password != confirm_new_password:
            flash('Error: La nueva contraseña y la confirmación no coinciden.', 'danger')
            return redirect(url_for('cambiar_password'))
        
        # 2. Validar complejidad de la nueva contraseña
        # La validación más estricta se hace en users.py, pero una validación de longitud simple ayuda
        if len(new_password) < 8:
            flash('Error: La nueva contraseña debe tener al menos 8 caracteres.', 'danger')
            return redirect(url_for('cambiar_password'))

        # 3. Llamar a la función de módulo para actualizar la contraseña en la BD
        is_updated, message = user_module.update_user_password(user_id, old_password, new_password)
        
        if is_updated:
            # Forzar el logout para que el usuario inicie sesión con la nueva contraseña
            logout_user() 
            flash(message, 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'danger')
            return redirect(url_for('cambiar_password'))

    return render_template('cambiar_password.html')


# ----------------------------------------------------
#               Ejecución de la Aplicación
# ----------------------------------------------------

if __name__ == '__main__':
    # Inicializa la base de datos (crea la tabla de usuarios si es necesario)
    conn = get_db_connection()
    user_module.create_user_table(conn)
    conn.close()
    
    # Inicia el servidor Flask
    app.run(debug=True)

# flask db init
# flask db migrate -m "Initial migration after reset"
# flask db upgrade

# 21:56 ~/LATRIBU1 (main)$ source env/Scripts/activate
# (env) 21:57 ~/LATRIBU1 (main)$

# En caso de que no sirva el env/Scripts/activate
# remover en env
# 05:48 ~/latribuapp (main)$ rm -rf env
# Crear nuevo
# 05:49 ~/latribuapp (main)$ python -m venv env
# 05:51 ~/latribuapp (main)$ source env/bin/activate
# (env) 05:52 ~/latribuapp (main)$ 


# Cuando se cambia de repositorio
# git remote -v
# git remote add origin <URL_DEL_REPOSITORIO>
# git remote set-url origin <NUEVA_URL_DEL_REPOSITORIO>
# git branchgit remote -v
# git push -u origin flet


# borrar base de datos y reconstruirla
# pip install PyMySQL
# SHOW TABLES;
# 21:56 ~/LATRIBU1 (main)$ source env/Scripts/activate <-- Entra al entorno virtual
# (env) 21:57 ~/LATRIBU1 (main)$
# (env) 23:30 ~/LATRIBU1 (main)$ cd /home/kenth1977/LATRIBU1
# (env) 23:31 ~/LATRIBU1 (main)$ rm -f instance/db.db
# (env) 23:32 ~/LATRIBU1 (main)$ python app.py