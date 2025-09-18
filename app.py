# Importaciones necesarias para la aplicación Flask
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Importa las funciones del módulo de users.py (se implementarán después)
# Este módulo contendrá toda la lógica de la base de datos para los usuarios
import users as user_module

# ----------------------------------------------------
#               Configuración de la Aplicación
# ----------------------------------------------------

# Inicializa la aplicación Flask
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(24) # Clave secreta para sesiones seguras

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
# Terminantemente prohibido bajo ninguna circunstancia tocar la base de datos,
# ni su nombre ni ubicación a menos que sea una orden directa.
# Nunca se debe incrustar usuarios directos al código ni de prueba ni reales.
DB_PATH = 'database/db.db'

def get_db_connection():
    """Establece y retorna una conexión a la base de datos SQLite."""
    # Asegúrate de que el directorio de la base de datos existe
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    # Configura la conexión para que retorne filas como objetos de fila (acceso por nombre de columna)
    conn.row_factory = sqlite3.Row
    return conn

# ----------------------------------------------------
#               Gestión de Usuarios (Flask-Login)
# ----------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    """
    Carga un objeto de usuario basado en su ID para Flask-Login.
    
    Args:
        user_id (str): El ID del usuario.
        
    Returns:
        UserMixin: El objeto de usuario correspondiente, o None si no se encuentra.
    """
    user_data = user_module.find_user_by_id(user_id)
    if user_data:
        user = UserMixin()
        user.id = user_data['id']
        user.nombre = user_data['nombre']
        user.primer_apellido = user_data['primer_apellido']
        user.segundo_apellido = user_data['segundo_apellido']
        user.username = user_data['usuario']
        user.email = user_data['email']
        user.telefono = user_data['telefono']
        user.rol = user_data['rol']
        return user
    return None

# ----------------------------------------------------
#                    Rutas de la Aplicación
# ----------------------------------------------------

@app.route('/')
def home():
    """Ruta principal, redirige al login si no hay un usuario autenticado."""
    if current_user.is_authenticated:
        return redirect(url_for('perfil'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Maneja el inicio de sesión del usuario."""
    if current_user.is_authenticated:
        return redirect(url_for('perfil'))
    
    if request.method == 'POST':
        user_input = request.form.get('username_or_email_or_phone')
        password = request.form.get('password')
        
        user_data = user_module.verify_user(user_input, password)
        
        if user_data:
            user = load_user(user_data['id'])
            login_user(user)
            flash('Has iniciado sesión exitosamente.', 'success')
            return redirect(url_for('perfil'))
        else:
            flash('Usuario, correo o contraseña incorrectos.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Cierra la sesión del usuario actual."""
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Maneja el registro de nuevos usuarios.
    
    Después de un registro exitoso, redirige al usuario a la página de login.
    """
    if request.method == 'POST':
        # Llama a la función de registro de users.py para manejar la lógica
        new_user = user_module.add_new_user(request.form)
        if isinstance(new_user, str):
            flash(new_user, 'danger')
        else:
            flash(f"¡Usuario {new_user['usuario']} registrado con éxito! Ahora puedes iniciar sesión.", 'success')
            return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/perfil')
@login_required
def perfil():
    """
    Muestra la página de perfil del usuario.
    
    Pasa el objeto `current_user` a la plantilla.
    """
    return render_template('perfil.html', user=current_user)

@app.route('/usuarios/editar/<int:user_id>')
@login_required
def editar_usuarios(user_id):
    """
    Ruta para editar la información de un usuario.
    """
    # Lógica para cargar el formulario de edición, que veremos en un paso posterior.
    # Por ahora, solo muestra un mensaje temporal.
    flash('La funcionalidad de editar perfil estará disponible en un futuro paso.', 'info')
    return redirect(url_for('perfil'))

# ----------------------------------------------------
#               Ejecución de la Aplicación
# ----------------------------------------------------

if __name__ == '__main__':
    # Inicializa la base de datos y crea la tabla de usuarios
    conn = get_db_connection()
    user_module.create_user_table(conn)
    conn.close()

    app.run(debug=True, port="8080")
