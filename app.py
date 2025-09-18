# Importaciones necesarias para la aplicación Flask
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Importa las funciones del módulo de usuarios.py (se implementarán después)
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
DB_NAME = 'db.db'

def get_db_connection():
    """
    Establece y devuelve una conexión a la base de datos.
    
    Returns:
        sqlite3.Connection: El objeto de conexión a la base de datos.
    """
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row # Permite acceder a las columnas por nombre
    return conn

def init_db():
    """
    Inicializa la base de datos y crea la tabla de usuarios si no existe.
    """
    conn = get_db_connection()
    user_module.create_user_table(conn)
    conn.close()

# ----------------------------------------------------
#               Clase de Usuario para Flask-Login
# ----------------------------------------------------

class User(UserMixin):
    """
    Clase de usuario para manejar las sesiones con Flask-Login.
    """
    def __init__(self, user_data):
        self.id = user_data['id']
        self.nombre = user_data['nombre']
        self.primer_apellido = user_data['primer_apellido']
        self.segundo_apellido = user_data['segundo_apellido']
        self.usuario = user_data['usuario']
        self.email = user_data['email']
        self.telefono = user_data['telefono']
        self.rol = user_data['rol']

@login_manager.user_loader
def load_user(user_id):
    """
    Callback para recargar el objeto de usuario desde la ID de la sesión.
    """
    user_data = user_module.find_user_by_id(user_id)
    if user_data:
        return User(user_data)
    return None

# ----------------------------------------------------
#                  Rutas de la Aplicación
# ----------------------------------------------------

@app.route('/')
def index():
    """
    Ruta de la página de inicio.
    """
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Maneja el inicio de sesión de los usuarios.
    """
    if request.method == 'POST':
        user_input = request.form.get('username_or_email_or_phone')
        password = request.form.get('password')
        
        user_data = user_module.verify_user(user_input, password)
        
        if user_data:
            user = User(user_data)
            login_user(user)
            flash('Has iniciado sesión exitosamente.', 'success')
            return redirect(url_for('home'))
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
        result = user_module.add_new_user(request.form)
        if isinstance(result, str):
            # Si se devuelve una cadena, el registro falló y el mensaje de error se muestra
            flash(result, 'danger')
            return render_template('register.html', form_data=request.form)
        elif result:
            # Si se devuelve un objeto de usuario, el registro fue exitoso
            flash(f"¡Usuario {result['usuario']} registrado con éxito! Ahora puedes iniciar sesión.", 'success')
            return redirect(url_for('login'))
        else:
            # En caso de un error genérico no manejado, se muestra un mensaje predeterminado
            flash("Error al registrar el usuario. Por favor, verifica los datos.", 'danger')
            
    return render_template('register.html')

@app.route('/home')
@login_required
def home():
    """
    Ruta de la página principal (requiere inicio de sesión).
    """
    return render_template('home.html')

# ----------------------------------------------------
#               Ejecución de la Aplicación
# ----------------------------------------------------

if __name__ == '__main__':
    # Este bloque solo se ejecuta al correr el script directamente
    # Llama a init_db() para crear la base de datos y la tabla de usuarios
    init_db()
    # Ejecuta la aplicación en modo de depuración
    app.run(debug=True, port=8080)
