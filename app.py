# Importaciones necesarias para la aplicación Flask
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Importa las funciones del módulo de users.py
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
DB_PATH = 'database/db.db'

def get_db_connection():
    """
    Establece una conexión a la base de datos SQLite y configura el acceso a las filas por nombre.
    
    Returns:
        sqlite3.Connection: El objeto de conexión.
    """
    # Asegúrate de que el directorio de la base de datos existe
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ----------------------------------------------------
#               Clase de Usuario para Flask-Login
# ----------------------------------------------------

class User(UserMixin):
    """
    Clase de modelo para el usuario, compatible con Flask-Login.
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
        
    @staticmethod
    def get(user_id):
        """
        Método estático para cargar un usuario desde la base de datos.
        """
        user_data = user_module.find_user_by_id(user_id)
        if user_data:
            return User(user_data)
        return None
        
@login_manager.user_loader
def load_user(user_id):
    """
    Función de callback para recargar al usuario desde la sesión.
    """
    return User.get(user_id)

# ----------------------------------------------------
#                     Rutas de la Aplicación
# ----------------------------------------------------

@app.route('/')
def home():
    """
    Ruta principal que muestra la página de inicio.
    """
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Ruta para el registro de nuevos usuarios.
    """
    if request.method == 'POST':
        # Añade un nuevo usuario usando la función del módulo users
        result = user_module.add_new_user(request.form)
        
        if isinstance(result, str):
            # Si add_new_user retorna una cadena, es un error
            flash(result, 'danger')
        else:
            # Si retorna el usuario, el registro fue exitoso
            flash('¡Registro exitoso! Por favor, inicia sesión.', 'success')
            return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Ruta para el inicio de sesión.
    """
    if current_user.is_authenticated:
        return redirect(url_for('perfil'))

    if request.method == 'POST':
        user_input = request.form.get('username_or_email_or_phone')
        password = request.form.get('password')
        
        # Limpia cualquier espacio en blanco en la contraseña
        password = password.strip()

        # Llama a la función de verificación genérica en el módulo de users
        user_data = user_module.verify_user(user_input, password)
        
        if user_data:
            user_obj = User(user_data)
            login_user(user_obj)
            return redirect(url_for('perfil'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')
            
    return render_template('login.html')
    
@app.route('/perfil')
@login_required
def perfil():
    """
    Ruta para la página de perfil del usuario.
    """
    # Pasar el objeto current_user a la plantilla para que Jinja pueda acceder a sus atributos
    return render_template('perfil.html', user=current_user)
    
@app.route('/logout')
@login_required
def logout():
    """
    Cierra la sesión del usuario.
    """
    logout_user()
    return redirect(url_for('home'))

@app.route('/usuarios')
@login_required
def usuarios():
    """
    Muestra la lista de usuarios.
    Solo accesible para administradores.
    """
    if current_user.rol != 'Administrador':
        flash('No tienes permiso para ver esta página.', 'danger')
        return redirect(url_for('perfil'))
        
    users = user_module.find_all_users()
    return render_template('ver_usuarios.html', users=users)

@app.route('/usuarios/editar/<int:user_id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(user_id):
    """
    Edita la información de un usuario.
    Solo accesible para administradores.
    """
    if current_user.rol != 'Administrador':
        flash('No tienes permiso para realizar esta acción.', 'danger')
        return redirect(url_for('perfil'))
        
    user = user_module.find_user_by_id(user_id)
    if not user:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('usuarios'))

    if request.method == 'POST':
        updated_user = user_module.update_user(user_id, request.form)
        if isinstance(updated_user, str):
            flash(updated_user, 'danger')
        else:
            flash('Usuario actualizado con éxito.', 'success')
        return redirect(url_for('usuarios'))

    # Cambiado el nombre del archivo de plantilla de 'editar_usuario.html' a 'editar_usuarios.html'
    return render_template('editar_usuarios.html', user=user)

@app.route('/usuarios/eliminar/<int:user_id>', methods=['POST'])
@login_required
def eliminar_usuario(user_id):
    """
    Elimina un usuario de la base de datos.
    Solo accesible para administradores.
    """
    if current_user.rol != 'Administrador':
        flash('No tienes permiso para realizar esta acción.', 'danger')
        return redirect(url_for('perfil'))

    success, message = user_module.delete_user_by_id(user_id)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    
    return redirect(url_for('usuarios'))

# ----------------------------------------------------
#               Ejecución de la Aplicación
# ----------------------------------------------------

# Inicializa la base de datos y crea la tabla de usuarios antes de la primera solicitud
with app.app_context():
    try:
        conn = get_db_connection()
        user_module.create_user_table(conn)
        conn.close()

        # Comprueba y actualiza el rol de superusuario
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = 'kenth1977@gmail.com'")
            user_to_check = cursor.fetchone()
            
            if user_to_check and user_to_check['rol'] != 'Administrador':
                print("El usuario kenth1977@gmail.com no es Administrador. Actualizando...")
                user_module.make_admin_by_email('kenth1977@gmail.com')
            conn.close()
        except Exception as e:
            print(f"Error al verificar y actualizar el rol de superusuario: {e}")
            
    except Exception as e:
        print(f"Error al inicializar la base de datos: {e}")


if __name__ == '__main__':
    app.run(debug=True, port=8080)
