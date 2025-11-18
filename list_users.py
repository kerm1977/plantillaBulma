from app import get_db_connection

print("Listado de usuarios registrados:")
print("-" * 50)
print(f"{'ID':<5} | {'Email':<30} | {'Usuario':<15} | {'Nombre':<20} | Rol")
print("-" * 80)

try:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, usuario, nombre, rol FROM users ORDER BY id')
    
    for user in cursor.fetchall():
        print(f"{user['id']:<5} | {user['email']:<30} | {user['usuario']:<15} | {user['nombre']:<20} | {user['rol']}")
    
    print("-" * 80)
    print("Fin del listado")
    
except Exception as e:
    print(f"Error al obtener los usuarios: {str(e)}")
    
finally:
    if 'conn' in locals() and conn:
        conn.close()
