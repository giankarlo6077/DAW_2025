from bd import obtener_conexion

def insertar_usuario(nombre, correo, password, rol):
    conexion = obtener_conexion()
    with conexion.cursor() as cursor:
        sql = "INSERT INTO usuarios (nombre, correo, password, rol) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (nombre, correo, password, rol))
    conexion.commit()
    conexion.close()


def obtener_usuarios():
    conexion = obtener_conexion()
    with conexion.cursor() as cursor:
        cursor.execute("SELECT * FROM usuarios")
        usuarios = cursor.fetchall()
    conexion.close()
    return usuarios


def eliminar_usuario(id):
    conexion = obtener_conexion()
    with conexion.cursor() as cursor:
        cursor.execute("DELETE FROM usuarios WHERE id=%s", (id,))
    conexion.commit()
    conexion.close()


def obtener_usuario_por_id(id):
    conexion = obtener_conexion()
    with conexion.cursor() as cursor:
        cursor.execute("SELECT * FROM usuarios WHERE id=%s", (id,))
        usuario = cursor.fetchone()
    conexion.close()
    return usuario


def actualizar_usuario(nombre, correo, password, rol, id):
    conexion = obtener_conexion()
    with conexion.cursor() as cursor:
        sql = """
        UPDATE usuarios
        SET nombre=%s, correo=%s, password=%s, rol=%s
        WHERE id=%s
        """
        cursor.execute(sql, (nombre, correo, password, rol, id))
    conexion.commit()
    conexion.close()