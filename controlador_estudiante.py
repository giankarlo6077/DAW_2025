from bd import obtener_conexion
import random
import string
from datetime import datetime

# ========================================
# CONTROLADOR: DASHBOARD ESTUDIANTE
# ========================================

def obtener_grupo_y_miembros(user_id):
    """Obtiene la información del grupo del usuario y sus miembros"""
    conexion = obtener_conexion()
    grupo_info = None
    miembros = []

    try:
        with conexion.cursor() as cursor:
            # 1. Obtener ID del grupo del usuario
            cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
            usuario_data = cursor.fetchone()

            if usuario_data and usuario_data.get('grupo_id'):
                grupo_id = usuario_data['grupo_id']

                # 2. Info del grupo
                cursor.execute("SELECT * FROM grupos WHERE id = %s", (grupo_id,))
                grupo_info = cursor.fetchone()

                # 3. Miembros
                cursor.execute("SELECT id, nombre FROM usuarios WHERE grupo_id = %s", (grupo_id,))
                miembros = cursor.fetchall()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return grupo_info, miembros

def obtener_historial_combinado(user_id, limite=5):
    """Obtiene y combina historial grupal e individual"""
    conexion = obtener_conexion()
    historial_total = []

    try:
        with conexion.cursor() as cursor:
            # 1. Historial Grupal
            cursor.execute("""
                SELECT h.titulo_cuestionario, h.puntuacion_final, h.fecha_partida,
                       h.nombre_grupo, 'grupal' as tipo
                FROM historial_partidas h
                INNER JOIN participantes_partida p ON h.id = p.partida_id
                WHERE p.usuario_id = %s
                ORDER BY h.fecha_partida DESC LIMIT %s
            """, (user_id, limite))
            grupales = cursor.fetchall()

            # 2. Historial Individual
            cursor.execute("""
                SELECT c.titulo as titulo_cuestionario, hi.puntuacion_final,
                       hi.fecha_realizacion as fecha_partida, NULL as nombre_grupo,
                       'individual' as tipo
                FROM historial_individual hi
                INNER JOIN cuestionarios c ON hi.cuestionario_id = c.id
                WHERE hi.usuario_id = %s AND hi.puntuacion_final > 0
                ORDER BY hi.fecha_realizacion DESC LIMIT %s
            """, (user_id, limite))
            individuales = cursor.fetchall()

            # 3. Combinar y Ordenar en Python
            historial_total = list(grupales) + list(individuales)
            historial_total.sort(
                key=lambda x: x.get('fecha_partida') or datetime.min,
                reverse=True
            )

    finally:
        if conexion and conexion.open:
            conexion.close()

    return historial_total[:limite]

def obtener_stats_aseguradas(user_id):
    """Obtiene stats, si no existen las crea por defecto (Lazy Initialization)"""
    conexion = obtener_conexion()
    stats = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()

            if not stats:
                # Inicializar si no existe
                cursor.execute("""
                    INSERT INTO estudiantes_stats
                    (user_id, nivel, monedas, fecha_creacion)
                    VALUES (%s, 1, 0, NOW())
                """, (user_id,))
                conexion.commit()

                # Volver a leer
                cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
                stats = cursor.fetchone()
    finally:
        if conexion and conexion.open:
            conexion.close()

    # Fallback por seguridad
    if not stats:
        stats = {
            'nivel': 1, 'monedas': 0, 'total_partidas': 0,
            'total_preguntas_correctas': 0, 'racha_actual': 0, 'mejor_puntaje': 0
        }
    return stats

def obtener_items_equipados(user_id):
    """Obtiene items equipados (Avatar, Marco, Título)"""
    conexion = obtener_conexion()
    items_equipados = {'avatar': None, 'marco': None, 'titulo': None}
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT ti.tipo, ti.icono, ti.nombre
                FROM estudiantes_items ei
                JOIN tienda_items ti ON ei.item_id = ti.id
                WHERE ei.usuario_id = %s AND ei.equipado = 1
            """, (user_id,))
            items = cursor.fetchall()

            for item in items:
                items_equipados[item['tipo']] = {
                    'icono': item['icono'],
                    'nombre': item['nombre']
                }
    finally:
        if conexion and conexion.open:
            conexion.close()
    return items_equipados

# ========================================
# CONTROLADOR: GESTIÓN DE GRUPOS
# ========================================

def _generar_codigo_grupo_unico(cursor):
    """Helper interno para generar código único"""
    while True:
        codigo = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        cursor.execute("SELECT id FROM grupos WHERE codigo_grupo = %s", (codigo,))
        if not cursor.fetchone():
            return codigo

def crear_nuevo_grupo(user_id, nombre_grupo):
    """Crea grupo y asigna al líder. Retorna (True, msg) o (False, error)"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Validar si ya tiene grupo
            cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
            if cursor.fetchone().get('grupo_id'):
                return False, "Ya perteneces a un grupo."

            codigo = _generar_codigo_grupo_unico(cursor)

            # Crear grupo
            cursor.execute("""
                INSERT INTO grupos (nombre_grupo, codigo_grupo, lider_id, fecha_creacion)
                VALUES (%s, %s, %s, NOW())
            """, (nombre_grupo, codigo, user_id))
            nuevo_grupo_id = cursor.lastrowid

            # Asignar usuario al grupo
            cursor.execute("UPDATE usuarios SET grupo_id = %s WHERE id = %s", (nuevo_grupo_id, user_id))
            conexion.commit()

            return True, f"Grupo '{nombre_grupo}' creado con éxito."
    finally:
        if conexion and conexion.open:
            conexion.close()

def unirse_a_grupo_existente(user_id, codigo_grupo):
    """Une al usuario a un grupo por código"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Validar si ya tiene grupo
            cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
            if cursor.fetchone().get('grupo_id'):
                return False, "Ya perteneces a un grupo."

            # Buscar grupo
            cursor.execute("SELECT id FROM grupos WHERE codigo_grupo = %s", (codigo_grupo,))
            grupo = cursor.fetchone()

            if not grupo:
                return False, "No se encontró ningún grupo con ese código."

            # Unir
            cursor.execute("UPDATE usuarios SET grupo_id = %s WHERE id = %s", (grupo['id'], user_id))
            conexion.commit()
            return True, "Te has unido al grupo exitosamente."
    finally:
        if conexion and conexion.open:
            conexion.close()

def procesar_salida_grupo(user_id):
    """Maneja la salida: Si es líder disuelve el grupo, si es miembro solo sale"""
    conexion = obtener_conexion()
    mensaje = ""
    try:
        with conexion.cursor() as cursor:
            # Obtener info del grupo actual
            cursor.execute("""
                SELECT g.id, g.lider_id
                FROM grupos g
                JOIN usuarios u ON g.id = u.grupo_id
                WHERE u.id = %s
            """, (user_id,))
            grupo = cursor.fetchone()

            if not grupo:
                return False, "No perteneces a ningún grupo."

            grupo_id = grupo['id']

            if grupo['lider_id'] == user_id:
                # Es líder: Disolver grupo (todos los miembros quedan sin grupo)
                cursor.execute("UPDATE usuarios SET grupo_id = NULL WHERE grupo_id = %s", (grupo_id,))
                cursor.execute("DELETE FROM grupos WHERE id = %s", (grupo_id,))
                mensaje = "Has salido y el grupo se ha disuelto."
            else:
                # Es miembro: Solo salir
                cursor.execute("UPDATE usuarios SET grupo_id = NULL WHERE id = %s", (user_id,))
                mensaje = "Has salido del grupo."

            conexion.commit()
            return True, mensaje
    finally:
        if conexion and conexion.open:
            conexion.close()

# ========================================
# CONTROLADOR: PERFIL ESTUDIANTE
# ========================================

def obtener_datos_perfil(user_id):
    """Obtiene correo y contraseña actual para validaciones"""
    conexion = obtener_conexion()
    datos = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT nombre, correo, password FROM usuarios WHERE id = %s", (user_id,))
            datos = cursor.fetchone()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return datos

def actualizar_perfil_estudiante(user_id, nombre, password_encriptada=None):
    """Actualiza nombre y opcionalmente la contraseña"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            if password_encriptada:
                cursor.execute("""
                    UPDATE usuarios
                    SET nombre = %s, password = %s
                    WHERE id = %s
                """, (nombre, password_encriptada, user_id))
            else:
                cursor.execute("""
                    UPDATE usuarios
                    SET nombre = %s
                    WHERE id = %s
                """, (nombre, user_id))
            conexion.commit()
            return True
    finally:
        if conexion and conexion.open:
            conexion.close()

def eliminar_cuenta_estudiante_definitiva(user_id):
    """Elimina la cuenta del estudiante"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Nota: Si tu base de datos tiene 'ON DELETE CASCADE', esto borrará todo lo relacionado.
            # Si no, deberías borrar manualmente historiales y stats antes de borrar el usuario.
            # Basado en tu código original, asumimos que el DELETE directo funciona.

            cursor.execute("DELETE FROM usuarios WHERE id = %s", (user_id,))
            conexion.commit()
            return True
    finally:
        if conexion and conexion.open:
            conexion.close()