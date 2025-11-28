from bd import obtener_conexion
import re
import pytz
import random
import string
from datetime import datetime

PERU_TZ = pytz.timezone('America/Lima')


# ========================================
# CONTROLADOR: UTILIDADES Y VALIDACIONES (Auth & Helpers)
# ========================================

def verificar_usuario_token(usuario_id):
    """Verifica si el usuario del token existe y devuelve sus datos básicos"""
    conexion = obtener_conexion()
    usuario = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id, rol FROM usuarios WHERE id = %s", (usuario_id,))
            usuario = cursor.fetchone()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return usuario

def verificar_listos_individual(sesion_id, pregunta_index):
    """Logica para verificar si todos terminaron en modo individual"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Contar total en sala
            cursor.execute("SELECT COUNT(*) as total FROM salas_espera WHERE sesion_id = %s", (sesion_id,))
            res_total = cursor.fetchone()
            total = res_total['total'] if res_total else 0

            # Contar listos
            cursor.execute("""
                SELECT COUNT(*) as listos FROM salas_espera
                WHERE sesion_id = %s AND pregunta_actual >= %s AND listo_para_siguiente = TRUE
            """, (sesion_id, pregunta_index))
            res_listos = cursor.fetchone()
            listos = res_listos['listos'] if res_listos else 0

            return listos >= total and total > 0
    finally:
        if conexion and conexion.open:
            conexion.close()

def verificar_listos_grupal(grupo_id, pregunta_index):
    """Logica para verificar si el grupo terminó"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Contar miembros
            cursor.execute("SELECT COUNT(*) as total FROM usuarios WHERE grupo_id = %s", (grupo_id,))
            res_total = cursor.fetchone()
            total = res_total['total'] if res_total else 0

            # Contar respondidos
            cursor.execute("""
                SELECT COUNT(DISTINCT usuario_id) as respondidos
                FROM progreso_grupal
                WHERE grupo_id = %s AND pregunta_index = %s AND respondio = 1
            """, (grupo_id, pregunta_index))
            res_resp = cursor.fetchone()
            respondidos = res_resp['respondidos'] if res_resp else 0

            return respondidos >= total and total > 0
    finally:
        if conexion and conexion.open:
            conexion.close()

def marcar_listo_individual(usuario_id, sesion_id, pregunta_index):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                UPDATE salas_espera
                SET pregunta_actual = %s, listo_para_siguiente = TRUE
                WHERE usuario_id = %s AND sesion_id = %s
            """, (pregunta_index, usuario_id, sesion_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def marcar_listo_grupal_logica(grupo_id, usuario_id, pregunta_index):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Upsert (Insertar o Actualizar)
            cursor.execute("""
                INSERT INTO progreso_grupal
                (grupo_id, usuario_id, pregunta_index, respondio, fecha_respuesta)
                VALUES (%s, %s, %s, 1, NOW())
                ON DUPLICATE KEY UPDATE respondio = 1, fecha_respuesta = NOW()
            """, (grupo_id, usuario_id, pregunta_index))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def resetear_estado_individual(sesion_id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                UPDATE salas_espera SET listo_para_siguiente = FALSE WHERE sesion_id = %s
            """, (sesion_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def generar_codigo_grupo_unico():
    """Genera código y verifica en BD que sea único (Loop moved here)"""
    conexion = obtener_conexion()
    try:
        while True:
            codigo = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            with conexion.cursor() as cursor:
                cursor.execute("SELECT id FROM grupos WHERE codigo_grupo = %s", (codigo,))
                if not cursor.fetchone():
                    return codigo
            # Si existe, el while repite automáticamente
    finally:
        if conexion and conexion.open:
            conexion.close()

def generar_pin_cuestionario_unico():
    """Genera PIN y verifica en BD que sea único"""
    conexion = obtener_conexion()
    try:
        while True:
            pin = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            with conexion.cursor() as cursor:
                cursor.execute("SELECT id FROM cuestionarios WHERE codigo_pin=%s", (pin,))
                if not cursor.fetchone():
                    return pin
    finally:
        if conexion and conexion.open:
            conexion.close()

def obtener_items_equipados_usuario(user_id):
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

# Utilerías sin BD (Pueden estar aquí para centralizar)
def validar_password_segura(password):
    if len(password) < 8: return False, "Mínimo 8 caracteres."
    if not re.search("[a-z]", password): return False, "Falta minúscula."
    if not re.search("[A-Z]", password): return False, "Falta mayúscula."
    if not re.search("[0-9]", password): return False, "Falta número."
    return True, ""

def convertir_fecha_peru(fecha_utc):
    if fecha_utc is None: return None
    if fecha_utc.tzinfo is None: fecha_utc = pytz.utc.localize(fecha_utc)
    return fecha_utc.astimezone(PERU_TZ)

def generar_codigo_verificacion_simple():
    return ''.join(random.choices(string.digits, k=6))

# ========================================
# CONTROLADOR DE AUTENTICACIÓN Y USUARIOS
# ========================================

def buscar_usuario_por_correo(correo):
    """Busca un usuario por correo (para login, registro o recuperación)"""
    conexion = obtener_conexion()
    usuario = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM usuarios WHERE correo = %s", (correo,))
            usuario = cursor.fetchone()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return usuario

def registrar_usuario_pendiente(nombre, correo, password_encriptada, rol, codigo, fecha_codigo):
    """
    Intenta registrar un nuevo usuario.
    Retorna el ID del nuevo usuario o None si el correo ya existe.
    """
    conexion = obtener_conexion()
    nuevo_id = None
    try:
        with conexion.cursor() as cursor:
            # Verificar si ya existe
            cursor.execute("SELECT id FROM usuarios WHERE correo = %s", (correo,))
            if cursor.fetchone():
                return None  # Correo duplicado

            sql = """INSERT INTO usuarios 
                     (nombre, correo, password, rol, verificado, codigo_verificacion, fecha_codigo)
                     VALUES (%s, %s, %s, %s, 0, %s, %s)"""
            cursor.execute(sql, (nombre, correo, password_encriptada, rol, codigo, fecha_codigo))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()
    return nuevo_id

def obtener_usuario_verificacion(usuario_id, codigo):
    """Obtiene datos del usuario para verificar el código"""
    conexion = obtener_conexion()
    usuario = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT id, fecha_codigo 
                FROM usuarios 
                WHERE id = %s AND codigo_verificacion = %s
            """, (usuario_id, codigo))
            usuario = cursor.fetchone()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return usuario

def marcar_usuario_como_verificado(usuario_id):
    """Marca al usuario como verificado y limpia el código"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                UPDATE usuarios 
                SET verificado = 1, codigo_verificacion = NULL, fecha_codigo = NULL 
                WHERE id = %s
            """, (usuario_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def actualizar_codigo_verificacion(usuario_id, nuevo_codigo, nueva_fecha):
    """Actualiza el código para reenvío"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                UPDATE usuarios 
                SET codigo_verificacion = %s, fecha_codigo = %s 
                WHERE id = %s
            """, (nuevo_codigo, nueva_fecha, usuario_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def guardar_token_recuperacion(usuario_id, token, expiracion):
    """Guarda el token de reseteo de contraseña"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                UPDATE usuarios 
                SET reset_token = %s, reset_token_expiration = %s 
                WHERE id = %s
            """, (token, expiracion, usuario_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def obtener_usuario_por_reset_token(token):
    """Busca usuario por token de recuperación"""
    conexion = obtener_conexion()
    usuario = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT id, reset_token_expiration 
                FROM usuarios 
                WHERE reset_token = %s
            """, (token,))
            usuario = cursor.fetchone()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return usuario

def actualizar_password_reseteada(usuario_id, nueva_password_enc):
    """Actualiza la contraseña y limpia el token"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                UPDATE usuarios 
                SET password = %s, reset_token = NULL, reset_token_expiration = NULL 
                WHERE id = %s
            """, (nueva_password_enc, usuario_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()