from bd import obtener_conexion
import random
import string
import pandas as pd
from io import BytesIO


# ========================================
# CONTROLADOR: DASHBOARD Y GESTIÓN CUESTIONARIOS
# ========================================

def obtener_datos_dashboard(profesor_id):
    """Obtiene estadísticas y cuestionarios del profesor"""
    conexion = obtener_conexion()
    datos = {
        "cuestionarios": [],
        "total_cuestionarios": 0,
        "total_preguntas": 0
    }
    try:
        with conexion.cursor() as cursor:
            # 1. Lista de cuestionarios con conteo de preguntas
            cursor.execute("""
                SELECT c.*, COUNT(p.id) as total_preguntas
                FROM cuestionarios c
                LEFT JOIN preguntas p ON c.id = p.cuestionario_id
                WHERE c.profesor_id = %s
                GROUP BY c.id ORDER BY c.fecha_creacion DESC
            """, (profesor_id,))
            datos["cuestionarios"] = cursor.fetchall()

            # 2. Total cuestionarios
            cursor.execute("SELECT COUNT(*) as total FROM cuestionarios WHERE profesor_id = %s", (profesor_id,))
            res_total = cursor.fetchone()
            datos["total_cuestionarios"] = res_total['total'] if res_total else 0

            # 3. Total preguntas globales
            cursor.execute("""
                SELECT COUNT(*) as total FROM preguntas p
                INNER JOIN cuestionarios c ON p.cuestionario_id = c.id
                WHERE c.profesor_id = %s
            """, (profesor_id,))
            res_preg = cursor.fetchone()
            datos["total_preguntas"] = res_preg['total'] if res_preg else 0
    finally:
        if conexion and conexion.open:
            conexion.close()
    return datos

def generar_pin_unico():
    """Genera un PIN único verificando en BD"""
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

def crear_nuevo_cuestionario(titulo, descripcion, modo, tiempo, num_preg, profesor_id):
    """Crea el cuestionario y retorna su ID"""
    codigo_pin = generar_pin_unico()
    conexion = obtener_conexion()
    nuevo_id = None
    try:
        with conexion.cursor() as cursor:
            sql = """INSERT INTO cuestionarios
                     (titulo, descripcion, modo_juego, tiempo_pregunta, num_preguntas, codigo_pin, profesor_id, fecha_creacion)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())"""
            cursor.execute(sql, (titulo, descripcion, modo, tiempo, num_preg, codigo_pin, profesor_id))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()
    return nuevo_id

def obtener_cuestionario_propio(cuestionario_id, profesor_id):
    """Verifica que el cuestionario pertenezca al profesor"""
    conexion = obtener_conexion()
    cuestionario = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM cuestionarios WHERE id=%s AND profesor_id=%s", (cuestionario_id, profesor_id))
            cuestionario = cursor.fetchone()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return cuestionario

def guardar_preguntas_batch(cuestionario_id, lista_preguntas):
    """Guarda múltiples preguntas de una sola vez"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            for idx, pregunta in enumerate(lista_preguntas, start=1):
                sql = """INSERT INTO preguntas (cuestionario_id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, orden)
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
                cursor.execute(sql, (
                    cuestionario_id, pregunta["pregunta"],
                    pregunta["opcion_a"], pregunta["opcion_b"],
                    pregunta["opcion_c"], pregunta["opcion_d"],
                    pregunta["respuesta_correcta"], idx
                ))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def obtener_datos_edicion(cuestionario_id, profesor_id):
    """Obtiene cuestionario y sus preguntas para editar"""
    conexion = obtener_conexion()
    datos = {"cuestionario": None, "preguntas": []}
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM cuestionarios WHERE id=%s AND profesor_id=%s", (cuestionario_id, profesor_id))
            datos["cuestionario"] = cursor.fetchone()

            if datos["cuestionario"]:
                cursor.execute("SELECT * FROM preguntas WHERE cuestionario_id=%s ORDER BY orden", (cuestionario_id,))
                datos["preguntas"] = cursor.fetchall()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return datos

def actualizar_cuestionario_completo(cuestionario_id, titulo, desc, modo, tiempo, lista_preguntas):
    """Actualiza info básica y reemplaza todas las preguntas (Transacción atómica)"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Actualizar datos básicos
            sql = "UPDATE cuestionarios SET titulo=%s, descripcion=%s, modo_juego=%s, tiempo_pregunta=%s, num_preguntas=%s WHERE id=%s"
            cursor.execute(sql, (titulo, desc, modo, tiempo, len(lista_preguntas), cuestionario_id))

            # 2. Borrar preguntas viejas
            cursor.execute("DELETE FROM preguntas WHERE cuestionario_id=%s", (cuestionario_id,))

            # 3. Insertar preguntas nuevas
            for idx, p in enumerate(lista_preguntas, start=1):
                sql_ins = "INSERT INTO preguntas (cuestionario_id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, orden) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
                cursor.execute(sql_ins, (cuestionario_id, p['pregunta'], p['opcion_a'], p['opcion_b'], p['opcion_c'], p['opcion_d'], p['respuesta_correcta'], idx))

            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def eliminar_cuestionario_cascada(cuestionario_id, profesor_id):
    """Elimina cuestionario y sus preguntas verificando dueño"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Verificar dueño antes de borrar (seguridad extra)
            cursor.execute("SELECT id FROM cuestionarios WHERE id=%s AND profesor_id=%s", (cuestionario_id, profesor_id))
            if not cursor.fetchone():
                return False

            cursor.execute("DELETE FROM preguntas WHERE cuestionario_id = %s", (cuestionario_id,))
            cursor.execute("DELETE FROM cuestionarios WHERE id = %s", (cuestionario_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

# ========================================
# CONTROLADOR: PERFIL Y CUENTA PROFESOR
# ========================================

def obtener_correo_por_id(user_id):
    conexion = obtener_conexion()
    correo = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT correo FROM usuarios WHERE id=%s", (user_id,))
            res = cursor.fetchone()
            if res: correo = res['correo']
    finally:
        if conexion and conexion.open: conexion.close()
    return correo

def obtener_password_actual(user_id):
    conexion = obtener_conexion()
    password = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT password FROM usuarios WHERE id=%s", (user_id,))
            res = cursor.fetchone()
            if res: password = res['password']
    finally:
        if conexion and conexion.open: conexion.close()
    return password

def actualizar_perfil(user_id, nombre, password_encriptada=None):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            if password_encriptada:
                cursor.execute("UPDATE usuarios SET nombre=%s, password=%s WHERE id=%s", (nombre, password_encriptada, user_id))
            else:
                cursor.execute("UPDATE usuarios SET nombre=%s WHERE id=%s", (nombre, user_id))
            conexion.commit()
    finally:
        if conexion and conexion.open: conexion.close()
    return True

def eliminar_cuenta_completa_profesor(user_id):
    """Elimina usuario, cuestionarios y preguntas en cascada"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Obtener IDs de cuestionarios para borrar preguntas
            cursor.execute("SELECT id FROM cuestionarios WHERE profesor_id = %s", (user_id,))
            cuestionarios = cursor.fetchall()

            if cuestionarios:
                cuestionario_ids = [c['id'] for c in cuestionarios]
                # Formatear string para IN clause: (%s, %s, ...)
                id_placeholders = ', '.join(['%s'] * len(cuestionario_ids))

                # Borrar preguntas de todos esos cuestionarios
                cursor.execute(f"DELETE FROM preguntas WHERE cuestionario_id IN ({id_placeholders})", tuple(cuestionario_ids))

            # Borrar cuestionarios
            cursor.execute("DELETE FROM cuestionarios WHERE profesor_id = %s", (user_id,))

            # Borrar usuario
            cursor.execute("DELETE FROM usuarios WHERE id = %s", (user_id,))

            conexion.commit()
    finally:
        if conexion and conexion.open: conexion.close()
    return True
# ========================================
# GESTIÓN DE EXCEL (IMPORTACIÓN/EXPORTACIÓN)
# ========================================

def generar_plantilla_preguntas():
    """Genera el archivo Excel de plantilla en memoria"""
    plantilla_data = {
        'Pregunta': ['¿Cuál es la capital de Francia?', '¿Cuánto es 2+2?', '(Agrega más preguntas...)'],
        'Opcion_A': ['París', '3', ''],
        'Opcion_B': ['Londres', '4', ''],
        'Opcion_C': ['Madrid', '5', ''],
        'Opcion_D': ['Roma', '6', ''],
        'Respuesta_Correcta': ['A', 'B', '']
    }
    df = pd.DataFrame(plantilla_data)

    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Preguntas', index=False)
        # Ajuste de columnas simple
        ws = writer.sheets['Preguntas']
        ws.column_dimensions['A'].width = 50

    output.seek(0)
    return output

def importar_preguntas_desde_excel(cuestionario_id, profesor_id, df):
    """Procesa el DataFrame de Pandas e inserta las preguntas"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Validar propiedad
            cursor.execute("SELECT num_preguntas FROM cuestionarios WHERE id=%s AND profesor_id=%s", (cuestionario_id, profesor_id))
            cuestionario = cursor.fetchone()
            if not cuestionario: return False, "Cuestionario no encontrado"

            # 2. Validaciones de datos
            if len(df) == 0: return False, "El archivo está vacío"

            columnas_req = ['Pregunta', 'Opcion_A', 'Opcion_B', 'Opcion_C', 'Opcion_D', 'Respuesta_Correcta']
            faltantes = [col for col in columnas_req if col not in df.columns]
            if faltantes: return False, f"Faltan columnas: {', '.join(faltantes)}"

            # 3. Limpieza
            df = df.dropna(subset=['Pregunta'])
            df = df.head(cuestionario['num_preguntas']) # Limitar cantidad

            # 4. Reemplazo (Borrar e Insertar)
            cursor.execute("DELETE FROM preguntas WHERE cuestionario_id = %s", (cuestionario_id,))

            for idx, row in df.iterrows():
                resp = str(row['Respuesta_Correcta']).strip().upper()
                if resp not in ['A', 'B', 'C', 'D']: resp = 'A' # Fallback por seguridad

                cursor.execute("""
                    INSERT INTO preguntas (cuestionario_id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, orden)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    cuestionario_id, str(row['Pregunta']), str(row['Opcion_A']),
                    str(row['Opcion_B']), str(row['Opcion_C']), str(row['Opcion_D']),
                    resp, idx + 1
                ))

            conexion.commit()
            return True, f"Se importaron {len(df)} preguntas exitosamente"
    finally:
        if conexion and conexion.open: conexion.close()

def crear_cuestionario_completo_excel(profesor_id, titulo, descripcion, modo, tiempo, df):
    """Crea cuestionario e importa preguntas en una transacción"""
    codigo_pin = generar_pin_unico() # Usamos la función que ya existe en este archivo
    num_preguntas = len(df)
    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            # 1. Crear Cuestionario
            cursor.execute("""
                INSERT INTO cuestionarios (titulo, descripcion, modo_juego, tiempo_pregunta, num_preguntas, codigo_pin, profesor_id, fecha_creacion)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (titulo, descripcion, modo, tiempo, num_preguntas, codigo_pin, profesor_id))
            cuestionario_id = cursor.lastrowid

            # 2. Insertar Preguntas
            for idx, row in df.iterrows():
                resp = str(row.get('Respuesta_Correcta', 'A')).strip().upper()
                if resp not in ['A', 'B', 'C', 'D']: resp = 'A'

                cursor.execute("""
                    INSERT INTO preguntas (cuestionario_id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, orden)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    cuestionario_id, str(row.get('Pregunta', '')), str(row.get('Opcion_A', '')),
                    str(row.get('Opcion_B', '')), str(row.get('Opcion_C', '')), str(row.get('Opcion_D', '')),
                    resp, idx + 1
                ))

            conexion.commit()
            return True, titulo, num_preguntas
    finally:
        if conexion and conexion.open: conexion.close()

# ========================================
# CONTROL DE SESIONES EN VIVO (SINCRONIZACIÓN)
# ========================================

def obtener_o_crear_estado_sesion(sesion_id):
    """
    Obtiene el estado actual de una sesión controlada por el profesor.
    Si no existe registro en control_sesiones, lo inicializa.
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT pregunta_actual, estado, tiempo_restante
                FROM control_sesiones
                WHERE sesion_id = %s
            """, (sesion_id,))

            estado = cursor.fetchone()

            if not estado:
                # Si no existe, crear registro inicial
                cursor.execute("""
                    INSERT INTO control_sesiones (sesion_id, pregunta_actual, estado, tiempo_restante)
                    VALUES (%s, 0, 'playing', 0)
                """, (sesion_id,))
                conexion.commit()

                return {
                    "pregunta_actual": 0,
                    "estado": "playing",
                    "tiempo_restante": 0
                }

            return estado
    finally:
        if conexion and conexion.open:
            conexion.close()

def actualizar_progreso_sesion(sesion_id, pregunta_actual, estado, tiempo_restante):
    """Actualiza o inserta el estado de la sesión en tiempo real"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO control_sesiones (sesion_id, pregunta_actual, estado, tiempo_restante, ultima_actualizacion)
                VALUES (%s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                    pregunta_actual = %s,
                    estado = %s,
                    tiempo_restante = %s,
                    ultima_actualizacion = NOW()
            """, (sesion_id, pregunta_actual, estado, tiempo_restante,
                  pregunta_actual, estado, tiempo_restante))
            conexion.commit()
            return True
    finally:
        if conexion and conexion.open:
            conexion.close()


# ========================================
# SINCRONIZACIÓN DE TIEMPO (JUEGO INDIVIDUAL)
# ========================================

def obtener_estado_pregunta_profesor(sesion_id):
    """Obtener el estado actual de la pregunta desde el profesor"""
    conexion = obtener_conexion()
    estado = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT estado, pregunta_actual, tiempo_restante
                FROM control_sesiones
                WHERE sesion_id = %s
            """, (sesion_id,))

            estado = cursor.fetchone()

            if not estado:
                # Si no existe, crear registro inicial
                cursor.execute("""
                    INSERT INTO control_sesiones (sesion_id, pregunta_actual, estado, tiempo_restante)
                    VALUES (%s, 0, 'playing', 0)
                """, (sesion_id,))
                conexion.commit()

                return {
                    'estado': 'playing',
                    'pregunta_actual': 0,
                    'tiempo_restante': 0
                }

    finally:
        if conexion and conexion.open:
            conexion.close()

    return estado if estado else None

def actualizar_tiempo_profesor(sesion_id, tiempo_restante):
    """Actualizar el tiempo restante de la pregunta actual"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                UPDATE control_sesiones
                SET tiempo_restante = %s,
                    ultima_actualizacion = NOW()
                WHERE sesion_id = %s
            """, (tiempo_restante, sesion_id))

            conexion.commit()
            return True
    except Exception as e:
        print(f"Error al actualizar tiempo: {e}")
        return False
    finally:
        if conexion and conexion.open:
            conexion.close()

def actualizar_estado_pregunta_profesor(sesion_id, pregunta_actual, estado, tiempo_restante):
    """Actualizar el estado completo de la pregunta (usado al cambiar de pregunta)"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO control_sesiones
                (sesion_id, pregunta_actual, estado, tiempo_restante, ultima_actualizacion)
                VALUES (%s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                    pregunta_actual = %s,
                    estado = %s,
                    tiempo_restante = %s,
                    ultima_actualizacion = NOW()
            """, (sesion_id, pregunta_actual, estado, tiempo_restante,
                  pregunta_actual, estado, tiempo_restante))

            conexion.commit()
            return True
    except Exception as e:
        print(f"Error al actualizar estado de pregunta: {e}")
        return False
    finally:
        if conexion and conexion.open:
            conexion.close()

def obtener_estudiantes_en_sesion(sesion_id):
    """Obtener lista de estudiantes en una sesión con su progreso actual"""
    conexion = obtener_conexion()
    estudiantes = []
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT
                    u.id,
                    u.nombre,
                    se.estado,
                    COALESCE((
                        SELECT COUNT(DISTINCT r.pregunta_id)
                        FROM respuestas_individuales r
                        JOIN historial_individual h ON r.historial_id = h.id
                        WHERE h.usuario_id = u.id AND h.sesion_id = %s
                    ), 0) as pregunta_actual
                FROM salas_espera se
                JOIN usuarios u ON se.usuario_id = u.id
                WHERE se.sesion_id = %s
                ORDER BY u.nombre
            """, (sesion_id, sesion_id))

            estudiantes = cursor.fetchall()
    finally:
        if conexion and conexion.open:
            conexion.close()

    return estudiantes

def obtener_ranking_final_sesion(sesion_id):
    """Obtener el ranking final de una sesión individual"""
    conexion = obtener_conexion()
    ranking = []
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT
                    u.nombre,
                    h.puntuacion_final as puntuacion,
                    h.tiempo_total,
                    COUNT(CASE WHEN r.respuesta_estudiante = p.respuesta_correcta THEN 1 END) as correctas,
                    COUNT(r.id) as total_respondidas
                FROM historial_individual h
                JOIN usuarios u ON h.usuario_id = u.id
                LEFT JOIN respuestas_individuales r ON h.id = r.historial_id
                LEFT JOIN preguntas p ON r.pregunta_id = p.id
                WHERE h.sesion_id = %s
                GROUP BY h.id, u.nombre, h.puntuacion_final, h.tiempo_total
                ORDER BY h.puntuacion_final DESC, h.tiempo_total ASC
            """, (sesion_id,))

            ranking = cursor.fetchall()
    finally:
        if conexion and conexion.open:
            conexion.close()

    return ranking