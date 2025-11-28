from bd import obtener_conexion
import random
import string
import json


# ========================================
# CONTROLADOR: CUESTIONARIOS
# ========================================

def obtener_todos_cuestionarios():
    conexion = obtener_conexion()
    cuestionarios = []
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT id, titulo, descripcion, modo_juego, tiempo_pregunta,
                       num_preguntas, codigo_pin, profesor_id, estado,
                       fecha_creacion, eliminado
                FROM cuestionarios
                WHERE eliminado = 0
                ORDER BY fecha_creacion DESC
            """)
            cuestionarios = cursor.fetchall()

            # Formatear fechas
            for c in cuestionarios:
                if c.get('fecha_creacion'):
                    c['fecha_creacion'] = c['fecha_creacion'].strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return cuestionarios

def obtener_cuestionario_por_id(cuestionario_id):
    conexion = obtener_conexion()
    cuestionario = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT c.*, u.nombre as nombre_profesor
                FROM cuestionarios c
                LEFT JOIN usuarios u ON c.profesor_id = u.id
                WHERE c.id = %s AND c.eliminado = 0
            """, (cuestionario_id,))
            cuestionario = cursor.fetchone()

            if cuestionario:
                if cuestionario.get('fecha_creacion'):
                    cuestionario['fecha_creacion'] = cuestionario['fecha_creacion'].strftime('%Y-%m-%d %H:%M:%S')

                # Obtener preguntas asociadas
                cursor.execute("""
                    SELECT * FROM preguntas
                    WHERE cuestionario_id = %s AND eliminado = 0
                    ORDER BY orden
                """, (cuestionario_id,))
                preguntas = cursor.fetchall()
                cuestionario['preguntas'] = preguntas
    finally:
        if conexion and conexion.open:
            conexion.close()
    return cuestionario

def crear_cuestionario(titulo, descripcion, modo_juego, tiempo_pregunta, num_preguntas, profesor_id, estado):
    conexion = obtener_conexion()
    nuevo_id = None
    codigo_pin = ''.join(random.choices('0123456789', k=6))

    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO cuestionarios
                (titulo, descripcion, modo_juego, tiempo_pregunta, num_preguntas,
                 codigo_pin, profesor_id, estado, fecha_creacion)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                titulo, descripcion, modo_juego, tiempo_pregunta,
                num_preguntas, codigo_pin, profesor_id, estado
            ))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()

    return {"id": nuevo_id, "codigo_pin": codigo_pin}

def actualizar_cuestionario(cuestionario_id, titulo, descripcion, modo_juego, tiempo_pregunta, estado):
    conexion = obtener_conexion()
    filas_afectadas = 0
    try:
        with conexion.cursor() as cursor:
            # Verificar existencia primero
            cursor.execute("SELECT id FROM cuestionarios WHERE id = %s", (cuestionario_id,))
            if not cursor.fetchone():
                return False # No encontrado

            cursor.execute("""
                UPDATE cuestionarios
                SET titulo = %s, descripcion = %s, modo_juego = %s,
                    tiempo_pregunta = %s, estado = %s
                WHERE id = %s
            """, (titulo, descripcion, modo_juego, tiempo_pregunta, estado, cuestionario_id))
            conexion.commit()
            filas_afectadas = 1 # Asumimos éxito si no hay error y existía
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def eliminar_cuestionario_logico(cuestionario_id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM cuestionarios WHERE id = %s", (cuestionario_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("""
                UPDATE cuestionarios
                SET eliminado = 1
                WHERE id = %s
            """, (cuestionario_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True


# ========================================
# CONTROLADOR: PREGUNTAS
# ========================================

def obtener_todas_preguntas(cuestionario_id=None):
    conexion = obtener_conexion()
    preguntas = []
    try:
        with conexion.cursor() as cursor:
            if cuestionario_id:
                cursor.execute("""
                    SELECT * FROM preguntas
                    WHERE cuestionario_id = %s AND eliminado = 0
                    ORDER BY orden
                """, (cuestionario_id,))
            else:
                cursor.execute("""
                    SELECT * FROM preguntas
                    WHERE eliminado = 0
                    ORDER BY cuestionario_id, orden
                """)
            preguntas = cursor.fetchall()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return preguntas

def obtener_pregunta_id(pregunta_id):
    conexion = obtener_conexion()
    pregunta = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT p.*, c.titulo as titulo_cuestionario
                FROM preguntas p
                LEFT JOIN cuestionarios c ON p.cuestionario_id = c.id
                WHERE p.id = %s AND p.eliminado = 0
            """, (pregunta_id,))
            pregunta = cursor.fetchone()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return pregunta

def crear_pregunta(cuestionario_id, pregunta_texto, op_a, op_b, op_c, op_d, correcta, orden):
    conexion = obtener_conexion()
    nuevo_id = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO preguntas
                (cuestionario_id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d,
                 respuesta_correcta, orden)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                cuestionario_id, pregunta_texto, op_a, op_b, op_c, op_d, correcta, orden
            ))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()
    return nuevo_id

def actualizar_pregunta(pregunta_id, pregunta_texto, op_a, op_b, op_c, op_d, correcta, orden):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM preguntas WHERE id = %s", (pregunta_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("""
                UPDATE preguntas
                SET pregunta = %s, opcion_a = %s, opcion_b = %s, opcion_c = %s,
                    opcion_d = %s, respuesta_correcta = %s, orden = %s
                WHERE id = %s
            """, (
                pregunta_texto, op_a, op_b, op_c, op_d, correcta, orden, pregunta_id
            ))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def eliminar_pregunta_logico(pregunta_id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM preguntas WHERE id = %s", (pregunta_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("""
                UPDATE preguntas
                SET eliminado = 1
                WHERE id = %s
            """, (pregunta_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True



# ========================================
# CONTROLADOR: USUARIOS
# ========================================

def obtener_todos_usuarios(rol=None):
    conexion = obtener_conexion()
    usuarios = []
    try:
        with conexion.cursor() as cursor:
            query = """
                SELECT id, nombre, correo, rol, verificado, fecha_codigo,
                       grupo_id, codificacion_facial
                FROM usuarios
            """
            if rol:
                query += " WHERE rol = %s ORDER BY nombre"
                cursor.execute(query, (rol,))
            else:
                query += " ORDER BY rol, nombre"
                cursor.execute(query)

            usuarios = cursor.fetchall()

            # Procesar datos (fechas y booleanos)
            for u in usuarios:
                if u.get('fecha_codigo'):
                    u['fecha_codigo'] = u['fecha_codigo'].strftime('%Y-%m-%d %H:%M:%S')

                # Lógica de reconocimiento facial (convertir a bool y quitar blob)
                u['tiene_reconocimiento_facial'] = bool(u.get('codificacion_facial'))
                u.pop('codificacion_facial', None)

                # Asegurar que no vaya password (aunque no se seleccionó en el query)
                u.pop('password', None)

    finally:
        if conexion and conexion.open:
            conexion.close()
    return usuarios

def obtener_usuario_por_id(usuario_id):
    conexion = obtener_conexion()
    usuario = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.nombre, u.correo, u.rol, u.verificado,
                       u.fecha_codigo, u.grupo_id, g.nombre_grupo
                FROM usuarios u
                LEFT JOIN grupos g ON u.grupo_id = g.id
                WHERE u.id = %s
            """, (usuario_id,))
            usuario = cursor.fetchone()

            if usuario:
                if usuario.get('fecha_codigo'):
                    usuario['fecha_codigo'] = usuario['fecha_codigo'].strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return usuario

def crear_usuario(nombre, correo, password, rol, verificado, codigo_verificacion):
    conexion = obtener_conexion()
    nuevo_id = None
    try:
        with conexion.cursor() as cursor:
            # Verificar si correo existe
            cursor.execute("SELECT id FROM usuarios WHERE correo = %s", (correo,))
            if cursor.fetchone():
                return None # Retorna None para indicar duplicado/error

            cursor.execute("""
                INSERT INTO usuarios
                (nombre, correo, password, rol, verificado, codigo_verificacion, fecha_codigo)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """, (
                nombre, correo, password, rol, verificado, codigo_verificacion
            ))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()
    return nuevo_id

def actualizar_usuario(usuario_id, nombre, correo, rol, verificado, grupo_id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM usuarios WHERE id = %s", (usuario_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("""
                UPDATE usuarios
                SET nombre = %s, correo = %s, rol = %s, verificado = %s, grupo_id = %s
                WHERE id = %s
            """, (nombre, correo, rol, verificado, grupo_id, usuario_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def eliminar_usuario_fisico(usuario_id):
    """Eliminación física directa"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM usuarios WHERE id = %s", (usuario_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True


# ========================================
# CONTROLADOR: GRUPOS
# ========================================

def obtener_todos_grupos():
    conexion = obtener_conexion()
    grupos = []
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT g.*, u.nombre as nombre_lider,
                       (SELECT COUNT(*) FROM usuarios WHERE grupo_id = g.id) as num_miembros
                FROM grupos g
                LEFT JOIN usuarios u ON g.leader_id = u.id
                ORDER BY g.fecha_creacion DESC
            """)
            grupos = cursor.fetchall()

            for g in grupos:
                if g.get('fecha_creacion'):
                    g['fecha_creacion'] = g['fecha_creacion'].strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return grupos

def obtener_grupo_completo(grupo_id):
    """Obtiene grupo y sus miembros"""
    conexion = obtener_conexion()
    grupo = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT g.*, u.nombre as nombre_lider
                FROM grupos g
                LEFT JOIN usuarios u ON g.leader_id = u.id
                WHERE g.id = %s
            """, (grupo_id,))
            grupo = cursor.fetchone()

            if grupo:
                if grupo.get('fecha_creacion'):
                    grupo['fecha_creacion'] = grupo['fecha_creacion'].strftime('%Y-%m-%d %H:%M:%S')

                # Obtener miembros
                cursor.execute("""
                    SELECT id, nombre, correo
                    FROM usuarios
                    WHERE grupo_id = %s
                    ORDER BY nombre
                """, (grupo_id,))
                miembros = cursor.fetchall()

                grupo['miembros'] = miembros
                grupo['num_miembros'] = len(miembros)
    finally:
        if conexion and conexion.open:
            conexion.close()
    return grupo

def crear_grupo(nombre_grupo, leader_id, active_min, game_state):
    conexion = obtener_conexion()
    nuevo_id = None
    # Generar código único de 8 caracteres (letras mayúsculas y dígitos)
    codigo_grupo = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO grupos
                (nombre_grupo, codigo_grupo, leader_id, fecha_creacion, active_min, game_state)
                VALUES (%s, %s, %s, NOW(), %s, %s)
            """, (
                nombre_grupo, codigo_grupo, leader_id, active_min, game_state
            ))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()
    return {"id": nuevo_id, "codigo_grupo": codigo_grupo}

def actualizar_grupo(grupo_id, nombre_grupo, leader_id, active_min, game_state, active_pin):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM grupos WHERE id = %s", (grupo_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("""
                UPDATE grupos
                SET nombre_grupo = %s, leader_id = %s, active_min = %s,
                    game_state = %s, active_pin = %s
                WHERE id = %s
            """, (
                nombre_grupo, leader_id, active_min, game_state, active_pin, grupo_id
            ))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def eliminar_grupo_cascada(grupo_id):
    """Elimina grupo y desvincula usuarios"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM grupos WHERE id = %s", (grupo_id,))
            if not cursor.fetchone():
                return False

            # Desasociar usuarios del grupo
            cursor.execute("UPDATE usuarios SET grupo_id = NULL WHERE grupo_id = %s", (grupo_id,))

            # Eliminar grupo
            cursor.execute("DELETE FROM grupos WHERE id = %s", (grupo_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True


# ========================================
# CONTROLADOR: HISTORIAL INDIVIDUAL
# ========================================

def obtener_historial_individual(usuario_id=None, cuestionario_id=None):
    conexion = obtener_conexion()
    historial = []
    try:
        with conexion.cursor() as cursor:
            query = """
                SELECT h.*, u.nombre as nombre_estudiante, c.titulo as titulo_cuestionario
                FROM historial_individual h
                LEFT JOIN usuarios u ON h.usuario_id = u.id
                LEFT JOIN cuestionarios c ON h.cuestionario_id = c.id
                WHERE 1=1
            """
            params = []

            if usuario_id:
                query += " AND h.usuario_id = %s"
                params.append(usuario_id)

            if cuestionario_id:
                query += " AND h.cuestionario_id = %s"
                params.append(cuestionario_id)

            query += " ORDER BY h.fecha_realizacion DESC"

            cursor.execute(query, params)
            historial = cursor.fetchall()

            for h in historial:
                if h.get('fecha_realizacion'):
                    h['fecha_realizacion'] = h.get('fecha_realizacion').strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return historial

def obtener_historial_individual_id(historial_id):
    conexion = obtener_conexion()
    registro = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT h.*, u.nombre as nombre_estudiante, c.titulo as titulo_cuestionario
                FROM historial_individual h
                LEFT JOIN usuarios u ON h.usuario_id = u.id
                LEFT JOIN cuestionarios c ON h.cuestionario_id = c.id
                WHERE h.id = %s
            """, (historial_id,))
            registro = cursor.fetchone()

            if registro and registro.get('fecha_realizacion'):
                registro['fecha_realizacion'] = registro.get('fecha_realizacion').strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return registro

def crear_historial_individual(cuestionario_id, usuario_id, nombre_estudiante, puntuacion, num_preguntas, tiempo, sesion_id):
    conexion = obtener_conexion()
    nuevo_id = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO historial_individual
                (cuestionario_id, usuario_id, nombre_estudiante, puntuacion_final,
                 num_preguntas_total, tiempo_total, fecha_realizacion, sesion_id)
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s)
            """, (
                cuestionario_id, usuario_id, nombre_estudiante,
                puntuacion, num_preguntas, tiempo, sesion_id
            ))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()
    return nuevo_id

def actualizar_historial_individual(historial_id, puntuacion, num_preguntas, tiempo):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM historial_individual WHERE id = %s", (historial_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("""
                UPDATE historial_individual
                SET puntuacion_final = %s, num_preguntas_total = %s, tiempo_total = %s
                WHERE id = %s
            """, (puntuacion, num_preguntas, tiempo, historial_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def eliminar_historial_individual(historial_id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM historial_individual WHERE id = %s", (historial_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("DELETE FROM historial_individual WHERE id = %s", (historial_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True


# ========================================
# CONTROLADOR: HISTORIAL PARTIDAS
# ========================================

def obtener_historial_partidas(grupo_id=None):
    conexion = obtener_conexion()
    partidas = []
    try:
        with conexion.cursor() as cursor:
            query = """
                SELECT h.*, g.nombre_grupo, c.titulo as titulo_cuestionario
                FROM historial_partidas h
                LEFT JOIN grupos g ON h.grupo_id = g.id
                LEFT JOIN cuestionarios c ON h.cuestionario_id = c.id
            """

            if grupo_id:
                query += " WHERE h.grupo_id = %s ORDER BY h.fecha_partida DESC"
                cursor.execute(query, (grupo_id,))
            else:
                query += " ORDER BY h.fecha_partida DESC"
                cursor.execute(query)

            partidas = cursor.fetchall()

            for p in partidas:
                if p.get('fecha_partida'):
                    p['fecha_partida'] = p.get('fecha_partida').strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return partidas

def obtener_partida_por_id(partida_id):
    conexion = obtener_conexion()
    partida = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT h.*, g.nombre_grupo, c.titulo as titulo_cuestionario
                FROM historial_partidas h
                LEFT JOIN grupos g ON h.grupo_id = g.id
                LEFT JOIN cuestionarios c ON h.cuestionario_id = c.id
                WHERE h.id = %s
            """, (partida_id,))
            partida = cursor.fetchone()

            if partida and partida.get('fecha_partida'):
                partida['fecha_partida'] = partida.get('fecha_partida').strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return partida

def crear_historial_partida(grupo_id, cuestionario_id, nombre_grupo, titulo_cuestionario, puntuacion, num_preguntas, num_miembros):
    conexion = obtener_conexion()
    nuevo_id = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO historial_partidas
                (grupo_id, cuestionario_id, nombre_grupo, titulo_cuestionario,
                 puntuacion_final, num_preguntas_total, num_miembros, fecha_partida)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                grupo_id, cuestionario_id, nombre_grupo, titulo_cuestionario,
                puntuacion, num_preguntas, num_miembros
            ))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()
    return nuevo_id

def actualizar_historial_partida(partida_id, puntuacion, num_preguntas, num_miembros):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM historial_partidas WHERE id = %s", (partida_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("""
                UPDATE historial_partidas
                SET puntuacion_final = %s, num_preguntas_total = %s, num_miembros = %s
                WHERE id = %s
            """, (puntuacion, num_preguntas, num_miembros, partida_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def eliminar_historial_partida(partida_id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM historial_partidas WHERE id = %s", (partida_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("DELETE FROM historial_partidas WHERE id = %s", (partida_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True


# ========================================
# CONTROLADOR: ESTADÍSTICAS ESTUDIANTES
# ========================================

def obtener_todas_stats(user_id=None):
    conexion = obtener_conexion()
    stats = []
    try:
        with conexion.cursor() as cursor:
            if user_id:
                cursor.execute("""
                    SELECT es.*, u.nombre as nombre_estudiante
                    FROM estudiantes_stats es
                    LEFT JOIN usuarios u ON es.user_id = u.id
                    WHERE es.user_id = %s
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT es.*, u.nombre as nombre_estudiante
                    FROM estudiantes_stats es
                    LEFT JOIN usuarios u ON es.user_id = u.id
                    ORDER BY es.experiencia_total DESC
                """)
            stats = cursor.fetchall()

            for s in stats:
                if s.get('ultima_partida'):
                    s['ultima_partida'] = s['ultima_partida'].strftime('%Y-%m-%d')
                if s.get('fecha_creacion'):
                    s['fecha_creacion'] = s['fecha_creacion'].strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return stats

def obtener_stats_por_usuario(user_id):
    conexion = obtener_conexion()
    stats = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT es.*, u.nombre as nombre_estudiante, u.correo
                FROM estudiantes_stats es
                LEFT JOIN usuarios u ON es.user_id = u.id
                WHERE es.user_id = %s
            """, (user_id,))
            stats = cursor.fetchone()

            if stats:
                if stats.get('ultima_partida'):
                    stats['ultima_partida'] = stats['ultima_partida'].strftime('%Y-%m-%d')
                if stats.get('fecha_creacion'):
                    stats['fecha_creacion'] = stats['fecha_creacion'].strftime('%Y-%m-%d %H:%M:%S')

                # Lógica de negocio: Calcular nivel basado en experiencia
                experiencia = stats.get('experiencia_actual', 0)
                stats['nivel_calculado'] = experiencia // 100 + 1
    finally:
        if conexion and conexion.open:
            conexion.close()
    return stats

def crear_stats_estudiante(user_id, nivel, exp_actual, exp_total, monedas, total_partidas, correctas, incorrectas, mejor_puntaje, racha, mejor_racha):
    conexion = obtener_conexion()
    nuevo_id = None
    try:
        with conexion.cursor() as cursor:
            # Verificar existencia
            cursor.execute("SELECT id FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            if cursor.fetchone():
                return None # Ya existe

            cursor.execute("""
                INSERT INTO estudiantes_stats
                (user_id, nivel, experiencia_actual, experiencia_total, monedas,
                 total_partidas, total_preguntas_correctas, total_preguntas_incorrectas,
                 mejor_puntaje, racha_actual, mejor_racha, fecha_creacion)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                user_id, nivel, exp_actual, exp_total, monedas,
                total_partidas, correctas, incorrectas,
                mejor_puntaje, racha, mejor_racha
            ))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()
    return nuevo_id

def actualizar_stats_estudiante(user_id, nivel, exp_actual, exp_total, monedas, total_partidas, correctas, incorrectas, mejor_puntaje, racha, mejor_racha, ultima_partida):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("""
                UPDATE estudiantes_stats
                SET nivel = %s, experiencia_actual = %s, experiencia_total = %s,
                    monedas = %s, total_partidas = %s, total_preguntas_correctas = %s,
                    total_preguntas_incorrectas = %s, mejor_puntaje = %s,
                    racha_actual = %s, mejor_racha = %s, ultima_partida = %s
                WHERE user_id = %s
            """, (
                nivel, exp_actual, exp_total, monedas, total_partidas,
                correctas, incorrectas, mejor_puntaje, racha, mejor_racha,
                ultima_partida, user_id
            ))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def eliminar_stats_estudiante(user_id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("DELETE FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True


# ========================================
# CONTROLADOR: PARTICIPANTES PARTIDA
# ========================================

def obtener_participantes(partida_id=None, usuario_id=None):
    conexion = obtener_conexion()
    participantes = []
    try:
        with conexion.cursor() as cursor:
            query = """
                SELECT pp.*, u.nombre as nombre_usuario
                FROM participantes_partida pp
                LEFT JOIN usuarios u ON pp.usuario_id = u.id
                WHERE 1=1
            """
            params = []
            if partida_id:
                query += " AND pp.partida_id = %s"
                params.append(partida_id)
            if usuario_id:
                query += " AND pp.usuario_id = %s"
                params.append(usuario_id)

            query += " ORDER BY pp.fecha_participacion DESC"

            cursor.execute(query, params)
            participantes = cursor.fetchall()

            for p in participantes:
                if p.get('fecha_participacion'):
                    p['fecha_participacion'] = p.get('fecha_participacion').strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return participantes

def obtener_participante_id(participante_id):
    conexion = obtener_conexion()
    participante = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT pp.*, u.nombre as nombre_usuario, u.correo
                FROM participantes_partida pp
                LEFT JOIN usuarios u ON pp.usuario_id = u.id
                WHERE pp.id = %s
            """, (participante_id,))
            participante = cursor.fetchone()

            if participante and participante.get('fecha_participacion'):
                participante['fecha_participacion'] = participante.get('fecha_participacion').strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return participante

def registrar_participante(partida_id, usuario_id, nombre_usuario):
    conexion = obtener_conexion()
    nuevo_id = None
    try:
        with conexion.cursor() as cursor:
            # Verificar duplicados
            cursor.execute("""
                SELECT id FROM participantes_partida
                WHERE partida_id = %s AND usuario_id = %s
            """, (partida_id, usuario_id))

            if cursor.fetchone():
                return None # Ya existe

            cursor.execute("""
                INSERT INTO participantes_partida
                (partida_id, usuario_id, nombre_usuario, fecha_participacion)
                VALUES (%s, %s, %s, NOW())
            """, (partida_id, usuario_id, nombre_usuario))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()
    return nuevo_id

def actualizar_participante(participante_id, nombre_usuario):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM participantes_partida WHERE id = %s", (participante_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("""
                UPDATE participantes_partida
                SET nombre_usuario = %s
                WHERE id = %s
            """, (nombre_usuario, participante_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def eliminar_participante(participante_id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM participantes_partida WHERE id = %s", (participante_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("DELETE FROM participantes_partida WHERE id = %s", (participante_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True


# ========================================
# CONTROLADOR: PROGRESO GRUPAL
# ========================================

def obtener_progreso_grupal(grupo_id=None, usuario_id=None, pregunta_index=None):
    conexion = obtener_conexion()
    progresos = []
    try:
        with conexion.cursor() as cursor:
            query = """
                SELECT pg.*, u.nombre as nombre_usuario, g.nombre_grupo
                FROM progreso_grupal pg
                LEFT JOIN usuarios u ON pg.usuario_id = u.id
                LEFT JOIN grupos g ON pg.grupo_id = g.id
                WHERE 1=1
            """
            params = []
            if grupo_id:
                query += " AND pg.grupo_id = %s"
                params.append(grupo_id)
            if usuario_id:
                query += " AND pg.usuario_id = %s"
                params.append(usuario_id)
            if pregunta_index is not None:
                query += " AND pg.pregunta_index = %s"
                params.append(pregunta_index)

            query += " ORDER BY pg.fecha_respuesta DESC"

            cursor.execute(query, params)
            progresos = cursor.fetchall()

            for p in progresos:
                if p.get('fecha_respuesta'):
                    p['fecha_respuesta'] = p.get('fecha_respuesta').strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return progresos

def obtener_progreso_id(progreso_id):
    conexion = obtener_conexion()
    progreso = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT pg.*, u.nombre as nombre_usuario, g.nombre_grupo
                FROM progreso_grupal pg
                LEFT JOIN usuarios u ON pg.usuario_id = u.id
                LEFT JOIN grupos g ON pg.grupo_id = g.id
                WHERE pg.id = %s
            """, (progreso_id,))
            progreso = cursor.fetchone()

            if progreso and progreso.get('fecha_respuesta'):
                progreso['fecha_respuesta'] = progreso.get('fecha_respuesta').strftime('%Y-%m-%d %H:%M:%S')
    finally:
        if conexion and conexion.open:
            conexion.close()
    return progreso

def registrar_progreso_upsert(grupo_id, usuario_id, pregunta_index, respondio):
    """Usa ON DUPLICATE KEY UPDATE para registrar o actualizar"""
    conexion = obtener_conexion()
    nuevo_id = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO progreso_grupal
                (grupo_id, usuario_id, pregunta_index, respondio, fecha_respuesta)
                VALUES (%s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                respondio = %s, fecha_respuesta = NOW()
            """, (
                grupo_id, usuario_id, pregunta_index, respondio, respondio
            ))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()
    return nuevo_id

def actualizar_progreso_manual(progreso_id, pregunta_index, respondio):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM progreso_grupal WHERE id = %s", (progreso_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("""
                UPDATE progreso_grupal
                SET pregunta_index = %s, respondio = %s, fecha_respuesta = NOW()
                WHERE id = %s
            """, (pregunta_index, respondio, progreso_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def eliminar_progreso(progreso_id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM progreso_grupal WHERE id = %s", (progreso_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("DELETE FROM progreso_grupal WHERE id = %s", (progreso_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True


# ========================================
# CONTROLADOR: RESPUESTAS INDIVIDUALES
# ========================================

def obtener_respuestas_individuales(historial_id=None, pregunta_id=None):
    conexion = obtener_conexion()
    respuestas = []
    try:
        with conexion.cursor() as cursor:
            query = """
                SELECT ri.*, p.pregunta as texto_pregunta
                FROM respuestas_individuales ri
                LEFT JOIN preguntas p ON ri.pregunta_id = p.id
                WHERE 1=1
            """
            params = []
            if historial_id:
                query += " AND ri.historial_id = %s"
                params.append(historial_id)
            if pregunta_id:
                query += " AND ri.pregunta_id = %s"
                params.append(pregunta_id)

            query += " ORDER BY ri.id ASC"

            cursor.execute(query, params)
            respuestas = cursor.fetchall()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return respuestas

def obtener_respuesta_individual_id(respuesta_id):
    conexion = obtener_conexion()
    respuesta = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT ri.*, p.pregunta as texto_pregunta,
                       p.opcion_a, p.opcion_b, p.opcion_c, p.opcion_d,
                       p.respuesta_correcta
                FROM respuestas_individuales ri
                LEFT JOIN preguntas p ON ri.pregunta_id = p.id
                WHERE ri.id = %s
            """, (respuesta_id,))
            respuesta = cursor.fetchone()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return respuesta

def registrar_respuesta_individual(historial_id, pregunta_id, respuesta_estudiante, es_correcta, puntos, tiempo):
    conexion = obtener_conexion()
    nuevo_id = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO respuestas_individuales
                (historial_id, pregunta_id, respuesta_estudiante,
                 es_correcta, puntos, tiempo_respuesta)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                historial_id, pregunta_id, respuesta_estudiante,
                es_correcta, puntos, tiempo
            ))
            conexion.commit()
            nuevo_id = cursor.lastrowid
    finally:
        if conexion and conexion.open:
            conexion.close()
    return nuevo_id

def actualizar_respuesta_individual(respuesta_id, respuesta_estudiante, es_correcta, puntos, tiempo):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM respuestas_individuales WHERE id = %s", (respuesta_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("""
                UPDATE respuestas_individuales
                SET respuesta_estudiante = %s, es_correcta = %s,
                    puntos = %s, tiempo_respuesta = %s
                WHERE id = %s
            """, (
                respuesta_estudiante, es_correcta, puntos, tiempo, respuesta_id
            ))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True

def eliminar_respuesta_individual(respuesta_id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM respuestas_individuales WHERE id = %s", (respuesta_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("DELETE FROM respuestas_individuales WHERE id = %s", (respuesta_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True


# ========================================
# CONTROLADOR: RECONOCIMIENTO FACIAL
# ========================================

def obtener_todos_reconocimientos():
    conexion = obtener_conexion()
    registros = []
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT rf.id, rf.usuario_id, rf.fecha_registro,
                       u.nombre, u.correo
                FROM reconocimiento_facial rf
                LEFT JOIN usuarios u ON rf.usuario_id = u.id
                ORDER BY rf.fecha_registro DESC
            """)
            registros = cursor.fetchall()

            for r in registros:
                if r.get('fecha_registro'):
                    r['fecha_registro'] = r.get('fecha_registro').strftime('%Y-%m-%d %H:%M:%S')
                r['tiene_embedding'] = True
    finally:
        if conexion and conexion.open:
            conexion.close()
    return registros

def obtener_reconocimiento_id(reconocimiento_id):
    conexion = obtener_conexion()
    registro = None
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT rf.id, rf.usuario_id, rf.fecha_registro,
                       u.nombre, u.correo
                FROM reconocimiento_facial rf
                LEFT JOIN usuarios u ON rf.usuario_id = u.id
                WHERE rf.id = %s
            """, (reconocimiento_id,))
            registro = cursor.fetchone()

            if registro:
                if registro.get('fecha_registro'):
                    registro['fecha_registro'] = registro.get('fecha_registro').strftime('%Y-%m-%d %H:%M:%S')
                registro['tiene_embedding'] = True
    finally:
        if conexion and conexion.open:
            conexion.close()
    return registro

def guardar_o_actualizar_embedding(usuario_id, embedding_list):
    """Maneja la lógica de Insertar o Actualizar el embedding"""
    conexion = obtener_conexion()
    resultado = {"id": None, "mensaje": ""}

    try:
        # Convertir lista a JSON string
        embedding_json = json.dumps(embedding_list)

        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM reconocimiento_facial WHERE usuario_id = %s", (usuario_id,))
            existing = cursor.fetchone()

            if existing:
                cursor.execute("""
                    UPDATE reconocimiento_facial
                    SET embedding = %s, fecha_registro = NOW()
                    WHERE usuario_id = %s
                """, (embedding_json, usuario_id))
                resultado["id"] = existing['id']
                resultado["mensaje"] = "Reconocimiento facial actualizado exitosamente"
            else:
                cursor.execute("""
                    INSERT INTO reconocimiento_facial
                    (usuario_id, embedding, fecha_registro)
                    VALUES (%s, %s, NOW())
                """, (usuario_id, embedding_json))
                resultado["id"] = cursor.lastrowid
                resultado["mensaje"] = "Reconocimiento facial registrado exitosamente"

            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return resultado

def actualizar_embedding_directo(reconocimiento_id, embedding_list, usuario_solicitante, rol_solicitante):
    """Verifica permisos y actualiza por ID de registro"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT usuario_id FROM reconocimiento_facial WHERE id = %s", (reconocimiento_id,))
            registro = cursor.fetchone()

            if not registro:
                return {"status": 404, "message": "Registro no encontrado"}

            # Verificar permisos (Lógica de negocio: solo el propio usuario o profesor)
            if rol_solicitante != 'profesor' and registro['usuario_id'] != usuario_solicitante:
                return {"status": 403, "message": "No tienes permisos para actualizar este registro"}

            embedding_json = json.dumps(embedding_list)

            cursor.execute("""
                UPDATE reconocimiento_facial
                SET embedding = %s, fecha_registro = NOW()
                WHERE id = %s
            """, (embedding_json, reconocimiento_id))
            conexion.commit()

            return {"status": 200, "message": "Reconocimiento facial actualizado exitosamente"}
    finally:
        if conexion and conexion.open:
            conexion.close()

def eliminar_reconocimiento(reconocimiento_id):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM reconocimiento_facial WHERE id = %s", (reconocimiento_id,))
            if not cursor.fetchone():
                return False

            cursor.execute("DELETE FROM reconocimiento_facial WHERE id = %s", (reconocimiento_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return True