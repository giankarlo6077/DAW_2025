from bd import obtener_conexion
import uuid
from datetime import datetime
import pandas as pd
from io import BytesIO

# ========================================
# CONTROLADOR: LÓGICA DE JUEGO GRUPAL (ESTUDIANTE)
# ========================================

def procesar_ingreso_juego_grupal(user_id, pin):
    """
    Valida ingreso a juego grupal. Si es líder, configura el grupo.
    Retorna: (success: bool, mensaje: str, grupo_id: int)
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Verificar grupo del usuario
            cursor.execute("""
                SELECT g.id, g.lider_id, g.nombre_grupo 
                FROM grupos g
                JOIN usuarios u ON g.id = u.grupo_id
                WHERE u.id = %s
            """, (user_id,))
            grupo = cursor.fetchone()

            if not grupo:
                return False, "Debes estar en un grupo para jugar en modo grupal.", None

            # 2. Validar cuestionario
            cursor.execute("SELECT id, titulo, modo_juego FROM cuestionarios WHERE codigo_pin = %s", (pin,))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                return False, f"No se encontró ningún cuestionario con el PIN '{pin}'.", None
            
            if cuestionario['modo_juego'] != 'grupal':
                return False, f"El cuestionario '{cuestionario['titulo']}' es INDIVIDUAL.", None

            # 3. Si es líder, actualizar estado del grupo
            if grupo['lider_id'] == user_id:
                cursor.execute("""
                    UPDATE grupos
                    SET active_pin = %s,
                        game_state = 'waiting',
                        current_question_index = 0,
                        current_score = 0,
                        ultima_respuesta_correcta = 0
                    WHERE id = %s
                """, (pin, grupo['id']))
                conexion.commit()
            
            return True, "OK", grupo['id']
    finally:
        if conexion and conexion.open:
            conexion.close()

def obtener_datos_sala_espera(grupo_id, user_id):
    """Obtiene datos de sala de espera y valida membresía"""
    conexion = obtener_conexion()
    resultado = {"grupo": None, "miembros": [], "es_miembro": False}
    try:
        with conexion.cursor() as cursor:
            # Datos grupo
            cursor.execute("SELECT * FROM grupos WHERE id = %s", (grupo_id,))
            resultado["grupo"] = cursor.fetchone()
            
            if resultado["grupo"]:
                # Miembros
                cursor.execute("SELECT id, nombre FROM usuarios WHERE grupo_id = %s ORDER BY id", (grupo_id,))
                resultado["miembros"] = cursor.fetchall()
                
                # Validar si usuario actual está en la lista
                resultado["es_miembro"] = any(m['id'] == user_id for m in resultado["miembros"])
    finally:
        if conexion and conexion.open:
            conexion.close()
    return resultado

def iniciar_partida_lider(grupo_id, user_id):
    """El líder cambia el estado a 'playing'"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT lider_id, active_pin FROM grupos WHERE id = %s", (grupo_id,))
            grupo = cursor.fetchone()

            if not grupo: return False, "Grupo no encontrado"
            if grupo['lider_id'] != user_id: return False, "Solo el líder puede iniciar"
            if not grupo['active_pin']: return False, "No hay cuestionario asignado"

            cursor.execute("""
                UPDATE grupos SET game_state = 'playing', current_question_index = 0, current_score = 0
                WHERE id = %s
            """, (grupo_id,))
            conexion.commit()
            return True, "Partida iniciada"
    finally:
        if conexion and conexion.open:
            conexion.close()

def obtener_datos_partida_activa(grupo_id):
    """Obtiene datos para la pantalla de juego"""
    conexion = obtener_conexion()
    datos = {"grupo": None, "cuestionario": None}
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM grupos WHERE id = %s", (grupo_id,))
            datos["grupo"] = cursor.fetchone()
            
            if datos["grupo"] and datos["grupo"].get('active_pin'):
                cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s", (datos["grupo"]['active_pin'],))
                datos["cuestionario"] = cursor.fetchone()
    finally:
        if conexion and conexion.open:
            conexion.close()
    return datos

def procesar_resultados_grupo(grupo_id, user_id):
    """
    Maneja la lógica compleja de resultados:
    1. Valida membresía.
    2. Si el juego terminó ('finished'), guarda en historial (Transacción).
    3. Si ya se guardó, recupera del historial.
    """
    conexion = obtener_conexion()
    res = {
        "error": None, 
        "grupo": None, 
        "cuestionario": None, 
        "miembros": []
    }
    
    try:
        with conexion.cursor() as cursor:
            # 1. Obtener grupo
            cursor.execute("SELECT * FROM grupos WHERE id = %s", (grupo_id,))
            grupo = cursor.fetchone()
            res["grupo"] = grupo

            # 2. Validar membresía
            if grupo:
                cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
                usuario = cursor.fetchone()
                if not usuario or usuario['grupo_id'] != grupo_id:
                    res["error"] = "No perteneces a este grupo"
                    return res

            # 3. Obtener Cuestionario Activo
            cuestionario = None
            if grupo and grupo['active_pin']:
                cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s", (grupo['active_pin'],))
                cuestionario = cursor.fetchone()
                res["cuestionario"] = cuestionario

            # 4. Obtener Miembros actuales
            cursor.execute("SELECT id, nombre FROM usuarios WHERE grupo_id = %s", (grupo_id,))
            miembros = cursor.fetchall()
            res["miembros"] = miembros

            # --- LÓGICA DE GUARDADO ---
            if cuestionario and grupo and grupo.get('game_state') == 'finished':
                # Insertar Historial Partida
                cursor.execute("""
                    INSERT INTO historial_partidas
                    (grupo_id, cuestionario_id, nombre_grupo, titulo_cuestionario, puntuacion_final, num_preguntas_total, num_miembros)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (grupo_id, cuestionario['id'], grupo['nombre_grupo'], cuestionario['titulo'],
                      grupo['current_score'], cuestionario['num_preguntas'], len(miembros)))
                
                partida_id = cursor.lastrowid

                # Insertar Participantes
                for miembro in miembros:
                    cursor.execute("""
                        INSERT INTO participantes_partida (partida_id, usuario_id, nombre_usuario)
                        VALUES (%s, %s, %s)
                    """, (partida_id, miembro['id'], miembro['nombre']))

                # Resetear Grupo
                cursor.execute("""
                    UPDATE grupos
                    SET active_pin = NULL, game_state = 'archived', current_question_index = 0
                    WHERE id = %s
                """, (grupo_id,))
                
                conexion.commit()
            
            # --- LÓGICA DE RECUPERACIÓN (Si ya fue archivado) ---
            elif not cuestionario:
                # Buscar último historial
                cursor.execute("""
                    SELECT h.*, c.titulo, c.descripcion, c.num_preguntas, c.tiempo_pregunta, c.modo_juego
                    FROM historial_partidas h
                    JOIN cuestionarios c ON h.cuestionario_id = c.id
                    JOIN participantes_partida p ON h.id = p.partida_id
                    WHERE p.usuario_id = %s AND h.grupo_id = %s
                    ORDER BY h.fecha_partida DESC LIMIT 1
                """, (user_id, grupo_id))
                historial = cursor.fetchone()

                if historial:
                    # Reconstruir objetos para la vista
                    res["cuestionario"] = {
                        'titulo': historial['titulo'],
                        'descripcion': historial['descripcion'],
                        'num_preguntas': historial['num_preguntas'],
                        'tiempo_pregunta': historial['tiempo_pregunta'],
                        'modo_juego': historial['modo_juego']
                    }
                    if not res["grupo"]:
                        res["grupo"] = {'nombre_grupo': historial['nombre_grupo'], 'current_score': historial['puntuacion_final']}
                    else:
                        res["grupo"]['current_score'] = historial['puntuacion_final']

                    # Recuperar miembros del historial
                    cursor.execute("SELECT nombre_usuario FROM participantes_partida WHERE partida_id = %s", (historial['id'],))
                    m_hist = cursor.fetchall()
                    res["miembros"] = [{'nombre': m['nombre_usuario']} for m in m_hist]
                else:
                    res["error"] = "No se encontraron resultados de la partida"

    finally:
        if conexion and conexion.open:
            conexion.close()
    
    return res


# ========================================
# CONTROLADOR: VISTAS Y GESTIÓN PROFESOR
# ========================================

def obtener_datos_sala_profesor_grupal(codigo_pin, profesor_id):
    """Datos para la sala de espera (vista profesor)"""
    conexion = obtener_conexion()
    datos = {"cuestionario": None, "grupos": []}
    try:
        with conexion.cursor() as cursor:
            # Cuestionario
            cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s AND profesor_id = %s", (codigo_pin, profesor_id))
            datos["cuestionario"] = cursor.fetchone()

            if datos["cuestionario"]:
                # Grupos esperando con sus miembros concatenados
                cursor.execute("""
                    SELECT g.id, g.nombre_grupo, g.game_state, g.lider_id, COUNT(u.id) as num_miembros
                    FROM grupos g
                    LEFT JOIN usuarios u ON g.id = u.grupo_id
                    WHERE g.active_pin = %s
                    GROUP BY g.id, g.nombre_grupo, g.game_state, g.lider_id
                    ORDER BY g.fecha_creacion DESC
                """, (codigo_pin,))
                grupos = cursor.fetchall()

                # Agregar lista de nombres de miembros a cada grupo
                for grupo in grupos:
                    cursor.execute("SELECT nombre FROM usuarios WHERE grupo_id = %s ORDER BY id", (grupo['id'],))
                    ms = cursor.fetchall()
                    grupo['miembros'] = ', '.join([m['nombre'] for m in ms]) if ms else 'Sin miembros'
                
                datos["grupos"] = grupos
    finally:
        if conexion and conexion.open:
            conexion.close()
    return datos

def iniciar_todos_grupos(codigo_pin, profesor_id):
    """Profesor inicia todas las partidas grupales"""
    conexion = obtener_conexion()
    afectados = 0
    try:
        with conexion.cursor() as cursor:
            # Validar propiedad
            cursor.execute("SELECT id FROM cuestionarios WHERE codigo_pin = %s AND profesor_id = %s", (codigo_pin, profesor_id))
            if not cursor.fetchone(): return False, "Cuestionario no encontrado"

            # Update masivo
            cursor.execute("""
                UPDATE grupos
                SET game_state = 'playing', current_question_index = 0, current_score = 0
                WHERE active_pin = %s AND game_state = 'waiting'
            """, (codigo_pin,))
            afectados = cursor.rowcount
            conexion.commit()
            return True, afectados
    finally:
        if conexion and conexion.open:
            conexion.close()

def obtener_vista_live_profesor_grupal(codigo_pin, profesor_id):
    """Datos para el monitoreo en vivo (Grupal)"""
    conexion = obtener_conexion()
    res = {"cuestionario": None, "preguntas": [], "grupos_ids": [], "total_grupos": 0}
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s AND profesor_id = %s", (codigo_pin, profesor_id))
            res["cuestionario"] = cursor.fetchone()

            if res["cuestionario"]:
                cursor.execute("SELECT id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta FROM preguntas WHERE cuestionario_id = %s ORDER BY orden", (res["cuestionario"]['id'],))
                res["preguntas"] = cursor.fetchall()

                cursor.execute("SELECT id FROM grupos WHERE active_pin = %s AND game_state IN ('waiting', 'playing')", (codigo_pin,))
                grupos = cursor.fetchall()
                res["grupos_ids"] = [g['id'] for g in grupos]
                res["total_grupos"] = len(grupos)
    finally:
        if conexion and conexion.open: conexion.close()
    return res

def obtener_vista_live_profesor_individual(codigo_pin, profesor_id):
    """Datos para el monitoreo en vivo (Individual)"""
    conexion = obtener_conexion()
    res = {"cuestionario": None, "preguntas": [], "sesion_id": None, "total_estudiantes": 0}
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s AND profesor_id = %s", (codigo_pin, profesor_id))
            res["cuestionario"] = cursor.fetchone()

            if res["cuestionario"]:
                cursor.execute("SELECT id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta FROM preguntas WHERE cuestionario_id = %s ORDER BY orden", (res["cuestionario"]['id'],))
                res["preguntas"] = cursor.fetchall()

                cursor.execute("SELECT DISTINCT sesion_id FROM salas_espera WHERE codigo_pin = %s AND estado = 'playing' LIMIT 1", (codigo_pin,))
                ses = cursor.fetchone()
                if ses:
                    res["sesion_id"] = ses['sesion_id']
                    cursor.execute("SELECT COUNT(*) as total FROM salas_espera WHERE sesion_id = %s", (ses['sesion_id'],))
                    res["total_estudiantes"] = cursor.fetchone()['total']
    finally:
        if conexion and conexion.open: conexion.close()
    return res

# ========================================
# CONTROLADOR: APIs AUXILIARES (AJAX)
# ========================================

def api_obtener_miembros_grupo(grupo_id):
    conexion = obtener_conexion()
    data = {"miembros": [], "lider_id": None}
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT lider_id FROM grupos WHERE id = %s", (grupo_id,))
            grupo = cursor.fetchone()
            if grupo:
                data["lider_id"] = grupo['lider_id']
                cursor.execute("SELECT id, nombre FROM usuarios WHERE grupo_id = %s ORDER BY id", (grupo_id,))
                data["miembros"] = cursor.fetchall()
            else:
                return None
    finally:
        if conexion and conexion.open: conexion.close()
    return data

def api_estudiantes_sesion(sesion_id):
    conexion = obtener_conexion()
    estudiantes = []
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.nombre, se.estado,
                COALESCE((SELECT COUNT(DISTINCT r.pregunta_id) 
                          FROM respuestas_individuales r JOIN historial_individual h ON r.historial_id = h.id 
                          WHERE h.usuario_id = u.id AND h.sesion_id = %s), 0) as pregunta_actual
                FROM salas_espera se JOIN usuarios u ON se.usuario_id = u.id
                WHERE se.sesion_id = %s ORDER BY u.nombre
            """, (sesion_id, sesion_id))
            estudiantes = cursor.fetchall()
    finally:
        if conexion and conexion.open: conexion.close()
    return estudiantes

def api_ranking_sesion(sesion_id):
    conexion = obtener_conexion()
    ranking = []
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT u.nombre, h.puntuacion_final as puntuacion, h.tiempo_total,
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
        if conexion and conexion.open: conexion.close()
    return ranking

def api_grupos_esperando_pin(codigo_pin):
    conexion = obtener_conexion()
    grupos = []
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT g.id, g.nombre_grupo, g.game_state, COUNT(u.id) as num_miembros
                FROM grupos g LEFT JOIN usuarios u ON g.id = u.grupo_id
                WHERE g.active_pin = %s GROUP BY g.id
            """, (codigo_pin,))
            grupos = cursor.fetchall()
    finally:
        if conexion and conexion.open: conexion.close()
    return grupos
    
# ========================================
# GESTIÓN DE PARTIDAS (PROFESOR Y LÍDER)
# ========================================

def iniciar_partidas_masivo_profesor(codigo_pin, profesor_id):
    """
    El profesor inicia todas las partidas que están en espera con ese PIN.
    Retorna: (success: bool, message: str, count: int)
    """
    conexion = obtener_conexion()
    grupos_afectados = 0
    try:
        with conexion.cursor() as cursor:
            # 1. Verificar propiedad del cuestionario
            cursor.execute("""
                SELECT id FROM cuestionarios
                WHERE codigo_pin = %s AND profesor_id = %s
            """, (codigo_pin, profesor_id))

            if not cursor.fetchone():
                return False, "Cuestionario no encontrado o no tienes permiso.", 0

            # 2. Actualizar grupos en espera
            cursor.execute("""
                UPDATE grupos
                SET game_state = 'playing',
                    current_question_index = 0,
                    current_score = 0
                WHERE active_pin = %s AND game_state = 'waiting'
            """, (codigo_pin,))

            grupos_afectados = cursor.rowcount
            conexion.commit()
            
            return True, "OK", grupos_afectados
    finally:
        if conexion and conexion.open:
            conexion.close()

def iniciar_partida_individual_lider(grupo_id, user_id):
    """El líder inicia su propia partida desde la sala de espera"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Validaciones
            cursor.execute("SELECT lider_id, active_pin FROM grupos WHERE id = %s", (grupo_id,))
            grupo = cursor.fetchone()

            if not grupo: return False, "Grupo no encontrado"
            if grupo['lider_id'] != user_id: return False, "Solo el líder puede iniciar"
            if not grupo['active_pin']: return False, "No hay cuestionario asignado"

            # Actualizar
            cursor.execute("""
                UPDATE grupos
                SET game_state = 'playing',
                    current_question_index = 0,
                    current_score = 0
                WHERE id = %s
            """, (grupo_id,))
            conexion.commit()
            return True, "Partida iniciada"
    finally:
        if conexion and conexion.open:
            conexion.close()

# ========================================
# DATOS Y APIs (Sala de Espera y API Grupos)
# ========================================

def obtener_datos_sala_espera(grupo_id, user_id):
    """Obtiene datos del grupo y miembros para la sala de espera"""
    conexion = obtener_conexion()
    res = {"grupo": None, "miembros": [], "es_miembro": False}
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM grupos WHERE id = %s", (grupo_id,))
            res["grupo"] = cursor.fetchone()

            if res["grupo"]:
                cursor.execute("SELECT id, nombre FROM usuarios WHERE grupo_id = %s ORDER BY id", (grupo_id,))
                res["miembros"] = cursor.fetchall()
                # Verificar si el usuario actual está en la lista
                res["es_miembro"] = any(m['id'] == user_id for m in res["miembros"])
    finally:
        if conexion and conexion.open: conexion.close()
    return res

def obtener_lista_grupos_esperando(codigo_pin):
    """API: Retorna lista de grupos esperando por PIN"""
    conexion = obtener_conexion()
    grupos = []
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT g.id, g.nombre_grupo, g.game_state,
                       COUNT(u.id) as num_miembros
                FROM grupos g
                LEFT JOIN usuarios u ON g.id = u.grupo_id
                WHERE g.active_pin = %s
                GROUP BY g.id
            """, (codigo_pin,))
            grupos = cursor.fetchall()
    finally:
        if conexion and conexion.open: conexion.close()
    return grupos

# ========================================
# RESULTADOS Y FINALIZACIÓN
# ========================================

def procesar_resultados_finales(grupo_id, user_id):
    """
    Lógica compleja de resultados:
    1. Guarda historial si el juego terminó ('finished').
    2. Archiva el grupo.
    3. O recupera datos del historial si ya fue archivado.
    """
    conexion = obtener_conexion()
    resultado = {
        "error": None,
        "grupo": None,
        "cuestionario": None,
        "miembros": []
    }
    
    try:
        with conexion.cursor() as cursor:
            # 1. Datos Básicos
            cursor.execute("SELECT * FROM grupos WHERE id = %s", (grupo_id,))
            grupo = cursor.fetchone()
            resultado["grupo"] = grupo

            # 2. Validar Membresía
            if grupo:
                cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
                usuario = cursor.fetchone()
                if not usuario or usuario['grupo_id'] != grupo_id:
                    resultado["error"] = "No perteneces a este grupo"
                    return resultado

            # 3. Intentar obtener cuestionario activo
            cuestionario = None
            if grupo and grupo['active_pin']:
                cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s", (grupo['active_pin'],))
                cuestionario = cursor.fetchone()
            resultado["cuestionario"] = cuestionario

            # 4. Obtener miembros actuales
            cursor.execute("SELECT id, nombre FROM usuarios WHERE grupo_id = %s", (grupo_id,))
            miembros = cursor.fetchall()
            resultado["miembros"] = miembros

            # CASO A: Juego recién terminado -> GUARDAR HISTORIAL
            if cuestionario and grupo and grupo.get('game_state') == 'finished':
                # Insertar historial
                cursor.execute("""
                    INSERT INTO historial_partidas
                    (grupo_id, cuestionario_id, nombre_grupo, titulo_cuestionario, puntuacion_final, num_preguntas_total, num_miembros)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (grupo_id, cuestionario['id'], grupo['nombre_grupo'], cuestionario['titulo'],
                      grupo['current_score'], cuestionario['num_preguntas'], len(miembros)))
                
                partida_id = cursor.lastrowid

                # Guardar participantes
                for m in miembros:
                    cursor.execute("""
                        INSERT INTO participantes_partida (partida_id, usuario_id, nombre_usuario)
                        VALUES (%s, %s, %s)
                    """, (partida_id, m['id'], m['nombre']))

                # Archivar grupo
                cursor.execute("""
                    UPDATE grupos
                    SET active_pin = NULL, game_state = 'archived', current_question_index = 0
                    WHERE id = %s
                """, (grupo_id,))
                
                conexion.commit()
            
            # CASO B: Juego ya archivado -> LEER HISTORIAL
            elif not cuestionario:
                cursor.execute("""
                    SELECT h.*, c.titulo, c.descripcion, c.num_preguntas, c.tiempo_pregunta, c.modo_juego
                    FROM historial_partidas h
                    JOIN cuestionarios c ON h.cuestionario_id = c.id
                    JOIN participantes_partida p ON h.id = p.partida_id
                    WHERE p.usuario_id = %s AND h.grupo_id = %s
                    ORDER BY h.fecha_partida DESC LIMIT 1
                """, (user_id, grupo_id))
                historial = cursor.fetchone()

                if historial:
                    # Reconstruir datos para la vista
                    resultado["cuestionario"] = {
                        'titulo': historial['titulo'], 'descripcion': historial['descripcion'],
                        'num_preguntas': historial['num_preguntas'], 'modo_juego': historial['modo_juego']
                    }
                    if not resultado["grupo"]:
                        resultado["grupo"] = {'nombre_grupo': historial['nombre_grupo'], 'current_score': historial['puntuacion_final']}
                    else:
                        resultado["grupo"]['current_score'] = historial['puntuacion_final']
                    
                    # Recuperar miembros del historial
                    cursor.execute("SELECT nombre_usuario FROM participantes_partida WHERE partida_id = %s", (historial['id'],))
                    m_hist = cursor.fetchall()
                    resultado["miembros"] = [{'nombre': m['nombre_usuario']} for m in m_hist]
                else:
                    resultado["error"] = "No se encontraron resultados de la partida"

    finally:
        if conexion and conexion.open:
            conexion.close()
    
    return resultado

# ========================================
# JUEGO INDIVIDUAL: GESTIÓN DE SALA DE ESPERA
# ========================================

def obtener_datos_sala_profesor_individual(codigo_pin, profesor_id):
    """Verifica y obtiene datos para la sala de espera individual del profesor"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT * FROM cuestionarios
                WHERE codigo_pin = %s AND profesor_id = %s
            """, (codigo_pin, profesor_id))
            cuestionario = cursor.fetchone()
            return cuestionario
    finally:
        if conexion and conexion.open:
            conexion.close()

def obtener_estudiantes_esperando_lista(codigo_pin):
    """
    Obtiene lista de estudiantes en espera y formatea el tiempo transcurrido.
    Retorna lista de dicts.
    """
    conexion = obtener_conexion()
    estudiantes = []
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.nombre, se.estado, se.fecha_ingreso
                FROM salas_espera se
                JOIN usuarios u ON se.usuario_id = u.id
                WHERE se.codigo_pin = %s
                ORDER BY se.fecha_ingreso ASC
            """, (codigo_pin,))
            estudiantes = cursor.fetchall()

            # Lógica de formato de tiempo (Mofida desde la ruta al controlador)
            for est in estudiantes:
                est['timestamp'] = 'Ahora'
                if est['fecha_ingreso']:
                    try:
                        tiempo = datetime.now() - est['fecha_ingreso']
                        segundos = int(tiempo.total_seconds())
                        if segundos < 60:
                            est['timestamp'] = f'Hace {segundos}s'
                        elif segundos < 3600:
                            est['timestamp'] = f'Hace {segundos // 60}m'
                        else:
                            est['timestamp'] = est['fecha_ingreso'].strftime('%H:%M')
                    except Exception:
                        pass
    finally:
        if conexion and conexion.open:
            conexion.close()
    return estudiantes

def iniciar_partidas_individuales_masivo(codigo_pin, profesor_id):
    """
    Genera una SESION_ID única e inicia el juego para todos los estudiantes en espera.
    Retorna: (success, data/message)
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Validar propiedad
            cursor.execute("SELECT id FROM cuestionarios WHERE codigo_pin=%s AND profesor_id=%s", (codigo_pin, profesor_id))
            if not cursor.fetchone():
                return False, "Cuestionario no encontrado"

            # 2. Generar ID de sesión
            sesion_id = f"SESION_{codigo_pin}_{uuid.uuid4().hex[:8]}"

            # 3. Actualizar estado en BD
            cursor.execute("""
                UPDATE salas_espera
                SET estado = 'playing', sesion_id = %s
                WHERE codigo_pin = %s AND estado = 'waiting'
            """, (sesion_id, codigo_pin))
            
            afectados = cursor.rowcount
            conexion.commit()

            return True, {
                "sesion_id": sesion_id,
                "estudiantes_iniciados": afectados
            }
    finally:
        if conexion and conexion.open:
            conexion.close()

def obtener_estado_estudiante_individual(usuario_id):
    """Consulta el estado actual del estudiante en la sala"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT estado, codigo_pin FROM salas_espera WHERE usuario_id = %s", (usuario_id,))
            return cursor.fetchone()
    finally:
        if conexion and conexion.open:
            conexion.close()

def salir_sala_espera_individual(usuario_id):
    """Elimina al estudiante de la sala de espera"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("DELETE FROM salas_espera WHERE usuario_id = %s", (usuario_id,))
            conexion.commit()
            return True
    finally:
        if conexion and conexion.open:
            conexion.close()

def ingresar_sala_espera_individual(user_id, codigo_pin):
    """Registra al estudiante en la sala de espera si no está"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM salas_espera WHERE usuario_id = %s AND codigo_pin = %s", (user_id, codigo_pin))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO salas_espera (usuario_id, codigo_pin, estado, fecha_ingreso)
                    VALUES (%s, %s, 'waiting', NOW())
                """, (user_id, codigo_pin))
                conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()
            
# ========================================
# JUEGO INDIVIDUAL: INICIO Y UNIÓN
# ========================================

def procesar_union_individual(user_id, codigo_pin):
    """Valida y registra al estudiante en la sala de espera individual"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Validar Cuestionario
            cursor.execute("SELECT id, modo_juego FROM cuestionarios WHERE codigo_pin = %s", (codigo_pin,))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                return False, "Código PIN no válido"
            
            if cuestionario["modo_juego"] != "individual":
                return False, "Este PIN no corresponde a un cuestionario individual"

            # 2. Registrar/Actualizar en Sala de Espera
            cursor.execute("SELECT id FROM salas_espera WHERE usuario_id = %s AND codigo_pin = %s", (user_id, codigo_pin))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO salas_espera (usuario_id, codigo_pin, estado, fecha_ingreso)
                    VALUES (%s, %s, 'waiting', NOW())
                """, (user_id, codigo_pin))
            else:
                cursor.execute("""
                    UPDATE salas_espera SET estado = 'waiting', fecha_ingreso = NOW()
                    WHERE usuario_id = %s AND codigo_pin = %s
                """, (user_id, codigo_pin))
            
            conexion.commit()
            return True, "OK"
    finally:
        if conexion and conexion.open: conexion.close()

def iniciar_juego_individual_logica(user_id, codigo_pin, nombre_estudiante):
    """Prepara la partida individual: obtiene datos y crea historial"""
    conexion = obtener_conexion()
    res = {"cuestionario": None, "preguntas": [], "sesion_id": None}
    
    try:
        with conexion.cursor() as cursor:
            # 1. Obtener Sesión ID
            cursor.execute("SELECT sesion_id FROM salas_espera WHERE usuario_id = %s AND codigo_pin = %s", (user_id, codigo_pin))
            sala = cursor.fetchone()
            res["sesion_id"] = sala['sesion_id'] if sala else None

            # 2. Obtener Cuestionario
            cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s", (codigo_pin,))
            res["cuestionario"] = cursor.fetchone()

            if not res["cuestionario"]: return False, "Cuestionario no encontrado"

            # 3. Obtener Preguntas
            cursor.execute("SELECT * FROM preguntas WHERE cuestionario_id = %s ORDER BY orden", (res["cuestionario"]['id'],))
            res["preguntas"] = cursor.fetchall()

            if not res["preguntas"]: return False, "El cuestionario no tiene preguntas"

            # 4. Crear Historial (Inicio de la partida)
            cursor.execute("""
                INSERT INTO historial_individual
                (usuario_id, cuestionario_id, nombre_estudiante, num_preguntas_total, fecha_realizacion, puntuacion_final, sesion_id)
                VALUES (%s, %s, %s, %s, NOW(), 0, %s)
            """, (user_id, res["cuestionario"]['id'], nombre_estudiante, res["cuestionario"]['num_preguntas'], res["sesion_id"]))
            conexion.commit()
            
            # Retornamos el ID del historial recién creado por si se necesita en sesión
            res["historial_id"] = cursor.lastrowid
            
            return True, res
    finally:
        if conexion and conexion.open: conexion.close()

# ========================================
# MOTOR DE JUEGO (APIs Tiempo Real)
# ========================================

def api_obtener_estado_grupo(grupo_id):
    """Devuelve el estado actual del juego para el polling"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT game_state, active_pin, current_question_index, current_score
                FROM grupos WHERE id = %s
            """, (grupo_id,))
            return cursor.fetchone()
    finally:
        if conexion and conexion.open: conexion.close()

def api_obtener_pregunta_actual(grupo_id):
    """Devuelve la pregunta actual basada en el índice del grupo"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Info del juego
            cursor.execute("SELECT active_pin, current_question_index, current_score, game_state FROM grupos WHERE id = %s", (grupo_id,))
            juego = cursor.fetchone()

            if not juego or not juego['active_pin']: return None, "No hay juego activo"

            # Info cuestionario
            cursor.execute("SELECT id, num_preguntas, tiempo_pregunta FROM cuestionarios WHERE codigo_pin = %s", (juego['active_pin'],))
            cuestionario = cursor.fetchone()

            if not cuestionario: return None, "Cuestionario no encontrado"

            # Verificar fin del juego
            if juego['current_question_index'] >= cuestionario['num_preguntas']:
                return {
                    "finished": True,
                    "score": juego['current_score']
                }, None

            # Obtener Pregunta
            cursor.execute("""
                SELECT id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d
                FROM preguntas WHERE cuestionario_id = %s ORDER BY orden LIMIT 1 OFFSET %s
            """, (cuestionario['id'], juego['current_question_index']))
            pregunta = cursor.fetchone()

            if not pregunta: return None, "Pregunta no encontrada"

            return {
                "pregunta": pregunta,
                "index": juego['current_question_index'],
                "total": cuestionario['num_preguntas'],
                "score": juego['current_score'],
                "tiempo_pregunta": cuestionario['tiempo_pregunta'],
                "game_state": juego['game_state'],
                "finished": False
            }, None
    finally:
        if conexion and conexion.open: conexion.close()

def api_obtener_resultado_ultima(grupo_id):
    """Devuelve la respuesta correcta de la pregunta ANTERIOR"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT g.current_question_index, g.current_score, g.game_state,
                       g.ultima_respuesta_correcta, c.id as cuestionario_id
                FROM grupos g JOIN cuestionarios c ON g.active_pin = c.codigo_pin
                WHERE g.id = %s
            """, (grupo_id,))
            juego = cursor.fetchone()

            if not juego: return None

            # Solo si estamos en 'answered' y hay pregunta previa
            if juego['game_state'] == 'answered' and juego['current_question_index'] > 0:
                pregunta_index = juego['current_question_index'] - 1
                cursor.execute("""
                    SELECT respuesta_correcta FROM preguntas 
                    WHERE cuestionario_id = %s ORDER BY orden LIMIT 1 OFFSET %s
                """, (juego['cuestionario_id'], pregunta_index))
                pregunta = cursor.fetchone()

                if pregunta:
                    return {
                        "tiene_respuesta": True,
                        "respuesta_correcta": pregunta['respuesta_correcta'],
                        "nuevo_score": juego['current_score'],
                        "fue_correcta": juego['ultima_respuesta_correcta']
                    }
            
            return {"tiene_respuesta": False}
    finally:
        if conexion and conexion.open: conexion.close()

def api_procesar_respuesta_lider(grupo_id, user_id, respuesta_usuario):
    """Procesa respuesta, calcula puntos y avanza el juego"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Validar Líder y Juego
            cursor.execute("""
                SELECT g.lider_id, g.current_question_index, g.current_score, 
                       c.id as cuestionario_id, c.num_preguntas
                FROM grupos g JOIN cuestionarios c ON g.active_pin = c.codigo_pin
                WHERE g.id = %s
            """, (grupo_id,))
            juego = cursor.fetchone()

            if not juego: return False, "Juego no encontrado"
            if juego['lider_id'] != user_id: return False, "Solo el líder puede responder"
            if juego['current_question_index'] >= juego['num_preguntas']: return False, "Juego terminado"

            # 2. Obtener Respuesta Correcta
            cursor.execute("""
                SELECT respuesta_correcta FROM preguntas 
                WHERE cuestionario_id = %s ORDER BY orden LIMIT 1 OFFSET %s
            """, (juego['cuestionario_id'], juego['current_question_index']))
            pregunta_actual = cursor.fetchone()

            if not pregunta_actual: return False, "Pregunta no encontrada"

            # 3. Calcular Puntaje
            es_correcta = (respuesta_usuario == pregunta_actual['respuesta_correcta'])
            puntos_ganados = 100 if es_correcta else 0
            nuevo_score = juego['current_score'] + puntos_ganados

            # 4. Actualizar Estado del Juego
            nuevo_index = juego['current_question_index'] + 1
            es_ultima = (nuevo_index >= juego['num_preguntas'])
            nuevo_estado = 'finished' if es_ultima else 'answered'

            cursor.execute("""
                UPDATE grupos SET 
                    current_question_index = %s,
                    current_score = %s,
                    game_state = %s,
                    ultima_respuesta_correcta = %s
                WHERE id = %s
            """, (nuevo_index, nuevo_score, nuevo_estado, es_correcta, grupo_id))
            
            conexion.commit()

            return True, {
                "es_correcta": es_correcta,
                "puntos_ganados": puntos_ganados,
                "respuesta_correcta": pregunta_actual['respuesta_correcta'],
                "es_ultima_pregunta": es_ultima,
                "nuevo_score": nuevo_score
            }
    finally:
        if conexion and conexion.open: conexion.close()
        
# ========================================
# VISUALIZACIÓN Y EXPORTACIÓN DE RESULTADOS
# ========================================

def procesar_visualizacion_cuestionario(codigo_pin, rol_usuario):
    """
    Valida el PIN y el modo de juego para visualización previa.
    Retorna: (success, data/message)
    """
    if rol_usuario != "estudiante":
        return False, "No autorizado"

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Buscar cuestionario
            cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s", (codigo_pin,))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                return False, f"No se encontró ningún cuestionario con el PIN '{codigo_pin}'."

            if cuestionario['modo_juego'] == 'grupal':
                return False, f"El PIN '{codigo_pin}' es para un juego GRUPAL. Únete a un grupo para jugarlo."

            # Si todo está bien, retornamos el PIN para la redirección
            return True, codigo_pin
    finally:
        if conexion and conexion.open:
            conexion.close()

def obtener_datos_exportacion(cuestionario_id, profesor_id):
    """Obtiene datos del cuestionario y conteo de resultados para la vista de exportación"""
    conexion = obtener_conexion()
    res = {"cuestionario": None, "total_resultados": 0}
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT titulo, num_preguntas, modo_juego FROM cuestionarios
                WHERE id = %s AND profesor_id = %s
            """, (cuestionario_id, profesor_id))
            res["cuestionario"] = cursor.fetchone()

            if res["cuestionario"]:
                if res["cuestionario"]['modo_juego'] == 'grupal':
                    cursor.execute("SELECT COUNT(*) as total FROM historial_partidas WHERE cuestionario_id = %s", (cuestionario_id,))
                else:
                    cursor.execute("SELECT COUNT(*) as total FROM historial_individual WHERE cuestionario_id = %s AND puntuacion_final > 0", (cuestionario_id,))
                
                res["total_resultados"] = cursor.fetchone()['total']
    finally:
        if conexion and conexion.open: conexion.close()
    return res

def generar_excel_resultados(cuestionario_id, profesor_id):
    """
    Genera el archivo Excel con los resultados.
    Retorna: (filename, BytesIO_object) o (None, error_message)
    """
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Validar propiedad
            cursor.execute("SELECT titulo, modo_juego, num_preguntas FROM cuestionarios WHERE id = %s AND profesor_id = %s", (cuestionario_id, profesor_id))
            cuestionario = cursor.fetchone()
            
            if not cuestionario:
                return None, "Cuestionario no encontrado"

            # 2. Obtener datos según modo
            if cuestionario['modo_juego'] == 'grupal':
                cursor.execute("""
                    SELECT h.id as partida_id, h.nombre_grupo as identificador,
                           h.puntuacion_final, h.num_preguntas_total,
                           h.num_miembros as extras, h.fecha_partida as fecha,
                           GROUP_CONCAT(p.nombre_usuario SEPARATOR ', ') as participantes
                    FROM historial_partidas h
                    LEFT JOIN participantes_partida p ON h.id = p.partida_id
                    WHERE h.cuestionario_id = %s
                    GROUP BY h.id ORDER BY h.fecha_partida DESC
                """, (cuestionario_id,))
            else:
                cursor.execute("""
                    SELECT h.id as partida_id, h.nombre_estudiante as identificador,
                           h.puntuacion_final, h.num_preguntas_total,
                           h.tiempo_total as extras, h.fecha_realizacion as fecha,
                           NULL as participantes
                    FROM historial_individual h
                    WHERE h.cuestionario_id = %s AND h.puntuacion_final > 0
                    ORDER BY h.fecha_realizacion DESC
                """, (cuestionario_id,))

            resultados = cursor.fetchall()
            
            if not resultados:
                return None, "No hay resultados para exportar"

            # 3. Procesar con Pandas
            df = pd.DataFrame(resultados)
            
            if cuestionario['modo_juego'] == 'grupal':
                df.columns = ['ID Partida', 'Grupo', 'Puntuación', 'Total Preguntas', 'Miembros', 'Fecha', 'Participantes']
                df['Porcentaje (%)'] = (df['Puntuación'] / (df['Total Preguntas'] * 100) * 100).round(2)
                total_jugadores = int(df['Miembros'].sum())
            else:
                df.columns = ['ID Partida', 'Estudiante', 'Puntuación', 'Total Preguntas', 'Tiempo (seg)', 'Fecha', 'Participantes']
                df = df.drop('Participantes', axis=1)
                df['Porcentaje (%)'] = (df['Puntuación'] / (df['Total Preguntas'] * 1000) * 100).round(2)
                df['Tiempo Promedio/Preg'] = (df['Tiempo (seg)'] / df['Total Preguntas']).round(1)
                total_jugadores = len(df)

            # 4. Crear Excel en memoria
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Resultados Detallados', index=False)
                
                # Generar hoja de estadísticas
                stats_data = {
                    'Métrica': ['Total de Partidas', 'Total de Jugadores', 'Puntuación Promedio', 'Puntuación Máxima'],
                    'Valor': [len(df), total_jugadores, df['Puntuación'].mean().round(2), df['Puntuación'].max()]
                }
                pd.DataFrame(stats_data).to_excel(writer, sheet_name='Estadísticas', index=False)
                
                # Ajuste de columnas (simplificado)
                for sheet in writer.sheets.values():
                    for col in sheet.columns:
                        sheet.column_dimensions[col[0].column_letter].width = 20

            output.seek(0)
            
            modo_texto = "Grupal" if cuestionario['modo_juego'] == 'grupal' else "Individual"
            filename = f"Resultados_{modo_texto}_{cuestionario['titulo'].replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            
            return filename, output

    finally:
        if conexion and conexion.open: conexion.close()
        
# ========================================
# SINCRONIZACIÓN Y BARRERAS (APIs)
# ========================================

def api_verificar_sincronizacion_individual(sesion_id, pregunta_index):
    """Calcula cuántos estudiantes han terminado la pregunta actual"""
    conexion = obtener_conexion()
    data = {'todos_listos': False, 'listos': 0, 'total': 0}
    try:
        with conexion.cursor() as cursor:
            # Total en la sesión
            cursor.execute("SELECT COUNT(*) as total FROM salas_espera WHERE sesion_id = %s", (sesion_id,))
            total = cursor.fetchone()['total']
            
            # Total que ya terminaron la pregunta
            cursor.execute("""
                SELECT COUNT(*) as listos FROM salas_espera 
                WHERE sesion_id = %s AND pregunta_actual >= %s AND listo_para_siguiente = 1
            """, (sesion_id, pregunta_index))
            listos = cursor.fetchone()['listos']

            data['total'] = total
            data['listos'] = listos
            data['todos_listos'] = (listos >= total and total > 0)
    finally:
        if conexion and conexion.open: conexion.close()
    return data

def api_verificar_sincronizacion_grupal(grupo_id, pregunta_index):
    """Calcula cuántos miembros del grupo han respondido (para consenso o espera)"""
    conexion = obtener_conexion()
    data = {'todos_listos': False, 'respondidos': 0, 'total': 0}
    try:
        with conexion.cursor() as cursor:
            # Total miembros
            cursor.execute("SELECT COUNT(*) as total FROM usuarios WHERE grupo_id = %s", (grupo_id,))
            total = cursor.fetchone()['total']

            # Total respuestas en progreso_grupal
            cursor.execute("""
                SELECT COUNT(DISTINCT usuario_id) as respondidos FROM progreso_grupal
                WHERE grupo_id = %s AND pregunta_index = %s AND respondio = 1
            """, (grupo_id, pregunta_index))
            respondidos = cursor.fetchone()['respondidos']

            data['total'] = total
            data['respondidos'] = respondidos
            data['todos_listos'] = (respondidos >= total and total > 0)
    finally:
        if conexion and conexion.open: conexion.close()
    return data