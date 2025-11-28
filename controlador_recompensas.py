from bd import obtener_conexion
from datetime import datetime, date

# ========================================
# LÓGICA DEL SISTEMA (XP, NIVELES, INSIGNIAS)
# ========================================

def inicializar_stats_estudiante(user_id):
    """Crea el registro de estadísticas para un nuevo estudiante"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO estudiantes_stats (user_id, nivel, monedas, fecha_creacion)
                VALUES (%s, 1, 0, NOW())
                ON DUPLICATE KEY UPDATE user_id=user_id
            """, (user_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open: conexion.close()

def calcular_xp_necesaria(nivel):
    """Calcula XP necesaria para el siguiente nivel"""
    return 100 * nivel + (nivel - 1) * 50

def otorgar_xp(user_id, xp_ganada):
    """Otorga XP y verifica subidas de nivel"""
    conexion = obtener_conexion()
    res = {'niveles_subidos': [], 'xp_ganada': xp_ganada, 'nivel_actual': 1}
    
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()

            if not stats:
                inicializar_stats_estudiante(user_id)
                cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
                stats = cursor.fetchone()

            nuevo_xp_actual = stats['experiencia_actual'] + xp_ganada
            nuevo_xp_total = stats['experiencia_total'] + xp_ganada
            nivel_actual = stats['nivel']
            niveles_subidos = []

            while True:
                xp_necesaria = calcular_xp_necesaria(nivel_actual)
                if nuevo_xp_actual >= xp_necesaria:
                    nivel_actual += 1
                    nuevo_xp_actual -= xp_necesaria
                    niveles_subidos.append(nivel_actual)
                else:
                    break

            cursor.execute("""
                UPDATE estudiantes_stats
                SET experiencia_actual = %s, experiencia_total = %s, nivel = %s
                WHERE user_id = %s
            """, (nuevo_xp_actual, nuevo_xp_total, nivel_actual, user_id))
            conexion.commit()

            res['niveles_subidos'] = niveles_subidos
            res['nivel_actual'] = nivel_actual
            res['xp_actual'] = nuevo_xp_actual
            res['xp_necesaria'] = calcular_xp_necesaria(nivel_actual)
            
    finally:
        if conexion and conexion.open: conexion.close()
    return res

def otorgar_monedas(user_id, monedas):
    """Suma monedas al usuario"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("UPDATE estudiantes_stats SET monedas = monedas + %s WHERE user_id = %s", (monedas, user_id))
            conexion.commit()
    finally:
        if conexion and conexion.open: conexion.close()

def verificar_y_desbloquear_insignias(user_id):
    """Verifica requisitos y desbloquea insignias nuevas"""
    conexion = obtener_conexion()
    insignias_desbloqueadas = []
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()
            if not stats: return []

            # Insignias disponibles (que no tiene aún)
            cursor.execute("""
                SELECT i.* FROM insignias i
                WHERE i.id NOT IN (SELECT insignia_id FROM estudiantes_insignias WHERE usuario_id = %s)
            """, (user_id,))
            insignias_disponibles = cursor.fetchall()

            for insignia in insignias_disponibles:
                desbloquear = False
                tipo = insignia['requisito_tipo']
                valor = insignia['requisito_valor']

                if tipo == 'partidas' and stats['total_partidas'] >= valor: desbloquear = True
                elif tipo == 'nivel' and stats['nivel'] >= valor: desbloquear = True
                elif tipo == 'racha' and stats['mejor_racha'] >= valor: desbloquear = True
                elif tipo == 'puntaje' and stats['mejor_puntaje'] >= valor: desbloquear = True

                if desbloquear:
                    # Insertar registro
                    cursor.execute("INSERT INTO estudiantes_insignias (usuario_id, insignia_id) VALUES (%s, %s)", (user_id, insignia['id']))
                    
                    # Dar recompensas de la insignia
                    if insignia['recompensa_xp'] > 0:
                        cursor.execute("UPDATE estudiantes_stats SET experiencia_total = experiencia_total + %s, experiencia_actual = experiencia_actual + %s WHERE user_id = %s", (insignia['recompensa_xp'], insignia['recompensa_xp'], user_id))
                    
                    if insignia['recompensa_monedas'] > 0:
                        cursor.execute("UPDATE estudiantes_stats SET monedas = monedas + %s WHERE user_id = %s", (insignia['recompensa_monedas'], user_id))
                    
                    insignias_desbloqueadas.append(insignia)
            
            conexion.commit()
    finally:
        if conexion and conexion.open: conexion.close()
    return insignias_desbloqueadas

def actualizar_stats_despues_partida(user_id, puntuacion, correctas, incorrectas):
    """Actualiza racha, partidas y llama a la lógica de XP/Insignias"""
    conexion = obtener_conexion()
    resultado = {}
    try:
        with conexion.cursor() as cursor:
            # 1. Stats actuales
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()
            
            if not stats:
                inicializar_stats_estudiante(user_id)
                cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
                stats = cursor.fetchone()

            # 2. Calcular Racha
            hoy = date.today()
            ultima = stats['ultima_partida']
            if ultima:
                diferencia = (hoy - ultima).days
                if diferencia == 1: nueva_racha = stats['racha_actual'] + 1
                elif diferencia == 0: nueva_racha = stats['racha_actual']
                else: nueva_racha = 1
            else:
                nueva_racha = 1
            
            mejor_racha = max(stats['mejor_racha'], nueva_racha)
            mejor_puntaje = max(stats['mejor_puntaje'], puntuacion)

            # 3. Update Base
            cursor.execute("""
                UPDATE estudiantes_stats SET
                    total_partidas = total_partidas + 1,
                    total_preguntas_correctas = total_preguntas_correctas + %s,
                    total_preguntas_incorrectas = total_preguntas_incorrectas + %s,
                    mejor_puntaje = %s,
                    racha_actual = %s,
                    mejor_racha = %s,
                    ultima_partida = %s
                WHERE user_id = %s
            """, (correctas, incorrectas, mejor_puntaje, nueva_racha, mejor_racha, hoy, user_id))
            conexion.commit()

            # 4. Calcular Recompensas
            xp_base = 50
            xp_por_correcta = 10
            xp_bonus_perfecto = 100 if correctas > 0 and incorrectas == 0 else 0
            total_xp = xp_base + (correctas * xp_por_correcta) + xp_bonus_perfecto

            res_xp = otorgar_xp(user_id, total_xp)
            monedas = 5 + (correctas * 2)
            otorgar_monedas(user_id, monedas)
            insignias = verificar_y_desbloquear_insignias(user_id)

            resultado = {
                'xp_info': res_xp,
                'monedas_ganadas': monedas,
                'insignias_nuevas': insignias,
                'racha_actual': nueva_racha,
                'es_mejor_puntaje': puntuacion == mejor_puntaje and puntuacion > stats['mejor_puntaje']
            }
    finally:
        if conexion and conexion.open: conexion.close()
    return resultado

# ========================================
# CONTROLADOR: DATOS PARA VISTAS (PERFIL, TIENDA, INVENTARIO)
# ========================================

def obtener_datos_perfil_completo(user_id):
    """Obtiene stats, insignias y progreso para la vista de perfil"""
    conexion = obtener_conexion()
    data = {}
    try:
        with conexion.cursor() as cursor:
            # Stats
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()
            if not stats:
                inicializar_stats_estudiante(user_id)
                cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
                stats = cursor.fetchone()
            data['stats'] = stats

            # Insignias Desbloqueadas
            cursor.execute("""
                SELECT i.*, ei.fecha_desbloqueo
                FROM estudiantes_insignias ei
                JOIN insignias i ON ei.insignia_id = i.id
                WHERE ei.usuario_id = %s
                ORDER BY ei.fecha_desbloqueo DESC
            """, (user_id,))
            data['insignias_desbloqueadas'] = cursor.fetchall()

            # Todas las insignias (para mostrar bloqueadas)
            cursor.execute("SELECT * FROM insignias ORDER BY requisito_valor ASC")
            data['todas_insignias'] = cursor.fetchall()

            # Progreso Nivel
            xp_necesaria = calcular_xp_necesaria(stats['nivel'])
            data['xp_necesaria'] = xp_necesaria
            data['progreso_nivel'] = (stats['experiencia_actual'] / xp_necesaria) * 100
    finally:
        if conexion and conexion.open: conexion.close()
    return data

def obtener_datos_tienda_completo(user_id):
    """Obtiene items disponibles y estado de compra para el usuario"""
    conexion = obtener_conexion()
    data = {}
    try:
        with conexion.cursor() as cursor:
            # Stats
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone() or {'nivel': 1, 'monedas': 0}
            data['stats'] = stats

            # Items Tienda
            cursor.execute("SELECT * FROM tienda_items WHERE disponible = 1 ORDER BY requisito_nivel ASC, precio ASC")
            items_tienda = cursor.fetchall()

            # Items Comprados
            cursor.execute("SELECT item_id FROM estudiantes_items WHERE usuario_id = %s", (user_id,))
            comprados_ids = [i['item_id'] for i in cursor.fetchall()]

            # Procesar lógica de visualización
            for item in items_tienda:
                item['comprado'] = item['id'] in comprados_ids
                item['puede_comprar'] = (
                    stats['monedas'] >= item['precio'] and
                    stats['nivel'] >= item['requisito_nivel'] and
                    not item['comprado']
                )
            data['items'] = items_tienda
    finally:
        if conexion and conexion.open: conexion.close()
    return data

def procesar_compra_item(user_id, item_id):
    """Valida y ejecuta la compra de un item"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()

            cursor.execute("SELECT * FROM tienda_items WHERE id = %s AND disponible = 1", (item_id,))
            item = cursor.fetchone()

            if not item: return False, "Item no disponible"

            # Validar duplicado
            cursor.execute("SELECT id FROM estudiantes_items WHERE usuario_id = %s AND item_id = %s", (user_id, item_id))
            if cursor.fetchone(): return False, "Ya tienes este item"

            # Validar requisitos
            if stats['monedas'] < item['precio']:
                return False, f"Necesitas {item['precio']} monedas"
            if stats['nivel'] < item['requisito_nivel']:
                return False, f"Necesitas nivel {item['requisito_nivel']}"

            # Ejecutar Transacción
            cursor.execute("INSERT INTO estudiantes_items (usuario_id, item_id, fecha_compra) VALUES (%s, %s, NOW())", (user_id, item_id))
            cursor.execute("UPDATE estudiantes_stats SET monedas = monedas - %s WHERE user_id = %s", (item['precio'], user_id))
            conexion.commit()

            return True, {
                "message": f"¡Compraste {item['nombre']}!",
                "monedas_restantes": stats['monedas'] - item['precio']
            }
    finally:
        if conexion and conexion.open: conexion.close()

def procesar_equipamiento_item(user_id, item_id):
    """Equipa un item y desequipa otros del mismo tipo"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Validar propiedad
            cursor.execute("""
                SELECT ei.*, ti.tipo FROM estudiantes_items ei
                JOIN tienda_items ti ON ei.item_id = ti.id
                WHERE ei.usuario_id = %s AND ei.item_id = %s
            """, (user_id, item_id))
            item_comprado = cursor.fetchone()

            if not item_comprado: return False, "No tienes este item"

            tipo_item = item_comprado['tipo']

            # Desequipar del mismo tipo
            cursor.execute("""
                UPDATE estudiantes_items ei
                JOIN tienda_items ti ON ei.item_id = ti.id
                SET ei.equipado = 0
                WHERE ei.usuario_id = %s AND ti.tipo = %s
            """, (user_id, tipo_item))

            # Equipar nuevo
            cursor.execute("UPDATE estudiantes_items SET equipado = 1 WHERE usuario_id = %s AND item_id = %s", (user_id, item_id))
            conexion.commit()
            return True, "Item equipado correctamente"
    finally:
        if conexion and conexion.open: conexion.close()

def obtener_datos_inventario(user_id):
    """Obtiene items comprados y stats para el inventario"""
    conexion = obtener_conexion()
    data = {}
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT ti.*, ei.equipado, ei.fecha_compra
                FROM estudiantes_items ei
                JOIN tienda_items ti ON ei.item_id = ti.id
                WHERE ei.usuario_id = %s
                ORDER BY ei.equipado DESC, ei.fecha_compra DESC
            """, (user_id,))
            data['items'] = cursor.fetchall()

            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            data['stats'] = cursor.fetchone()
    finally:
        if conexion and conexion.open: conexion.close()
    return data