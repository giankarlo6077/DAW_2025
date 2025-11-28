from bd import obtener_conexion
import json

# ========================================
# LÓGICA DE AUTENTICACIÓN FACIAL
# ========================================

def procesar_autenticacion_facial(embedding_capturado):
    """
    Compara el embedding capturado con todos los usuarios registrados.
    Retorna: (exito: bool, datos: dict/str)
    - Si exito es True, datos es el dict del usuario.
    - Si exito es False, datos es el mensaje de error.
    """
    # Validación básica
    if not embedding_capturado or len(embedding_capturado) != 128:
        return False, "Datos de rostro inválidos"

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Obtener usuarios con rostro registrado
            cursor.execute("""
                SELECT id as usuario_id, codificacion_facial as embedding, nombre, correo, rol, verificado
                FROM usuarios
                WHERE codificacion_facial IS NOT NULL
            """)
            usuarios_registrados = cursor.fetchall()

            if not usuarios_registrados:
                return False, "No hay usuarios con reconocimiento facial registrado"

            # 2. Algoritmo de comparación (Distancia Euclidiana)
            mejor_coincidencia = None
            mejor_similitud = float('inf')
            umbral_similitud = 0.6  # Ajustable según precisión deseada

            for usuario in usuarios_registrados:
                try:
                    # Parsear el JSON almacenado en BD
                    embedding_db = json.loads(usuario['embedding'])

                    # Calcular distancia
                    distancia = sum((a - b) ** 2 for a, b in zip(embedding_capturado, embedding_db)) ** 0.5

                    if distancia < mejor_similitud:
                        mejor_similitud = distancia
                        mejor_coincidencia = usuario
                except Exception as e:
                    print(f"Error procesando embedding de usuario {usuario['usuario_id']}: {e}")
                    continue

            # 3. Verificar resultado
            if mejor_coincidencia and mejor_similitud < umbral_similitud:
                if not mejor_coincidencia['verificado']:
                    return False, "Tu cuenta aún no está verificada. Revisa tu correo."
                
                # Limpiar el embedding del resultado para no arrastrar datos pesados
                mejor_coincidencia.pop('embedding', None)
                
                return True, mejor_coincidencia
            
            return False, "No se pudo verificar tu identidad. Intenta con login normal."

    finally:
        if conexion and conexion.open:
            conexion.close()
            
# ========================================
# LÓGICA DE REGISTRO DE ROSTRO
# ========================================

def registrar_rostro_usuario(user_id, embedding_list):
    """
    Guarda el embedding facial en la columna codificacion_facial del usuario.
    Retorna: (success: bool, message: str)
    """
    # 1. Validación de datos
    if not embedding_list or len(embedding_list) != 128:
        return False, "El embedding debe tener 128 dimensiones"

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Convertir lista a JSON string
            embedding_json = json.dumps(embedding_list)

            # 2. Actualizar usuario
            cursor.execute("""
                UPDATE usuarios
                SET codificacion_facial = %s
                WHERE id = %s
            """, (embedding_json, user_id))
            
            conexion.commit()
            
            return True, "Reconocimiento facial registrado exitosamente"
    except Exception as e:
        return False, str(e)
    finally:
        if conexion and conexion.open:
            conexion.close()