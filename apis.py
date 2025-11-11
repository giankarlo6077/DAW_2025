
from flask import jsonify, request, session
from bd import obtener_conexion
import json
from datetime import datetime

# ========================================
# TABLA: cuestionarios
# ========================================

@app.route("/api/cuestionarios", methods=["GET"])
def api_obtener_cuestionarios():
    """GET: Lista todos los cuestionarios"""
    try:
        conexion = obtener_conexion()
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
            
            # Convertir datetime a string para JSON
            for c in cuestionarios:
                if c.get('fecha_creacion'):
                    c['fecha_creacion'] = c['fecha_creacion'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                "success": True,
                "data": cuestionarios,
                "total": len(cuestionarios)
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener cuestionarios: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/cuestionarios/<int:cuestionario_id>", methods=["GET"])
def api_obtener_cuestionario_por_id(cuestionario_id):
    """GET: Lista un solo cuestionario por ID"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT c.*, u.nombre as nombre_profesor
                FROM cuestionarios c
                LEFT JOIN usuarios u ON c.profesor_id = u.id
                WHERE c.id = %s AND c.eliminado = 0
            """, (cuestionario_id,))
            cuestionario = cursor.fetchone()
            
            if not cuestionario:
                return jsonify({
                    "success": False,
                    "message": "Cuestionario no encontrado"
                }), 404
            
            # Convertir datetime a string
            if cuestionario.get('fecha_creacion'):
                cuestionario['fecha_creacion'] = cuestionario['fecha_creacion'].strftime('%Y-%m-%d %H:%M:%S')
            
            # Obtener preguntas del cuestionario
            cursor.execute("""
                SELECT * FROM preguntas 
                WHERE cuestionario_id = %s AND eliminado = 0
                ORDER BY orden
            """, (cuestionario_id,))
            preguntas = cursor.fetchall()
            cuestionario['preguntas'] = preguntas
            
            return jsonify({
                "success": True,
                "data": cuestionario
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener cuestionario: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/cuestionarios", methods=["POST"])
def api_registrar_cuestionario():
    """POST: Registra un nuevo cuestionario"""
    try:
        data = request.get_json()
        
        # Validaciones básicas
        if not data.get('titulo'):
            return jsonify({
                "success": False,
                "message": "El título es requerido"
            }), 400
        
        # Generar código PIN único
        import random
        codigo_pin = ''.join(random.choices('0123456789', k=6))
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO cuestionarios 
                (titulo, descripcion, modo_juego, tiempo_pregunta, num_preguntas, 
                 codigo_pin, profesor_id, estado, fecha_creacion)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                data.get('titulo'),
                data.get('descripcion', ''),
                data.get('modo_juego', 'individual'),
                data.get('tiempo_pregunta', 30),
                data.get('num_preguntas', 0),
                codigo_pin,
                data.get('profesor_id'),
                data.get('estado', 'activo')
            ))
            conexion.commit()
            
            nuevo_id = cursor.lastrowid
            
            return jsonify({
                "success": True,
                "message": "Cuestionario creado exitosamente",
                "data": {
                    "id": nuevo_id,
                    "codigo_pin": codigo_pin
                }
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar cuestionario: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/cuestionarios/<int:cuestionario_id>", methods=["PUT"])
def api_actualizar_cuestionario(cuestionario_id):
    """POST/PUT: Actualiza un cuestionario existente"""
    try:
        data = request.get_json()
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            # Verificar que existe
            cursor.execute("SELECT id FROM cuestionarios WHERE id = %s", (cuestionario_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Cuestionario no encontrado"
                }), 404
            
            # Actualizar
            cursor.execute("""
                UPDATE cuestionarios 
                SET titulo = %s, descripcion = %s, modo_juego = %s, 
                    tiempo_pregunta = %s, estado = %s
                WHERE id = %s
            """, (
                data.get('titulo'),
                data.get('descripcion'),
                data.get('modo_juego'),
                data.get('tiempo_pregunta'),
                data.get('estado'),
                cuestionario_id
            ))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Cuestionario actualizado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar cuestionario: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/cuestionarios/<int:cuestionario_id>", methods=["DELETE"])
def api_eliminar_cuestionario(cuestionario_id):
    """POST/DELETE: Elimina (lógicamente) un cuestionario"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            # Verificar que existe
            cursor.execute("SELECT id FROM cuestionarios WHERE id = %s", (cuestionario_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Cuestionario no encontrado"
                }), 404
            
            # Eliminación lógica
            cursor.execute("""
                UPDATE cuestionarios 
                SET eliminado = 1
                WHERE id = %s
            """, (cuestionario_id,))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Cuestionario eliminado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar cuestionario: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# ========================================
# TABLA: preguntas
# ========================================

@app.route("/api/preguntas", methods=["GET"])
def api_obtener_preguntas():
    """GET: Lista todas las preguntas"""
    try:
        cuestionario_id = request.args.get('cuestionario_id')
        
        conexion = obtener_conexion()
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
            
            return jsonify({
                "success": True,
                "data": preguntas,
                "total": len(preguntas)
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener preguntas: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/preguntas/<int:pregunta_id>", methods=["GET"])
def api_obtener_pregunta_por_id(pregunta_id):
    """GET: Obtiene una pregunta específica"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT p.*, c.titulo as titulo_cuestionario
                FROM preguntas p
                LEFT JOIN cuestionarios c ON p.cuestionario_id = c.id
                WHERE p.id = %s AND p.eliminado = 0
            """, (pregunta_id,))
            pregunta = cursor.fetchone()
            
            if not pregunta:
                return jsonify({
                    "success": False,
                    "message": "Pregunta no encontrada"
                }), 404
            
            return jsonify({
                "success": True,
                "data": pregunta
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener pregunta: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/preguntas", methods=["POST"])
def api_registrar_pregunta():
    """POST: Registra una nueva pregunta"""
    try:
        data = request.get_json()
        
        # Validaciones
        if not data.get('pregunta'):
            return jsonify({
                "success": False,
                "message": "El texto de la pregunta es requerido"
            }), 400
        
        if not data.get('cuestionario_id'):
            return jsonify({
                "success": False,
                "message": "El ID del cuestionario es requerido"
            }), 400
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO preguntas 
                (cuestionario_id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, 
                 respuesta_correcta, orden)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                data.get('cuestionario_id'),
                data.get('pregunta'),
                data.get('opcion_a', ''),
                data.get('opcion_b', ''),
                data.get('opcion_c', ''),
                data.get('opcion_d', ''),
                data.get('respuesta_correcta'),
                data.get('orden', 0)
            ))
            conexion.commit()
            
            nuevo_id = cursor.lastrowid
            
            return jsonify({
                "success": True,
                "message": "Pregunta creada exitosamente",
                "data": {"id": nuevo_id}
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar pregunta: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/preguntas/<int:pregunta_id>", methods=["PUT"])
def api_actualizar_pregunta(pregunta_id):
    """POST/PUT: Actualiza una pregunta existente"""
    try:
        data = request.get_json()
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM preguntas WHERE id = %s", (pregunta_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Pregunta no encontrada"
                }), 404
            
            cursor.execute("""
                UPDATE preguntas 
                SET pregunta = %s, opcion_a = %s, opcion_b = %s, opcion_c = %s, 
                    opcion_d = %s, respuesta_correcta = %s, orden = %s
                WHERE id = %s
            """, (
                data.get('pregunta'),
                data.get('opcion_a'),
                data.get('opcion_b'),
                data.get('opcion_c'),
                data.get('opcion_d'),
                data.get('respuesta_correcta'),
                data.get('orden'),
                pregunta_id
            ))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Pregunta actualizada exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar pregunta: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/preguntas/<int:pregunta_id>", methods=["DELETE"])
def api_eliminar_pregunta(pregunta_id):
    """POST/DELETE: Elimina una pregunta"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM preguntas WHERE id = %s", (pregunta_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Pregunta no encontrada"
                }), 404
            
            cursor.execute("""
                UPDATE preguntas 
                SET eliminado = 1
                WHERE id = %s
            """, (pregunta_id,))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Pregunta eliminada exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar pregunta: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# ========================================
# TABLA: usuarios
# ========================================

@app.route("/api/usuarios", methods=["GET"])
def api_obtener_usuarios():
    """GET: Lista todos los usuarios"""
    try:
        rol = request.args.get('rol')  # Filtrar por rol si se especifica
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            if rol:
                cursor.execute("""
                    SELECT id, nombre, correo, rol, verificado, fecha_codigo, 
                           grupo_id, codificacion_facial
                    FROM usuarios
                    WHERE rol = %s
                    ORDER BY nombre
                """, (rol,))
            else:
                cursor.execute("""
                    SELECT id, nombre, correo, rol, verificado, fecha_codigo, 
                           grupo_id, codificacion_facial
                    FROM usuarios
                    ORDER BY rol, nombre
                """)
            
            usuarios = cursor.fetchall()
            
            # No incluir passwords en la respuesta
            for u in usuarios:
                if u.get('fecha_codigo'):
                    u['fecha_codigo'] = u['fecha_codigo'].strftime('%Y-%m-%d %H:%M:%S')
                # Indicar si tiene reconocimiento facial sin exponer el embedding
                u['tiene_reconocimiento_facial'] = bool(u.get('codificacion_facial'))
                u.pop('codificacion_facial', None)
            
            return jsonify({
                "success": True,
                "data": usuarios,
                "total": len(usuarios)
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener usuarios: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/usuarios/<int:usuario_id>", methods=["GET"])
def api_obtener_usuario_por_id(usuario_id):
    """GET: Obtiene un usuario específico"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.nombre, u.correo, u.rol, u.verificado, 
                       u.fecha_codigo, u.grupo_id, g.nombre_grupo
                FROM usuarios u
                LEFT JOIN grupos g ON u.grupo_id = g.id
                WHERE u.id = %s
            """, (usuario_id,))
            usuario = cursor.fetchone()
            
            if not usuario:
                return jsonify({
                    "success": False,
                    "message": "Usuario no encontrado"
                }), 404
            
            if usuario.get('fecha_codigo'):
                usuario['fecha_codigo'] = usuario['fecha_codigo'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                "success": True,
                "data": usuario
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener usuario: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/usuarios", methods=["POST"])
def api_registrar_usuario():
    """POST: Registra un nuevo usuario"""
    try:
        data = request.get_json()
        
        # Validaciones
        if not data.get('nombre') or not data.get('correo') or not data.get('password'):
            return jsonify({
                "success": False,
                "message": "Nombre, correo y contraseña son requeridos"
            }), 400
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            # Verificar si el correo ya existe
            cursor.execute("SELECT id FROM usuarios WHERE correo = %s", (data.get('correo'),))
            if cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "El correo ya está registrado"
                }), 400
            
            # Insertar usuario
            cursor.execute("""
                INSERT INTO usuarios 
                (nombre, correo, password, rol, verificado, codigo_verificacion, fecha_codigo)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """, (
                data.get('nombre'),
                data.get('correo'),
                data.get('password'),  # En producción, hashear la contraseña
                data.get('rol', 'estudiante'),
                data.get('verificado', 0),
                data.get('codigo_verificacion', '')
            ))
            conexion.commit()
            
            nuevo_id = cursor.lastrowid
            
            return jsonify({
                "success": True,
                "message": "Usuario registrado exitosamente",
                "data": {"id": nuevo_id}
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar usuario: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/usuarios/<int:usuario_id>", methods=["PUT"])
def api_actualizar_usuario(usuario_id):
    """POST/PUT: Actualiza un usuario existente"""
    try:
        data = request.get_json()
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM usuarios WHERE id = %s", (usuario_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Usuario no encontrado"
                }), 404
            
            cursor.execute("""
                UPDATE usuarios 
                SET nombre = %s, correo = %s, rol = %s, verificado = %s, grupo_id = %s
                WHERE id = %s
            """, (
                data.get('nombre'),
                data.get('correo'),
                data.get('rol'),
                data.get('verificado'),
                data.get('grupo_id'),
                usuario_id
            ))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Usuario actualizado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar usuario: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/usuarios/<int:usuario_id>", methods=["DELETE"])
def api_eliminar_usuario(usuario_id):
    """POST/DELETE: Elimina un usuario"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM usuarios WHERE id = %s", (usuario_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Usuario no encontrado"
                }), 404
            
            # Eliminación física (en producción podrías usar eliminación lógica)
            cursor.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Usuario eliminado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar usuario: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# ========================================
# TABLA: grupos
# ========================================

@app.route("/api/grupos", methods=["GET"])
def api_obtener_grupos():
    """GET: Lista todos los grupos"""
    try:
        conexion = obtener_conexion()
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
            
            return jsonify({
                "success": True,
                "data": grupos,
                "total": len(grupos)
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener grupos: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/grupos/<int:grupo_id>", methods=["GET"])
def api_obtener_grupo_por_id(grupo_id):
    """GET: Obtiene un grupo específico con sus miembros"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT g.*, u.nombre as nombre_lider
                FROM grupos g
                LEFT JOIN usuarios u ON g.leader_id = u.id
                WHERE g.id = %s
            """, (grupo_id,))
            grupo = cursor.fetchone()
            
            if not grupo:
                return jsonify({
                    "success": False,
                    "message": "Grupo no encontrado"
                }), 404
            
            if grupo.get('fecha_creacion'):
                grupo['fecha_creacion'] = grupo['fecha_creacion'].strftime('%Y-%m-%d %H:%M:%S')
            
            # Obtener miembros del grupo
            cursor.execute("""
                SELECT id, nombre, correo
                FROM usuarios
                WHERE grupo_id = %s
                ORDER BY nombre
            """, (grupo_id,))
            miembros = cursor.fetchall()
            grupo['miembros'] = miembros
            grupo['num_miembros'] = len(miembros)
            
            return jsonify({
                "success": True,
                "data": grupo
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener grupo: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/grupos", methods=["POST"])
def api_registrar_grupo():
    """POST: Registra un nuevo grupo"""
    try:
        data = request.get_json()
        
        if not data.get('nombre_grupo'):
            return jsonify({
                "success": False,
                "message": "El nombre del grupo es requerido"
            }), 400
        
        # Generar código único de 8 caracteres
        import random
        import string
        codigo_grupo = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO grupos 
                (nombre_grupo, codigo_grupo, leader_id, fecha_creacion, active_min, game_state)
                VALUES (%s, %s, %s, NOW(), %s, %s)
            """, (
                data.get('nombre_grupo'),
                codigo_grupo,
                data.get('leader_id'),
                data.get('active_min', ''),
                data.get('game_state', '')
            ))
            conexion.commit()
            
            nuevo_id = cursor.lastrowid
            
            return jsonify({
                "success": True,
                "message": "Grupo creado exitosamente",
                "data": {
                    "id": nuevo_id,
                    "codigo_grupo": codigo_grupo
                }
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar grupo: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/grupos/<int:grupo_id>", methods=["PUT"])
def api_actualizar_grupo(grupo_id):
    """POST/PUT: Actualiza un grupo existente"""
    try:
        data = request.get_json()
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM grupos WHERE id = %s", (grupo_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Grupo no encontrado"
                }), 404
            
            cursor.execute("""
                UPDATE grupos 
                SET nombre_grupo = %s, leader_id = %s, active_min = %s, 
                    game_state = %s, active_pin = %s
                WHERE id = %s
            """, (
                data.get('nombre_grupo'),
                data.get('leader_id'),
                data.get('active_min'),
                data.get('game_state'),
                data.get('active_pin'),
                grupo_id
            ))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Grupo actualizado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar grupo: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/grupos/<int:grupo_id>", methods=["DELETE"])
def api_eliminar_grupo(grupo_id):
    """POST/DELETE: Elimina un grupo"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM grupos WHERE id = %s", (grupo_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Grupo no encontrado"
                }), 404
            
            # Desasociar usuarios del grupo
            cursor.execute("UPDATE usuarios SET grupo_id = NULL WHERE grupo_id = %s", (grupo_id,))
            
            # Eliminar grupo
            cursor.execute("DELETE FROM grupos WHERE id = %s", (grupo_id,))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Grupo eliminado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar grupo: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# ========================================
# TABLA: historial_individual
# ========================================

@app.route("/api/historial_individual", methods=["GET"])
def api_obtener_historial_individual():
    """GET: Lista todo el historial individual"""
    try:
        usuario_id = request.args.get('usuario_id')
        cuestionario_id = request.args.get('cuestionario_id')
        
        conexion = obtener_conexion()
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
                    h['fecha_realizacion'] = h['fecha_realizacion'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                "success": True,
                "data": historial,
                "total": len(historial)
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener historial: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/historial_individual/<int:historial_id>", methods=["GET"])
def api_obtener_historial_individual_por_id(historial_id):
    """GET: Obtiene un registro específico del historial"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT h.*, u.nombre as nombre_estudiante, c.titulo as titulo_cuestionario
                FROM historial_individual h
                LEFT JOIN usuarios u ON h.usuario_id = u.id
                LEFT JOIN cuestionarios c ON h.cuestionario_id = c.id
                WHERE h.id = %s
            """, (historial_id,))
            historial = cursor.fetchone()
            
            if not historial:
                return jsonify({
                    "success": False,
                    "message": "Historial no encontrado"
                }), 404
            
            if historial.get('fecha_realizacion'):
                historial['fecha_realizacion'] = historial['fecha_realizacion'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                "success": True,
                "data": historial
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener historial: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/historial_individual", methods=["POST"])
def api_registrar_historial_individual():
    """POST: Registra un nuevo historial individual"""
    try:
        data = request.get_json()
        
        if not data.get('cuestionario_id') or not data.get('usuario_id'):
            return jsonify({
                "success": False,
                "message": "cuestionario_id y usuario_id son requeridos"
            }), 400
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO historial_individual 
                (cuestionario_id, usuario_id, nombre_estudiante, puntuacion_final, 
                 num_preguntas_total, tiempo_total, fecha_realizacion, sesion_id)
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s)
            """, (
                data.get('cuestionario_id'),
                data.get('usuario_id'),
                data.get('nombre_estudiante'),
                data.get('puntuacion_final', 0),
                data.get('num_preguntas_total', 0),
                data.get('tiempo_total', 0),
                data.get('sesion_id')
            ))
            conexion.commit()
            
            nuevo_id = cursor.lastrowid
            
            return jsonify({
                "success": True,
                "message": "Historial registrado exitosamente",
                "data": {"id": nuevo_id}
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar historial: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/historial_individual/<int:historial_id>", methods=["PUT"])
def api_actualizar_historial_individual(historial_id):
    """POST/PUT: Actualiza un registro del historial"""
    try:
        data = request.get_json()
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM historial_individual WHERE id = %s", (historial_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Historial no encontrado"
                }), 404
            
            cursor.execute("""
                UPDATE historial_individual 
                SET puntuacion_final = %s, num_preguntas_total = %s, tiempo_total = %s
                WHERE id = %s
            """, (
                data.get('puntuacion_final'),
                data.get('num_preguntas_total'),
                data.get('tiempo_total'),
                historial_id
            ))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Historial actualizado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar historial: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/historial_individual/<int:historial_id>", methods=["DELETE"])
def api_eliminar_historial_individual(historial_id):
    """POST/DELETE: Elimina un registro del historial"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM historial_individual WHERE id = %s", (historial_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Historial no encontrado"
                }), 404
            
            cursor.execute("DELETE FROM historial_individual WHERE id = %s", (historial_id,))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Historial eliminado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar historial: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# ========================================
# TABLA: historial_partidas
# ========================================

@app.route("/api/historial_partidas", methods=["GET"])
def api_obtener_historial_partidas():
    """GET: Lista todo el historial de partidas grupales"""
    try:
        grupo_id = request.args.get('grupo_id')
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            if grupo_id:
                cursor.execute("""
                    SELECT h.*, g.nombre_grupo, c.titulo as titulo_cuestionario
                    FROM historial_partidas h
                    LEFT JOIN grupos g ON h.grupo_id = g.id
                    LEFT JOIN cuestionarios c ON h.cuestionario_id = c.id
                    WHERE h.grupo_id = %s
                    ORDER BY h.fecha_partida DESC
                """, (grupo_id,))
            else:
                cursor.execute("""
                    SELECT h.*, g.nombre_grupo, c.titulo as titulo_cuestionario
                    FROM historial_partidas h
                    LEFT JOIN grupos g ON h.grupo_id = g.id
                    LEFT JOIN cuestionarios c ON h.cuestionario_id = c.id
                    ORDER BY h.fecha_partida DESC
                """)
            
            partidas = cursor.fetchall()
            
            for p in partidas:
                if p.get('fecha_partida'):
                    p['fecha_partida'] = p['fecha_partida'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                "success": True,
                "data": partidas,
                "total": len(partidas)
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener historial de partidas: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/historial_partidas/<int:partida_id>", methods=["GET"])
def api_obtener_historial_partida_por_id(partida_id):
    """GET: Obtiene una partida específica"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT h.*, g.nombre_grupo, c.titulo as titulo_cuestionario
                FROM historial_partidas h
                LEFT JOIN grupos g ON h.grupo_id = g.id
                LEFT JOIN cuestionarios c ON h.cuestionario_id = c.id
                WHERE h.id = %s
            """, (partida_id,))
            partida = cursor.fetchone()
            
            if not partida:
                return jsonify({
                    "success": False,
                    "message": "Partida no encontrada"
                }), 404
            
            if partida.get('fecha_partida'):
                partida['fecha_partida'] = partida['fecha_partida'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                "success": True,
                "data": partida
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener partida: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/historial_partidas", methods=["POST"])
def api_registrar_historial_partida():
    """POST: Registra una nueva partida grupal"""
    try:
        data = request.get_json()
        
        if not data.get('grupo_id') or not data.get('cuestionario_id'):
            return jsonify({
                "success": False,
                "message": "grupo_id y cuestionario_id son requeridos"
            }), 400
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO historial_partidas 
                (grupo_id, cuestionario_id, nombre_grupo, titulo_cuestionario, 
                 puntuacion_final, num_preguntas_total, num_miembros, fecha_partida)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                data.get('grupo_id'),
                data.get('cuestionario_id'),
                data.get('nombre_grupo'),
                data.get('titulo_cuestionario'),
                data.get('puntuacion_final', 0),
                data.get('num_preguntas_total', 0),
                data.get('num_miembros', 0)
            ))
            conexion.commit()
            
            nuevo_id = cursor.lastrowid
            
            return jsonify({
                "success": True,
                "message": "Partida registrada exitosamente",
                "data": {"id": nuevo_id}
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar partida: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/historial_partidas/<int:partida_id>", methods=["PUT"])
def api_actualizar_historial_partida(partida_id):
    """POST/PUT: Actualiza una partida grupal"""
    try:
        data = request.get_json()
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM historial_partidas WHERE id = %s", (partida_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Partida no encontrada"
                }), 404
            
            cursor.execute("""
                UPDATE historial_partidas 
                SET puntuacion_final = %s, num_preguntas_total = %s, num_miembros = %s
                WHERE id = %s
            """, (
                data.get('puntuacion_final'),
                data.get('num_preguntas_total'),
                data.get('num_miembros'),
                partida_id
            ))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Partida actualizada exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar partida: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/historial_partidas/<int:partida_id>", methods=["DELETE"])
def api_eliminar_historial_partida(partida_id):
    """POST/DELETE: Elimina una partida grupal"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM historial_partidas WHERE id = %s", (partida_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Partida no encontrada"
                }), 404
            
            cursor.execute("DELETE FROM historial_partidas WHERE id = %s", (partida_id,))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Partida eliminada exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar partida: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# ========================================
# TABLA: estudiantes_stats
# ========================================

@app.route("/api/estudiantes_stats", methods=["GET"])
def api_obtener_estudiantes_stats():
    """GET: Lista todas las estadísticas de estudiantes"""
    try:
        usuario_id = request.args.get('user_id')
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            if usuario_id:
                cursor.execute("""
                    SELECT es.*, u.nombre as nombre_estudiante
                    FROM estudiantes_stats es
                    LEFT JOIN usuarios u ON es.user_id = u.id
                    WHERE es.user_id = %s
                """, (usuario_id,))
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
            
            return jsonify({
                "success": True,
                "data": stats,
                "total": len(stats)
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener estadísticas: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/estudiantes_stats/<int:user_id>", methods=["GET"])
def api_obtener_estudiante_stats_por_id(user_id):
    """GET: Obtiene las estadísticas de un estudiante específico"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT es.*, u.nombre as nombre_estudiante, u.correo
                FROM estudiantes_stats es
                LEFT JOIN usuarios u ON es.user_id = u.id
                WHERE es.user_id = %s
            """, (user_id,))
            stats = cursor.fetchone()
            
            if not stats:
                return jsonify({
                    "success": False,
                    "message": "Estadísticas no encontradas"
                }), 404
            
            if stats.get('ultima_partida'):
                stats['ultima_partida'] = stats['ultima_partida'].strftime('%Y-%m-%d')
            if stats.get('fecha_creacion'):
                stats['fecha_creacion'] = stats['fecha_creacion'].strftime('%Y-%m-%d %H:%M:%S')
            
            # Calcular nivel basado en experiencia
            stats['nivel_calculado'] = stats['experiencia_actual'] // 100 + 1
            
            return jsonify({
                "success": True,
                "data": stats
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener estadísticas: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/estudiantes_stats", methods=["POST"])
def api_registrar_estudiante_stats():
    """POST: Registra estadísticas iniciales para un estudiante"""
    try:
        data = request.get_json()
        
        if not data.get('user_id'):
            return jsonify({
                "success": False,
                "message": "user_id es requerido"
            }), 400
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            # Verificar si ya existe
            cursor.execute("SELECT id FROM estudiantes_stats WHERE user_id = %s", (data.get('user_id'),))
            if cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Las estadísticas ya existen para este usuario"
                }), 400
            
            cursor.execute("""
                INSERT INTO estudiantes_stats 
                (user_id, nivel, experiencia_actual, experiencia_total, monedas, 
                 total_partidas, total_preguntas_correctas, total_preguntas_incorrectas, 
                 mejor_puntaje, racha_actual, mejor_racha, fecha_creacion)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                data.get('user_id'),
                data.get('nivel', 1),
                data.get('experiencia_actual', 0),
                data.get('experiencia_total', 0),
                data.get('monedas', 0),
                data.get('total_partidas', 0),
                data.get('total_preguntas_correctas', 0),
                data.get('total_preguntas_incorrectas', 0),
                data.get('mejor_puntaje', 0),
                data.get('racha_actual', 0),
                data.get('mejor_racha', 0)
            ))
            conexion.commit()
            
            nuevo_id = cursor.lastrowid
            
            return jsonify({
                "success": True,
                "message": "Estadísticas creadas exitosamente",
                "data": {"id": nuevo_id}
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar estadísticas: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/estudiantes_stats/<int:user_id>", methods=["PUT"])
def api_actualizar_estudiante_stats(user_id):
    """POST/PUT: Actualiza las estadísticas de un estudiante"""
    try:
        data = request.get_json()
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Estadísticas no encontradas"
                }), 404
            
            cursor.execute("""
                UPDATE estudiantes_stats 
                SET nivel = %s, experiencia_actual = %s, experiencia_total = %s, 
                    monedas = %s, total_partidas = %s, total_preguntas_correctas = %s, 
                    total_preguntas_incorrectas = %s, mejor_puntaje = %s, 
                    racha_actual = %s, mejor_racha = %s, ultima_partida = %s
                WHERE user_id = %s
            """, (
                data.get('nivel'),
                data.get('experiencia_actual'),
                data.get('experiencia_total'),
                data.get('monedas'),
                data.get('total_partidas'),
                data.get('total_preguntas_correctas'),
                data.get('total_preguntas_incorrectas'),
                data.get('mejor_puntaje'),
                data.get('racha_actual'),
                data.get('mejor_racha'),
                data.get('ultima_partida'),
                user_id
            ))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Estadísticas actualizadas exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar estadísticas: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/estudiantes_stats/<int:user_id>", methods=["DELETE"])
def api_eliminar_estudiante_stats(user_id):
    """POST/DELETE: Elimina las estadísticas de un estudiante"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Estadísticas no encontradas"
                }), 404
            
            cursor.execute("DELETE FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Estadísticas eliminadas exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar estadísticas: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# ========================================
# TABLA: participantes_partida
# ========================================

@app.route("/api/participantes_partida", methods=["GET"])
def api_obtener_participantes_partida():
    """GET: Lista participantes de partidas"""
    try:
        partida_id = request.args.get('partida_id')
        usuario_id = request.args.get('usuario_id')
        
        conexion = obtener_conexion()
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
                    p['fecha_participacion'] = p['fecha_participacion'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                "success": True,
                "data": participantes,
                "total": len(participantes)
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener participantes: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/participantes_partida/<int:participante_id>", methods=["GET"])
def api_obtener_participante_partida_por_id(participante_id):
    """GET: Obtiene un participante específico"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT pp.*, u.nombre as nombre_usuario, u.correo
                FROM participantes_partida pp
                LEFT JOIN usuarios u ON pp.usuario_id = u.id
                WHERE pp.id = %s
            """, (participante_id,))
            participante = cursor.fetchone()
            
            if not participante:
                return jsonify({
                    "success": False,
                    "message": "Participante no encontrado"
                }), 404
            
            if participante.get('fecha_participacion'):
                participante['fecha_participacion'] = participante['fecha_participacion'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                "success": True,
                "data": participante
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener participante: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/participantes_partida", methods=["POST"])
def api_registrar_participante_partida():
    """POST: Registra un participante en una partida"""
    try:
        data = request.get_json()
        
        # Validaciones
        if not data.get('partida_id') or not data.get('usuario_id'):
            return jsonify({
                "success": False,
                "message": "partida_id y usuario_id son requeridos"
            }), 400
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            # Verificar si ya está registrado
            cursor.execute("""
                SELECT id FROM participantes_partida 
                WHERE partida_id = %s AND usuario_id = %s
            """, (data.get('partida_id'), data.get('usuario_id')))
            
            if cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "El participante ya está registrado en esta partida"
                }), 400
            
            cursor.execute("""
                INSERT INTO participantes_partida 
                (partida_id, usuario_id, nombre_usuario, fecha_participacion)
                VALUES (%s, %s, %s, NOW())
            """, (
                data.get('partida_id'),
                data.get('usuario_id'),
                data.get('nombre_usuario')
            ))
            conexion.commit()
            
            nuevo_id = cursor.lastrowid
            
            return jsonify({
                "success": True,
                "message": "Participante registrado exitosamente",
                "data": {"id": nuevo_id}
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar participante: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/participantes_partida/<int:participante_id>", methods=["PUT"])
def api_actualizar_participante_partida(participante_id):
    """POST/PUT: Actualiza un participante de partida"""
    try:
        data = request.get_json()
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM participantes_partida WHERE id = %s", (participante_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Participante no encontrado"
                }), 404
            
            cursor.execute("""
                UPDATE participantes_partida 
                SET nombre_usuario = %s
                WHERE id = %s
            """, (
                data.get('nombre_usuario'),
                participante_id
            ))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Participante actualizado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar participante: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/participantes_partida/<int:participante_id>", methods=["DELETE"])
def api_eliminar_participante_partida(participante_id):
    """POST/DELETE: Elimina un participante de una partida"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM participantes_partida WHERE id = %s", (participante_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Participante no encontrado"
                }), 404
            
            cursor.execute("DELETE FROM participantes_partida WHERE id = %s", (participante_id,))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Participante eliminado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar participante: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# ========================================
# TABLA: progreso_grupal
# ========================================

@app.route("/api/progreso_grupal", methods=["GET"])
def api_obtener_progreso_grupal():
    """GET: Lista el progreso grupal"""
    try:
        grupo_id = request.args.get('grupo_id')
        usuario_id = request.args.get('usuario_id')
        pregunta_index = request.args.get('pregunta_index')
        
        conexion = obtener_conexion()
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
                    p['fecha_respuesta'] = p['fecha_respuesta'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                "success": True,
                "data": progresos,
                "total": len(progresos)
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener progreso grupal: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/progreso_grupal/<int:progreso_id>", methods=["GET"])
def api_obtener_progreso_grupal_por_id(progreso_id):
    """GET: Obtiene un progreso grupal específico"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT pg.*, u.nombre as nombre_usuario, g.nombre_grupo
                FROM progreso_grupal pg
                LEFT JOIN usuarios u ON pg.usuario_id = u.id
                LEFT JOIN grupos g ON pg.grupo_id = g.id
                WHERE pg.id = %s
            """, (progreso_id,))
            progreso = cursor.fetchone()
            
            if not progreso:
                return jsonify({
                    "success": False,
                    "message": "Progreso no encontrado"
                }), 404
            
            if progreso.get('fecha_respuesta'):
                progreso['fecha_respuesta'] = progreso['fecha_respuesta'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                "success": True,
                "data": progreso
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener progreso: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/progreso_grupal", methods=["POST"])
def api_registrar_progreso_grupal():
    """POST: Registra el progreso grupal"""
    try:
        data = request.get_json()
        
        # Validaciones
        if not data.get('grupo_id') or not data.get('usuario_id'):
            return jsonify({
                "success": False,
                "message": "grupo_id y usuario_id son requeridos"
            }), 400
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO progreso_grupal 
                (grupo_id, usuario_id, pregunta_index, respondio, fecha_respuesta)
                VALUES (%s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                respondio = %s, fecha_respuesta = NOW()
            """, (
                data.get('grupo_id'),
                data.get('usuario_id'),
                data.get('pregunta_index', 0),
                data.get('respondio', 1),
                data.get('respondio', 1)
            ))
            conexion.commit()
            
            nuevo_id = cursor.lastrowid
            
            return jsonify({
                "success": True,
                "message": "Progreso registrado exitosamente",
                "data": {"id": nuevo_id}
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar progreso: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/progreso_grupal/<int:progreso_id>", methods=["PUT"])
def api_actualizar_progreso_grupal(progreso_id):
    """POST/PUT: Actualiza el progreso grupal"""
    try:
        data = request.get_json()
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM progreso_grupal WHERE id = %s", (progreso_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Progreso no encontrado"
                }), 404
            
            cursor.execute("""
                UPDATE progreso_grupal 
                SET pregunta_index = %s, respondio = %s, fecha_respuesta = NOW()
                WHERE id = %s
            """, (
                data.get('pregunta_index'),
                data.get('respondio'),
                progreso_id
            ))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Progreso actualizado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar progreso: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/progreso_grupal/<int:progreso_id>", methods=["DELETE"])
def api_eliminar_progreso_grupal(progreso_id):
    """POST/DELETE: Elimina un progreso grupal"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM progreso_grupal WHERE id = %s", (progreso_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Progreso no encontrado"
                }), 404
            
            cursor.execute("DELETE FROM progreso_grupal WHERE id = %s", (progreso_id,))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Progreso eliminado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar progreso: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# ========================================
# TABLA: respuestas_individuales
# ========================================

@app.route("/api/respuestas_individuales", methods=["GET"])
def api_obtener_respuestas_individuales():
    """GET: Lista respuestas individuales"""
    try:
        historial_id = request.args.get('historial_id')
        pregunta_id = request.args.get('pregunta_id')
        
        conexion = obtener_conexion()
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
            
            return jsonify({
                "success": True,
                "data": respuestas,
                "total": len(respuestas)
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener respuestas: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/respuestas_individuales/<int:respuesta_id>", methods=["GET"])
def api_obtener_respuesta_individual_por_id(respuesta_id):
    """GET: Obtiene una respuesta individual específica"""
    try:
        conexion = obtener_conexion()
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
            
            if not respuesta:
                return jsonify({
                    "success": False,
                    "message": "Respuesta no encontrada"
                }), 404
            
            return jsonify({
                "success": True,
                "data": respuesta
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener respuesta: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/respuestas_individuales", methods=["POST"])
def api_registrar_respuesta_individual():
    """POST: Registra una respuesta individual"""
    try:
        data = request.get_json()
        
        # Validaciones
        if not data.get('historial_id') or not data.get('pregunta_id'):
            return jsonify({
                "success": False,
                "message": "historial_id y pregunta_id son requeridos"
            }), 400
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO respuestas_individuales 
                (historial_id, pregunta_id, respuesta_estudiante, 
                 es_correcta, puntos, tiempo_respuesta)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                data.get('historial_id'),
                data.get('pregunta_id'),
                data.get('respuesta_estudiante'),
                data.get('es_correcta', 0),
                data.get('puntos', 0),
                data.get('tiempo_respuesta', 0)
            ))
            conexion.commit()
            
            nuevo_id = cursor.lastrowid
            
            return jsonify({
                "success": True,
                "message": "Respuesta registrada exitosamente",
                "data": {"id": nuevo_id}
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar respuesta: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/respuestas_individuales/<int:respuesta_id>", methods=["PUT"])
def api_actualizar_respuesta_individual(respuesta_id):
    """POST/PUT: Actualiza una respuesta individual"""
    try:
        data = request.get_json()
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM respuestas_individuales WHERE id = %s", (respuesta_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Respuesta no encontrada"
                }), 404
            
            cursor.execute("""
                UPDATE respuestas_individuales 
                SET respuesta_estudiante = %s, es_correcta = %s, 
                    puntos = %s, tiempo_respuesta = %s
                WHERE id = %s
            """, (
                data.get('respuesta_estudiante'),
                data.get('es_correcta'),
                data.get('puntos'),
                data.get('tiempo_respuesta'),
                respuesta_id
            ))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Respuesta actualizada exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar respuesta: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/respuestas_individuales/<int:respuesta_id>", methods=["DELETE"])
def api_eliminar_respuesta_individual(respuesta_id):
    """POST/DELETE: Elimina una respuesta individual"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM respuestas_individuales WHERE id = %s", (respuesta_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Respuesta no encontrada"
                }), 404
            
            cursor.execute("DELETE FROM respuestas_individuales WHERE id = %s", (respuesta_id,))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Respuesta eliminada exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar respuesta: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# ========================================
# TABLA: reconocimiento_facial
# ========================================

@app.route("/api/reconocimiento_facial", methods=["GET"])
def api_obtener_reconocimiento_facial():
    """GET: Lista registros de reconocimiento facial"""
    try:
        usuario_id = request.args.get('usuario_id')
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            if usuario_id:
                cursor.execute("""
                    SELECT rf.id, rf.usuario_id, rf.fecha_registro,
                           u.nombre, u.correo
                    FROM reconocimiento_facial rf
                    LEFT JOIN usuarios u ON rf.usuario_id = u.id
                    WHERE rf.usuario_id = %s
                    ORDER BY rf.fecha_registro DESC
                """, (usuario_id,))
            else:
                cursor.execute("""
                    SELECT rf.id, rf.usuario_id, rf.fecha_registro,
                           u.nombre, u.correo
                    FROM reconocimiento_facial rf
                    LEFT JOIN usuarios u ON rf.usuario_id = u.id
                    ORDER BY rf.fecha_registro DESC
                """)
            
            registros = cursor.fetchall()
            
            # NO incluir el embedding en la respuesta por seguridad
            for r in registros:
                if r.get('fecha_registro'):
                    r['fecha_registro'] = r['fecha_registro'].strftime('%Y-%m-%d %H:%M:%S')
                r['tiene_embedding'] = True  # Solo indicar que existe
            
            return jsonify({
                "success": True,
                "data": registros,
                "total": len(registros)
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener registros: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/reconocimiento_facial/<int:reconocimiento_id>", methods=["GET"])
def api_obtener_reconocimiento_facial_por_id(reconocimiento_id):
    """GET: Obtiene un registro de reconocimiento facial específico"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT rf.id, rf.usuario_id, rf.fecha_registro,
                       u.nombre, u.correo
                FROM reconocimiento_facial rf
                LEFT JOIN usuarios u ON rf.usuario_id = u.id
                WHERE rf.id = %s
            """, (reconocimiento_id,))
            registro = cursor.fetchone()
            
            if not registro:
                return jsonify({
                    "success": False,
                    "message": "Registro no encontrado"
                }), 404
            
            if registro.get('fecha_registro'):
                registro['fecha_registro'] = registro['fecha_registro'].strftime('%Y-%m-%d %H:%M:%S')
            
            registro['tiene_embedding'] = True
            
            return jsonify({
                "success": True,
                "data": registro
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener registro: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/reconocimiento_facial", methods=["POST"])
def api_registrar_reconocimiento_facial():
    """POST: Registra un embedding facial"""
    try:
        data = request.get_json()
        
        # Validaciones
        if not data.get('usuario_id') or not data.get('embedding'):
            return jsonify({
                "success": False,
                "message": "usuario_id y embedding son requeridos"
            }), 400
        
        # Validar que el embedding tenga 128 dimensiones
        if len(data.get('embedding')) != 128:
            return jsonify({
                "success": False,
                "message": "El embedding debe tener 128 dimensiones"
            }), 400
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            # Verificar si ya existe un registro
            cursor.execute("""
                SELECT id FROM reconocimiento_facial WHERE usuario_id = %s
            """, (data.get('usuario_id'),))
            
            existing = cursor.fetchone()
            
            embedding_json = json.dumps(data.get('embedding'))
            
            if existing:
                # Actualizar el registro existente
                cursor.execute("""
                    UPDATE reconocimiento_facial 
                    SET embedding = %s, fecha_registro = NOW()
                    WHERE usuario_id = %s
                """, (embedding_json, data.get('usuario_id')))
                registro_id = existing['id']
                mensaje = "Reconocimiento facial actualizado exitosamente"
            else:
                # Crear nuevo registro
                cursor.execute("""
                    INSERT INTO reconocimiento_facial 
                    (usuario_id, embedding, fecha_registro)
                    VALUES (%s, %s, NOW())
                """, (data.get('usuario_id'), embedding_json))
                registro_id = cursor.lastrowid
                mensaje = "Reconocimiento facial registrado exitosamente"
            
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": mensaje,
                "data": {"id": registro_id}
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar reconocimiento facial: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/reconocimiento_facial/<int:reconocimiento_id>", methods=["PUT"])
def api_actualizar_reconocimiento_facial(reconocimiento_id):
    """POST/PUT: Actualiza un registro de reconocimiento facial"""
    try:
        data = request.get_json()
        
        if not data.get('embedding'):
            return jsonify({
                "success": False,
                "message": "embedding es requerido"
            }), 400
        
        if len(data.get('embedding')) != 128:
            return jsonify({
                "success": False,
                "message": "El embedding debe tener 128 dimensiones"
            }), 400
        
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM reconocimiento_facial WHERE id = %s", (reconocimiento_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Registro no encontrado"
                }), 404
            
            embedding_json = json.dumps(data.get('embedding'))
            
            cursor.execute("""
                UPDATE reconocimiento_facial 
                SET embedding = %s, fecha_registro = NOW()
                WHERE id = %s
            """, (embedding_json, reconocimiento_id))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Reconocimiento facial actualizado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar reconocimiento facial: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/reconocimiento_facial/<int:reconocimiento_id>", methods=["DELETE"])
def api_eliminar_reconocimiento_facial(reconocimiento_id):
    """POST/DELETE: Elimina un registro de reconocimiento facial"""
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id FROM reconocimiento_facial WHERE id = %s", (reconocimiento_id,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Registro no encontrado"
                }), 404
            
            cursor.execute("DELETE FROM reconocimiento_facial WHERE id = %s", (reconocimiento_id,))
            conexion.commit()
            
            return jsonify({
                "success": True,
                "message": "Reconocimiento facial eliminado exitosamente"
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar reconocimiento facial: {str(e)}"
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()