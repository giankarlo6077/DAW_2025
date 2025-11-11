import pymysql
import pymysql.cursors
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_mail import Mail, Message
from bd import obtener_conexion
import random
import string
import re
import secrets
from datetime import datetime, timedelta, date
from io import BytesIO
import json
import pandas as pd
import traceback
import pytz
import jwt
from functools import wraps

from io import BytesIO
import json

PERU_TZ = pytz.timezone('America/Lima')

app = Flask(__name__)


# --- CONFIGURACIÓN DE LA APLICACIÓN ---
app.secret_key = 'una-clave-secreta-muy-larga-y-dificil-de-adivinar'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['JWT_SECRET_KEY'] = 'tu-jwt-secret-key-super-segura-cambiala'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Configuración de correo
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'cevar4@gmail.com'
app.config['MAIL_PASSWORD'] = 'rgzl jhyh ceaa snxi'
app.config['MAIL_DEFAULT_SENDER'] = 'cevar4@gmail.com'
app.config['MAIL_DEBUG'] = True

mail = Mail(app)

# ========== NUEVO: FUNCIONES Y DECORADORES JWT ==========

def generar_token_jwt(usuario_id, rol):
    """Genera un token JWT para el usuario"""
    try:
        payload = {
            'usuario_id': usuario_id,
            'rol': rol,
            'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
            'iat': datetime.utcnow()
        }
        token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
        return token
    except Exception as e:
        print(f"Error generando token: {e}")
        return None


def token_requerido(f):
    """Decorador para proteger rutas con JWT"""
    @wraps(f)
    def decorador(*args, **kwargs):
        token = None

        # Buscar token en headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Format: "Bearer TOKEN"
            except IndexError:
                return jsonify({'success': False, 'mensaje': 'Formato de token inválido'}), 401

        # Si no hay token en headers, buscar en cookies (para compatibilidad con navegador)
        if not token and 'token_jwt' in request.cookies:
            token = request.cookies.get('token_jwt')

        if not token:
            return jsonify({'success': False, 'mensaje': 'Token faltante. Inicia sesión nuevamente.'}), 401

        try:
            # Decodificar token
            datos = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            usuario_id = datos['usuario_id']
            rol = datos['rol']

            # Verificar que el usuario existe
            conexion = obtener_conexion()
            with conexion.cursor() as cursor:
                cursor.execute("SELECT id, rol FROM usuarios WHERE id = %s", (usuario_id,))
                usuario = cursor.fetchone()

                if not usuario:
                    return jsonify({'success': False, 'mensaje': 'Usuario no encontrado'}), 401

            conexion.close()

        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'mensaje': 'Token expirado. Inicia sesión nuevamente.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'mensaje': 'Token inválido'}), 401
        except Exception as e:
            print(f"Error validando token: {e}")
            return jsonify({'success': False, 'mensaje': 'Error en la autenticación'}), 401

        # Pasar usuario_id y rol a la función
        return f(usuario_id, rol, *args, **kwargs)

    return decorador


def rol_requerido(roles_permitidos):
    """Decorador adicional para verificar roles específicos"""
    def decorador_rol(f):
        @wraps(f)
        def wrapper(usuario_id, rol, *args, **kwargs):
            if rol not in roles_permitidos:
                return jsonify({'success': False, 'mensaje': 'No tienes permisos para esta acción'}), 403
            return f(usuario_id, rol, *args, **kwargs)
        return wrapper
    return decorador_rol


# --- FUNCIONES DE AYUDA ---
def verificar_todos_listos_individual(sesion_id, pregunta_index):
    """Verifica si todos los estudiantes de una sesión terminaron la pregunta actual"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Contar estudiantes en la sesión
            cursor.execute("""
                SELECT COUNT(*) as total
                FROM salas_espera
                WHERE sesion_id = %s
            """, (sesion_id,))
            total = cursor.fetchone()['total']

            # Contar estudiantes listos para la siguiente pregunta
            cursor.execute("""
                SELECT COUNT(*) as listos
                FROM salas_espera
                WHERE sesion_id = %s
                AND pregunta_actual >= %s
                AND listo_para_siguiente = TRUE
            """, (sesion_id, pregunta_index))
            listos = cursor.fetchone()['listos']

            return listos >= total
    finally:
        if conexion and conexion.open:
            conexion.close()

def verificar_todos_listos_grupal(grupo_id, pregunta_index):
    """Verifica si todos los miembros del grupo terminaron la pregunta actual"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Contar miembros del grupo
            cursor.execute("""
                SELECT COUNT(*) as total
                FROM usuarios
                WHERE grupo_id = %s
            """, (grupo_id,))
            total = cursor.fetchone()['total']

            # Contar miembros que respondieron
            cursor.execute("""
                SELECT COUNT(DISTINCT usuario_id) as respondidos
                FROM progreso_grupal
                WHERE grupo_id = %s
                AND pregunta_index = %s
                AND respondio = TRUE
            """, (grupo_id, pregunta_index))
            respondidos = cursor.fetchone()['respondidos']

            return respondidos >= total
    finally:
        if conexion and conexion.open:
            conexion.close()

def marcar_estudiante_listo_individual(usuario_id, sesion_id, pregunta_index):
    """Marca que un estudiante terminó de responder una pregunta"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                UPDATE salas_espera
                SET pregunta_actual = %s,
                    listo_para_siguiente = TRUE
                WHERE usuario_id = %s AND sesion_id = %s
            """, (pregunta_index, usuario_id, sesion_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def marcar_miembro_listo_grupal(grupo_id, usuario_id, pregunta_index):
    """Marca que un miembro del grupo terminó de responder"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO progreso_grupal
                (grupo_id, usuario_id, pregunta_index, respondio, fecha_respuesta)
                VALUES (%s, %s, %s, TRUE, NOW())
                ON DUPLICATE KEY UPDATE
                respondio = TRUE,
                fecha_respuesta = NOW()
            """, (grupo_id, usuario_id, pregunta_index))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def resetear_barrera_individual(sesion_id):
    """Resetea el estado de 'listo' para la siguiente pregunta"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                UPDATE salas_espera
                SET listo_para_siguiente = FALSE
                WHERE sesion_id = %s
            """, (sesion_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def convertir_a_hora_peru(fecha_utc):
    """Convierte una fecha UTC a hora de Perú"""
    if fecha_utc is None:
        return None

    # Si la fecha no tiene timezone, asumimos que es UTC
    if fecha_utc.tzinfo is None:
        fecha_utc = pytz.utc.localize(fecha_utc)

    # Convertir a hora de Perú
    return fecha_utc.astimezone(PERU_TZ)

def es_password_segura(password):
    """Verifica si la contraseña cumple con los requisitos de seguridad."""
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if not re.search("[a-z]", password):
        return False, "La contraseña debe contener al menos una letra minúscula."
    if not re.search("[A-Z]", password):
        return False, "La contraseña debe contener al menos una letra mayúscula."
    if not re.search("[0-9]", password):
        return False, "La contraseña debe contener al menos un número."
    return True, ""

def generar_codigo_grupo():
    """Genera un código de grupo único de 8 caracteres."""
    while True:
        codigo = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("SELECT id FROM grupos WHERE codigo_grupo = %s", (codigo,))
                if not cursor.fetchone():
                    return codigo
        finally:
            if conexion and conexion.open:
                conexion.close()

def obtener_items_equipados(user_id):
    """Obtiene todos los items equipados del estudiante"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # NOTA: La tabla estudiantes_items usa la columna usuario_id
            # El dashboard_estudiante necesita el user_id de la sesión
            cursor.execute("""
                SELECT ti.tipo, ti.icono, ti.nombre
                FROM estudiantes_items ei
                JOIN tienda_items ti ON ei.item_id = ti.id
                WHERE ei.usuario_id = %s AND ei.equipado = 1
            """, (user_id,))

            items = cursor.fetchall()

            # Organizar items por tipo
            items_equipados = {
                'avatar': None,
                'marco': None,
                'titulo': None
            }

            for item in items:
                items_equipados[item['tipo']] = {
                    'icono': item['icono'],
                    'nombre': item['nombre']
                }

            return items_equipados
    finally:
        if conexion and conexion.open:
            conexion.close()

def enviar_correo_recuperacion(correo, token):
    """Envía un correo con el enlace para restablecer la contraseña."""
    try:
        with app.app_context():
            enlace_reseteo = url_for('resetear_password', token=token, _external=True)
        msg = Message('Restablece tu Contraseña - Sistema de Cuestionarios', recipients=[correo])
        msg.html = f"""
        <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f6fa;">
            <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #667eea; text-align: center;">Restablecer Contraseña</h2>
                <p>Hola,</p>
                <p>Recibimos una solicitud para restablecer tu contraseña. Haz clic en el siguiente enlace para continuar:</p>
                <p style="text-align: center;">
                    <a href="{enlace_reseteo}" style="display: inline-block; background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold;">
                        Restablecer mi contraseña
                    </a>
                </p>
                <p>Si no solicitaste esto, puedes ignorar este correo.</p>
                <p style="font-size: 12px; color: #999;">Este enlace expirará en 1 hora.</p>
            </div>
        </div>
        """
        mail.send(msg)
        return True
    except Exception as e:
        print(f"❌ Error al enviar correo de recuperación: {str(e)}")
        return False

def generar_pin():
    while True:
        pin = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("SELECT id FROM cuestionarios WHERE codigo_pin=%s", (pin,))
                if not cursor.fetchone():
                    return pin
        finally:
            conexion.close()

def generar_codigo_verificacion():
    return ''.join(random.choices(string.digits, k=6))

def enviar_correo_verificacion_mejorado(correo, codigo, nombre):
    try:
        with app.app_context():
            enlace_verificacion = url_for('verificar_cuenta', _external=True)
        msg = Message(subject='Verifica tu cuenta - Sistema de Cuestionarios', recipients=[correo])
        msg.html = f'''
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f6fa;">
            <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h2 style="color: #667eea; margin: 0;">¡Bienvenido a nuestro Sistema!</h2>
                </div>
                <p style="color: #333; font-size: 16px;">Hola <strong>{nombre}</strong>,</p>
                <p style="color: #666; line-height: 1.6;">Gracias por registrarte.</p>
                <div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 20px; margin: 25px 0; border-radius: 5px;">
                    <h3 style="color: #1976d2; margin-top: 0;">Tienes dos opciones para verificar:</h3>
                    <p style="color: #0d47a1; margin: 15px 0;"><strong>Opción 1: Hacer clic en el enlace</strong></p>
                    <a href="{enlace_verificacion}" style="display: inline-block; background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 10px 0;">
                        Verificar mi cuenta
                    </a>
                    <p style="color: #0d47a1; margin: 20px 0 10px 0;"><strong>Opción 2: Ingresar este código</strong></p>
                    <div style="background: #667eea; color: white; padding: 20px; text-align: center; border-radius: 10px; font-size: 32px; font-weight: bold; letter-spacing: 8px; margin: 10px 0;">
                        {codigo}
                    </div>
                </div>
                <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p style="color: #856404; margin: 0;"><strong>Este código expira en 15 minutos</strong></p>
                </div>
            </div>
        </body>
        </html>
        '''
        mail.send(msg)
        return True
    except Exception as e:
        print(f"❌ Error al enviar correo: {str(e)}")
        return False

# --- RUTAS DE AUTENTICACIÓN Y USUARIO ---

@app.route("/")
def inicio():
    return redirect(url_for("login"))

@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form["nombre"]
        correo = request.form["correo"]
        password = request.form["password"]
        confirmar = request.form["confirmar"]
        rol = request.form["rol"]

        if password != confirmar:
            flash("❌ Las contraseñas no coinciden", "error")
            return render_template("registro.html", nombre=nombre, correo=correo, rol_seleccionado=rol)

        es_segura, mensaje_error = es_password_segura(password)
        if not es_segura:
            flash(f"❌ {mensaje_error}", "error")
            return render_template("registro.html", nombre=nombre, correo=correo, rol_seleccionado=rol)

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("SELECT id FROM usuarios WHERE correo = %s", (correo,))
                if cursor.fetchone():
                    flash("❌ Ese correo ya está registrado.", "error")
                    return render_template("registro.html", nombre=nombre, correo=correo, rol_seleccionado=rol)

                codigo = generar_codigo_verificacion()
                fecha_codigo = datetime.now()
                sql = """INSERT INTO usuarios (nombre, correo, password, rol, verificado, codigo_verificacion, fecha_codigo)
                         VALUES (%s, %s, %s, %s, FALSE, %s, %s)"""
                cursor.execute(sql, (nombre, correo, password, rol, codigo, fecha_codigo))
                conexion.commit()
                usuario_id = cursor.lastrowid

            session["temp_usuario_id"] = usuario_id
            session["temp_correo"] = correo
            session["temp_nombre"] = nombre
            session["temp_rol"] = rol

            if enviar_correo_verificacion_mejorado(correo, codigo, nombre):
                return render_template("registro_exitoso.html", correo=correo)
            else:
                flash("❌ Error al enviar el correo de verificación.", "error")
                return redirect(url_for("registro"))
        except Exception as e:
            flash("❌ Error al procesar el registro.", "error")
            print(f"Error en /registro: {e}")
            return redirect(url_for("registro"))
        finally:
            if conexion and conexion.open:
                conexion.close()

    return render_template("registro.html")

@app.route("/verificar_cuenta", methods=["GET", "POST"])
def verificar_cuenta():
    if "temp_correo" not in session: return redirect(url_for("registro"))
    if request.method == "POST":
        codigo_ingresado = request.form["codigo"]
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("SELECT * FROM usuarios WHERE id=%s AND codigo_verificacion=%s", (session["temp_usuario_id"], codigo_ingresado))
                usuario = cursor.fetchone()
                if not usuario:
                    flash("❌ Código incorrecto.", "error")
                    return redirect(url_for("verificar_cuenta"))
                if datetime.now() - usuario["fecha_codigo"] > timedelta(minutes=15):
                    flash("❌ El código ha expirado. Solicita uno nuevo.", "error")
                    return redirect(url_for("reenviar_codigo"))
                cursor.execute("UPDATE usuarios SET verificado=TRUE, codigo_verificacion=NULL, fecha_codigo=NULL WHERE id=%s", (session["temp_usuario_id"],))
                conexion.commit()
            session.permanent = True
            session["usuario"] = session["temp_nombre"]
            session["correo"] = session["temp_correo"]
            session["rol"] = session["temp_rol"]
            session["user_id"] = session["temp_usuario_id"]
            for key in ["temp_usuario_id", "temp_correo", "temp_nombre", "temp_rol"]: session.pop(key, None)
            flash("✅ ¡Cuenta verificada exitosamente!", "success")
            return render_template("bienvenido.html", nombre=session["usuario"], rol=session["rol"])
        finally:
            conexion.close()
    return render_template("verificar_cuenta.html", correo=session["temp_correo"])

@app.route("/reenviar_codigo")
def reenviar_codigo():
    if "temp_usuario_id" not in session:
        flash("Tu sesión ha expirado. Por favor, intenta registrarte de nuevo.", "error")
        return redirect(url_for("registro"))
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            codigo = generar_codigo_verificacion()
            fecha_codigo = datetime.now()
            cursor.execute("UPDATE usuarios SET codigo_verificacion=%s, fecha_codigo=%s WHERE id=%s", (codigo, fecha_codigo, session["temp_usuario_id"]))
            conexion.commit()
            if enviar_correo_verificacion_mejorado(session["temp_correo"], codigo, session["temp_nombre"]):
                flash("✅ Se ha reenviado un nuevo código a tu correo.", "success")
            else:
                flash("❌ Hubo un error al reenviar el código.", "error")
    finally:
        if conexion and conexion.open:
            conexion.close()
    return redirect(url_for("verificar_cuenta"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")

        if not correo or not password:
            flash("Por favor, ingresa tu correo y contraseña.", "warning")
            return render_template("login.html")

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("SELECT * FROM usuarios WHERE correo = %s", (correo,))
                usuario = cursor.fetchone()

                if usuario and usuario["password"] == password:
                    session.permanent = True
                    session["user_id"] = usuario["id"]
                    session["user_name"] = usuario["nombre"]
                    session["user_role"] = usuario["rol"]

                    # ← NUEVO: Generar token JWT
                    token = generar_token_jwt(usuario["id"], usuario["rol"])

                    if usuario["rol"] == "profesor":
                        response = redirect(url_for("dashboard_profesor"))
                    else:
                        response = redirect(url_for("dashboard_estudiante"))

                    # ← NUEVO: Guardar token en cookie (para requests del navegador)
                    response.set_cookie('token_jwt', token, httponly=True, secure=False, samesite='Lax')

                    flash(f"¡Bienvenido, {usuario['nombre']}!", "success")
                    return response
                else:
                    flash("Correo o contraseña incorrectos.", "danger")
        finally:
            if conexion and conexion.open:
                conexion.close()

    return render_template("iniciosesion.html")

@app.route("/api/auth/token", methods=["POST"])
def obtener_token():
    """Endpoint para obtener un token JWT mediante credenciales"""
    try:
        data = request.get_json()

        correo = data.get('correo', '').strip().lower()
        password = data.get('password', '')

        if not correo or not password:
            return jsonify({
                'success': False,
                'mensaje': 'Correo y contraseña son requeridos'
            }), 400

        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id, nombre, rol, password FROM usuarios WHERE correo = %s", (correo,))
            usuario = cursor.fetchone()

            if not usuario or usuario['password'] != password:
                return jsonify({
                    'success': False,
                    'mensaje': 'Credenciales inválidas'
                }), 401

            # Generar token
            token = generar_token_jwt(usuario['id'], usuario['rol'])

            if not token:
                return jsonify({
                    'success': False,
                    'mensaje': 'Error generando token'
                }), 500

            return jsonify({
                'success': True,
                'token': token,
                'usuario': {
                    'id': usuario['id'],
                    'nombre': usuario['nombre'],
                    'rol': usuario['rol']
                },
                'expira_en': str(app.config['JWT_ACCESS_TOKEN_EXPIRES'])
            }), 200

    except Exception as e:
        print(f"Error en obtener_token: {e}")
        return jsonify({
            'success': False,
            'mensaje': f'Error del servidor: {str(e)}'
        }), 500
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/recuperar_password", methods=["GET", "POST"])
def recuperar_password():
    if request.method == "POST":
        correo = request.form["correo"]
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("SELECT id FROM usuarios WHERE correo = %s", (correo,))
                if usuario := cursor.fetchone():
                    token, expiracion = secrets.token_urlsafe(16), datetime.now() + timedelta(hours=1)
                    cursor.execute("UPDATE usuarios SET reset_token = %s, reset_token_expiration = %s WHERE id = %s", (token, expiracion, usuario['id']))
                    conexion.commit()
                    enviar_correo_recuperacion(correo, token)
            flash("✅ Si tu correo está registrado, recibirás un enlace para restablecer tu contraseña.", "success")
            return redirect(url_for("login"))
        finally:
            if conexion and conexion.open: conexion.close()
    return render_template("recuperar_password.html")

@app.route("/resetear_password/<token>", methods=["GET", "POST"])
def resetear_password(token):
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT id, reset_token_expiration FROM usuarios WHERE reset_token = %s", (token,))
            usuario = cursor.fetchone()
            if not usuario or datetime.now() > usuario['reset_token_expiration']:
                flash("❌ El enlace de recuperación es inválido o ha expirado.", "error")
                return redirect(url_for("login"))
            if request.method == "POST":
                password, confirmar = request.form["password"], request.form["confirmar"]
                if password != confirmar:
                    flash("❌ Las nuevas contraseñas no coinciden.", "error")
                    return render_template("resetear_password.html", token=token)
                es_segura, mensaje_error = es_password_segura(password)
                if not es_segura:
                    flash(f"❌ {mensaje_error}", "error")
                    return render_template("resetear_password.html", token=token)
                cursor.execute("UPDATE usuarios SET password = %s, reset_token = NULL, reset_token_expiration = NULL WHERE id = %s", (password, usuario['id']))
                conexion.commit()
                flash("✅ Tu contraseña ha sido actualizada. Ya puedes iniciar sesión.", "success")
                return redirect(url_for("login"))
    finally:
        if conexion and conexion.open: conexion.close()
    return render_template("resetear_password.html", token=token)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --- RUTAS DE PROFESOR ---

@app.route("/dashboard_profesor")
def dashboard_profesor():
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT c.*, COUNT(p.id) as total_preguntas
                FROM cuestionarios c
                LEFT JOIN preguntas p ON c.id = p.cuestionario_id
                WHERE c.profesor_id = %s
                GROUP BY c.id ORDER BY c.fecha_creacion DESC
            """, (session["user_id"],))
            cuestionarios = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) as total FROM cuestionarios WHERE profesor_id = %s", (session["user_id"],))
            total_cuestionarios = cursor.fetchone()['total']
            cursor.execute("""
                SELECT COUNT(*) as total FROM preguntas p
                INNER JOIN cuestionarios c ON p.cuestionario_id = c.id
                WHERE c.profesor_id = %s
            """, (session["user_id"],))
            total_preguntas = cursor.fetchone()['total']
    finally:
        if conexion and conexion.open:
            conexion.close()
    return render_template("dashboard_profesor.html",
                           nombre=session["usuario"],
                           cuestionarios=cuestionarios,
                           total_cuestionarios=total_cuestionarios,
                           total_preguntas=total_preguntas)

@app.route("/crear_cuestionario", methods=["POST"])
def crear_cuestionario():
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))
    try:
        titulo = request.form["titulo"]
        descripcion = request.form["descripcion"]
        modo_juego = request.form["modo_juego"]
        tiempo_pregunta = int(request.form["tiempo_pregunta"])
        num_preguntas = int(request.form["num_preguntas"])
        codigo_pin = generar_pin()
        profesor_id = session["user_id"]
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            sql = """INSERT INTO cuestionarios
                     (titulo, descripcion, modo_juego, tiempo_pregunta, num_preguntas, codigo_pin, profesor_id)
                     VALUES (%s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql, (titulo, descripcion, modo_juego, tiempo_pregunta, num_preguntas, codigo_pin, profesor_id))
            conexion.commit()
            cuestionario_id = cursor.lastrowid
        return redirect(url_for("agregar_preguntas", cuestionario_id=cuestionario_id))
    except Exception as e:
        flash(f"❌ Error al crear cuestionario: {str(e)}", "error")
        return redirect(url_for("dashboard_profesor"))
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/agregar_preguntas/<int:cuestionario_id>")
def agregar_preguntas(cuestionario_id):
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM cuestionarios WHERE id=%s AND profesor_id=%s", (cuestionario_id, session["user_id"]))
            cuestionario = cursor.fetchone()
        if not cuestionario:
            flash("❌ Cuestionario no encontrado", "error")
            return redirect(url_for("dashboard_profesor"))
        return render_template("agregar_preguntas.html", cuestionario=cuestionario, preguntas=[])
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/guardar_preguntas/<int:cuestionario_id>", methods=["POST"])
def guardar_preguntas(cuestionario_id):
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "Acceso denegado"}), 403
    try:
        data = request.get_json()
        preguntas = data.get("preguntas", [])
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            for idx, pregunta in enumerate(preguntas, start=1):
                sql = """INSERT INTO preguntas (cuestionario_id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, orden)
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
                cursor.execute(sql, (cuestionario_id, pregunta["pregunta"], pregunta["opcion_a"], pregunta["opcion_b"], pregunta["opcion_c"], pregunta["opcion_d"], pregunta["respuesta_correcta"], idx))
            conexion.commit()
        return jsonify({"success": True, "message": "Preguntas guardadas correctamente"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/editar_cuestionario/<int:cuestionario_id>")
def editar_cuestionario(cuestionario_id):
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM cuestionarios WHERE id=%s AND profesor_id=%s", (cuestionario_id, session["user_id"]))
            cuestionario = cursor.fetchone()
            if not cuestionario:
                flash("❌ Cuestionario no encontrado", "error")
                return redirect(url_for("dashboard_profesor"))
            cursor.execute("SELECT * FROM preguntas WHERE cuestionario_id=%s ORDER BY orden", (cuestionario_id,))
            preguntas = cursor.fetchall()
        return render_template("editar_cuestionario.html", cuestionario=cuestionario, preguntas=preguntas)
    except Exception as e:
        flash(f"❌ Error al cargar el cuestionario: {str(e)}", "error")
        return redirect(url_for("dashboard_profesor"))
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/actualizar_cuestionario/<int:cuestionario_id>", methods=["POST"])
def actualizar_cuestionario(cuestionario_id):
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "Acceso denegado"}), 403
    try:
        data = request.get_json()
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            sql = "UPDATE cuestionarios SET titulo=%s, descripcion=%s, modo_juego=%s, tiempo_pregunta=%s, num_preguntas=%s WHERE id=%s"
            cursor.execute(sql, (data['titulo'], data['descripcion'], data['modo_juego'], data['tiempo_pregunta'], len(data['preguntas']), cuestionario_id))
            cursor.execute("DELETE FROM preguntas WHERE cuestionario_id=%s", (cuestionario_id,))
            for idx, p in enumerate(data['preguntas'], start=1):
                sql = "INSERT INTO preguntas (cuestionario_id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, orden) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
                cursor.execute(sql, (cuestionario_id, p['pregunta'], p['opcion_a'], p['opcion_b'], p['opcion_c'], p['opcion_d'], p['respuesta_correcta'], idx))
            conexion.commit()
        return jsonify({"success": True, "message": "Cuestionario actualizado"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/eliminar_cuestionario/<int:cuestionario_id>", methods=["POST"])
def eliminar_cuestionario(cuestionario_id):
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "Acceso denegado"}), 403
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("DELETE FROM preguntas WHERE cuestionario_id = %s", (cuestionario_id,))
            cursor.execute("DELETE FROM cuestionarios WHERE id = %s AND profesor_id = %s", (cuestionario_id, session['user_id']))
            conexion.commit()
        return jsonify({"success": True, "message": "Cuestionario eliminado"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/cambiar_datos_profesor", methods=["GET", "POST"])
def cambiar_datos_profesor():
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))
    if request.method == "POST":
        nombre_nuevo = request.form["nombre"]
        password_actual = request.form["password_actual"]
        password_nueva = request.form.get("password_nueva", "")
        confirmar_nueva = request.form.get("confirmar_nueva", "")
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("SELECT password FROM usuarios WHERE id=%s", (session["user_id"],))
                usuario = cursor.fetchone()
                if not usuario or usuario["password"] != password_actual:
                    flash("❌ La contraseña actual es incorrecta", "error")
                    return redirect(url_for("cambiar_datos_profesor"))
                if password_nueva:
                    if password_nueva != confirmar_nueva:
                        flash("❌ Las contraseñas nuevas no coinciden", "error")
                        return redirect(url_for("cambiar_datos_profesor"))
                    es_segura, msg = es_password_segura(password_nueva)
                    if not es_segura:
                        flash(f"❌ {msg}", "error")
                        return redirect(url_for("cambiar_datos_profesor"))
                    cursor.execute("UPDATE usuarios SET nombre=%s, password=%s WHERE id=%s", (nombre_nuevo, password_nueva, session["user_id"]))
                else:
                    cursor.execute("UPDATE usuarios SET nombre=%s WHERE id=%s", (nombre_nuevo, session["user_id"]))
                conexion.commit()
            session["usuario"] = nombre_nuevo
            flash("✅ Datos actualizados correctamente", "success")
            return redirect(url_for("dashboard_profesor"))
        finally:
            if conexion and conexion.open:
                conexion.close()
    return render_template("CambiarDatos_profesor.html", nombre=session["usuario"], correo=session["correo"])

@app.route("/eliminar_cuenta_profesor", methods=["POST"])
def eliminar_cuenta_profesor():
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    password_actual = request.form.get("password_actual")
    user_id = session["user_id"]
    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT password FROM usuarios WHERE id = %s", (user_id,))
            usuario = cursor.fetchone()
            if not usuario or usuario['password'] != password_actual:
                flash("❌ Contraseña incorrecta. No se pudo eliminar la cuenta.", "error")
                return redirect(url_for('cambiar_datos_profesor'))

            cursor.execute("SELECT id FROM cuestionarios WHERE profesor_id = %s", (user_id,))
            cuestionarios = cursor.fetchall()
            if cuestionarios:
                cuestionario_ids = [c['id'] for c in cuestionarios]
                id_placeholders = ', '.join(['%s'] * len(cuestionario_ids))
                cursor.execute(f"DELETE FROM preguntas WHERE cuestionario_id IN ({id_placeholders})", tuple(cuestionario_ids))

            cursor.execute("DELETE FROM cuestionarios WHERE profesor_id = %s", (user_id,))
            cursor.execute("DELETE FROM usuarios WHERE id = %s", (user_id,))

            conexion.commit()
            session.clear()
            flash("✅ Tu cuenta y todos tus datos han sido eliminados permanentemente.", "success")
            return redirect(url_for('login'))

    except Exception as e:
        flash("❌ Ocurrió un error al intentar eliminar la cuenta.", "error")
        print(f"Error al eliminar cuenta: {e}")
        return redirect(url_for('cambiar_datos_profesor'))
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/dashboard_estudiante")
def dashboard_estudiante():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    # Variables por defecto
    grupo_info = None
    miembros = []
    cuestionarios_recientes = []
    user_id = session.get("user_id")

    print(f"\n{'='*70}")
    print(f"📊 CARGANDO DASHBOARD ESTUDIANTE")
    print(f"👤 Usuario: {session['usuario']} (ID: {user_id})")
    print(f"{'='*70}\n")

    # === BLOQUE 1: Información del grupo ===
    try:
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # Obtener grupo del usuario
                cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
                usuario_data = cursor.fetchone()

                if usuario_data and usuario_data.get('grupo_id'):
                    grupo_id = usuario_data['grupo_id']

                    # Información del grupo
                    cursor.execute("SELECT * FROM grupos WHERE id = %s", (grupo_id,))
                    grupo_info = cursor.fetchone()

                    # Miembros del grupo
                    cursor.execute("SELECT id, nombre FROM usuarios WHERE grupo_id = %s", (grupo_id,))
                    miembros = cursor.fetchall()

                    print(f"✅ Grupo: {grupo_info['nombre_grupo'] if grupo_info else 'N/A'}")
                    print(f"   Miembros: {len(miembros)}")
                else:
                    print(f"ℹ️ Usuario no pertenece a ningún grupo")

        except Exception as e:
            print(f"⚠️ Error al cargar grupo: {e}")
        finally:
            if conexion and conexion.open:
                conexion.close()
    except Exception as e:
        print(f"❌ Error crítico en bloque de grupo: {e}")

    # === BLOQUE 2: Historial de partidas ===
    print(f"\n📚 Cargando historial...")

    partidas_grupales = []
    partidas_individuales = []

    # 2.1 Cargar historial GRUPAL
    try:
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("""
                    SELECT
                        h.titulo_cuestionario,
                        h.puntuacion_final,
                        h.fecha_partida,
                        h.nombre_grupo,
                        'grupal' as tipo
                    FROM historial_partidas h
                    INNER JOIN participantes_partida p ON h.id = p.partida_id
                    WHERE p.usuario_id = %s
                    ORDER BY h.fecha_partida DESC
                    LIMIT 5
                """, (user_id,))

                partidas_grupales = cursor.fetchall() or []
                print(f"   ✅ Partidas grupales: {len(partidas_grupales)}")

        except Exception as e:
            print(f"   ⚠️ No se pudo cargar historial grupal: {e}")
        finally:
            if conexion and conexion.open:
                conexion.close()
    except Exception as e:
        print(f"   ❌ Error en conexión grupal: {e}")

    # 2.2 Cargar historial INDIVIDUAL
    try:
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("""
                    SELECT
                        hi.id,
                        hi.cuestionario_id,
                        hi.puntuacion_final,
                        hi.fecha_realizacion,
                        c.titulo as titulo_cuestionario
                    FROM historial_individual hi
                    INNER JOIN cuestionarios c ON hi.cuestionario_id = c.id
                    WHERE hi.usuario_id = %s
                      AND hi.puntuacion_final > 0
                    ORDER BY hi.fecha_realizacion DESC
                    LIMIT 5
                """, (user_id,))

                resultados = cursor.fetchall() or []

                # Formatear para que coincida con el formato grupal
                for resultado in resultados:
                    partidas_individuales.append({
                        'titulo_cuestionario': resultado['titulo_cuestionario'],
                        'puntuacion_final': resultado['puntuacion_final'],
                        'fecha_partida': resultado['fecha_realizacion'],
                        'nombre_grupo': None,
                        'tipo': 'individual'
                    })

                print(f"   ✅ Partidas individuales: {len(partidas_individuales)}")

        except Exception as e:
            print(f"   ⚠️ No se pudo cargar historial individual: {e}")
        finally:
            if conexion and conexion.open:
                conexion.close()
    except Exception as e:
        print(f"   ❌ Error en conexión individual: {e}")

    # 2.3 Combinar ambos historiales
    try:
        cuestionarios_recientes = partidas_grupales + partidas_individuales

        # Ordenar por fecha (manejar ambos tipos de fecha)
        if cuestionarios_recientes:
            cuestionarios_recientes.sort(
                key=lambda x: x.get('fecha_partida', datetime.min),
                reverse=True
            )
            cuestionarios_recientes = cuestionarios_recientes[:5]

        print(f"   ✅ Total partidas combinadas: {len(cuestionarios_recientes)}")

    except Exception as e:
        print(f"   ⚠️ Error al combinar historiales: {e}")
        cuestionarios_recientes = []

    # === BLOQUE 3: Stats y Items ===
    print(f"\n📊 Cargando estadísticas del estudiante...")
    stats = None
    try:
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # ✅ TRAER TODAS LAS COLUMNAS DE STATS
                cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
                stats = cursor.fetchone()

                if not stats:
                    print(f"⚠️ No hay stats para user_id={user_id}. Inicializando...")
                    inicializar_stats_estudiante(user_id)
                    cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
                    stats = cursor.fetchone()

                # Debug: Imprimir stats cargadas
                if stats:
                    print(f"   ✅ Stats cargadas correctamente:")
                    print(f"      - Nivel: {stats.get('nivel', 0)}")
                    print(f"      - Monedas: {stats.get('monedas', 0)}")
                    print(f"      - Total Partidas: {stats.get('total_partidas', 0)}")
                    print(f"      - Preguntas Correctas: {stats.get('total_preguntas_correctas', 0)}")
                    print(f"      - Racha Actual: {stats.get('racha_actual', 0)}")
                    print(f"      - Mejor Puntaje: {stats.get('mejor_puntaje', 0)}")
                else:
                    print(f"   ⚠️ Stats es None después de inicializar")

        finally:
            if conexion and conexion.open:
                conexion.close()
    except Exception as e:
        print(f"❌ Error al cargar stats: {e}")
        import traceback
        traceback.print_exc()
        # Valores por defecto si falla todo
        stats = {
            'nivel': 1,
            'monedas': 0,
            'total_partidas': 0,
            'total_preguntas_correctas': 0,
            'total_preguntas_incorrectas': 0,
            'racha_actual': 0,
            'mejor_racha': 0,
            'mejor_puntaje': 0,
            'experiencia_actual': 0,
            'experiencia_total': 0
        }

    # Cargar items equipados
    print(f"\n🎨 Cargando items equipados...")
    try:
        items_equipados = obtener_items_equipados(user_id)
        print(f"   ✅ Items equipados: {items_equipados}")
    except Exception as e:
        print(f"   ⚠️ Error al cargar items: {e}")
        items_equipados = {'avatar': None, 'marco': None, 'titulo': None}

    # === RENDERIZAR ===
    print(f"\n✅ Dashboard cargado exitosamente")
    print(f"   - Grupo: {'Sí' if grupo_info else 'No'}")
    print(f"   - Miembros: {len(miembros)}")
    print(f"   - Historial: {len(cuestionarios_recientes)}")
    print(f"   - Stats: {'Cargadas' if stats else 'Por defecto'}")
    print(f"{'='*70}\n")

    return render_template("dashboard_estudiante.html",
                           nombre=session["usuario"],
                           grupo=grupo_info,
                           miembros=miembros,
                           user_id=user_id,
                           cuestionarios_recientes=cuestionarios_recientes,
                           items_equipados=items_equipados,
                           stats=stats)


@app.route("/crear_grupo", methods=["POST"])
def crear_grupo():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    nombre_grupo = request.form.get("nombre_grupo")
    user_id = session["user_id"]

    if not nombre_grupo:
        flash("❌ Debes darle un nombre a tu grupo.", "error")
        return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")  # ✅ AGREGADO

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Verificar si el usuario ya está en un grupo
            cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
            usuario = cursor.fetchone()

            if usuario and usuario.get('grupo_id'):
                flash("❌ Ya perteneces a un grupo.", "error")
                return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")  # ✅ AGREGADO

            # Generar código único
            codigo_grupo = generar_codigo_grupo()

            # Insertar grupo
            cursor.execute("""
                INSERT INTO grupos (nombre_grupo, codigo_grupo, lider_id)
                VALUES (%s, %s, %s)
            """, (nombre_grupo, codigo_grupo, user_id))
            conexion.commit()
            nuevo_grupo_id = cursor.lastrowid

            # Actualizar usuario con el grupo
            cursor.execute("""
                UPDATE usuarios SET grupo_id = %s WHERE id = %s
            """, (nuevo_grupo_id, user_id))
            conexion.commit()

            flash(f"✅ ¡Grupo '{nombre_grupo}' creado con éxito!", "success")

    except Exception as e:
        flash(f"❌ Error al crear el grupo: {str(e)}", "error")
        print(f"Error en /crear_grupo: {e}")
        import traceback
        traceback.print_exc()

    finally:
        if conexion and conexion.open:
            conexion.close()

    return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")  # ✅ AGREGADO


@app.route("/unirse_grupo", methods=["POST"])
def unirse_grupo():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    codigo_grupo, user_id = request.form.get("codigo_grupo"), session["user_id"]

    if not codigo_grupo:
        flash("❌ Debes ingresar un código de grupo.", "error")
        return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")  # ✅ AGREGADO

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
            if cursor.fetchone().get('grupo_id'):
                flash("❌ Ya perteneces a un grupo.", "error")
                return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")  # ✅ AGREGADO

            cursor.execute("SELECT id FROM grupos WHERE codigo_grupo = %s", (codigo_grupo,))
            if not (grupo := cursor.fetchone()):
                flash("❌ No se encontró ningún grupo con ese código.", "error")
                return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")  # ✅ AGREGADO

            cursor.execute("UPDATE usuarios SET grupo_id = %s WHERE id = %s", (grupo['id'], user_id))
            conexion.commit()
            flash("✅ Te has unido al grupo exitosamente.", "success")
    except Exception as e:
        flash("❌ Ocurrió un error al unirte al grupo.", "error")
        print(f"Error en /unirse_grupo: {e}")
    finally:
        if conexion and conexion.open:
            conexion.close()

    return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")  # ✅ AGREGADO


@app.route("/salir_grupo")
def salir_grupo():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT g.id, g.lider_id FROM grupos g JOIN usuarios u ON g.id = u.grupo_id WHERE u.id = %s", (user_id,))
            if not (grupo := cursor.fetchone()):
                flash("❌ No perteneces a ningún grupo.", "error")
                return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")  # ✅ AGREGADO

            if grupo['lider_id'] == user_id:
                grupo_id = grupo['id']
                cursor.execute("UPDATE usuarios SET grupo_id = NULL WHERE grupo_id = %s", (grupo_id,))
                cursor.execute("DELETE FROM grupos WHERE id = %s", (grupo_id,))
                flash("✅ Has salido y el grupo se ha disuelto.", "success")
            else:
                cursor.execute("UPDATE usuarios SET grupo_id = NULL WHERE id = %s", (user_id,))
                flash("✅ Has salido del grupo.", "success")
            conexion.commit()
    except Exception as e:
        flash("❌ Ocurrió un error al salir del grupo.", "error")
        print(f"Error en /salir_grupo: {e}")
    finally:
        if conexion and conexion.open:
            conexion.close()

    return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")  # ✅ AGREGADO

@app.route("/juego_grupo", methods=["POST"])
def juego_grupo():
    """Maneja el inicio (Líder) o la unión (Miembro) a un juego grupal."""
    print(f"\n{'='*70}")
    print(f"🎮 INICIANDO/UNIÉNDOSE A JUEGO GRUPAL")
    print(f"{'='*70}")

    if "usuario" not in session or session.get("rol") != "estudiante":
        print("❌ No autorizado")
        return redirect(url_for("login"))

    pin = request.form.get("pin")
    user_id = session["user_id"]

    print(f"👤 Usuario ID: {user_id}")
    print(f"📌 PIN recibido: {pin}")

    if not pin:
        flash("❌ Debes ingresar un código PIN.", "error")
        return redirect(url_for("dashboard_estudiante"))

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Verificar que el usuario está en un grupo
            cursor.execute("""
                SELECT g.id, g.lider_id, g.nombre_grupo, g.codigo_grupo
                FROM grupos g
                JOIN usuarios u ON g.id = u.grupo_id
                WHERE u.id = %s
            """, (user_id,))
            grupo = cursor.fetchone()

            if not grupo:
                print(f"❌ Usuario no pertenece a ningún grupo")
                flash("❌ Debes estar en un grupo para jugar en modo grupal.", "error")
                return redirect(url_for('dashboard_estudiante'))

            print(f"✅ Grupo encontrado: {grupo['nombre_grupo']} (ID: {grupo['id']})")

            # 2. VALIDACIÓN CRÍTICA: Verificar que el cuestionario existe y es GRUPAL
            cursor.execute("""
                SELECT id, titulo, modo_juego
                FROM cuestionarios
                WHERE codigo_pin = %s
            """, (pin,))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                print(f"❌ No se encontró cuestionario con PIN: {pin}")
                flash(f"❌ No se encontró ningún cuestionario con el PIN '{pin}'.", "error")
                return redirect(url_for('dashboard_estudiante'))

            if cuestionario['modo_juego'] != 'grupal':
                print(f"❌ Cuestionario NO es grupal (modo: {cuestionario['modo_juego']})")
                flash(f"❌ El cuestionario '{cuestionario['titulo']}' está configurado para juego INDIVIDUAL.", "error")
                return redirect(url_for('dashboard_estudiante'))

            print(f"✅ Cuestionario validado: {cuestionario['titulo']} (Grupal)")

            # 3. LÓGICA UNIFICADA: Actualizar el grupo (solo el líder puede hacerlo)
            es_lider = (grupo['lider_id'] == user_id)

            if es_lider:
                print(f"👑 Usuario es el líder. Actualizando grupo...")

                # Solo el líder actualiza el active_pin y estado
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
                print(f"✅ Grupo actualizado por el líder")
            else:
                print(f"👤 Usuario es miembro (no líder)")

            # 4. REDIRECCIÓN PARA TODOS (líder y miembros)
            print(f"✅ Redirigiendo a sala de espera: /sala_espera/{grupo['id']}")
            return redirect(url_for('sala_espera_grupo', grupo_id=grupo['id']))

    except Exception as e:
        print(f"\n❌❌❌ ERROR EN JUEGO_GRUPO ❌❌❌")
        print(f"Mensaje: {str(e)}")
        import traceback
        traceback.print_exc()
        print(f"{'='*70}\n")
        flash(f"❌ Error al iniciar el juego grupal: {str(e)}", "error")
        return redirect(url_for('dashboard_estudiante'))

    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/profesor_vista_juego_grupal/<codigo_pin>")
def profesor_vista_juego_grupal(codigo_pin):
    """Vista en vivo del profesor durante el juego grupal"""
    print(f"\n{'='*70}")
    print(f"📺 PROFESOR VISTA JUEGO GRUPAL - PIN: {codigo_pin}")
    print(f"{'='*70}")

    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Obtener cuestionario
            cursor.execute("""
                SELECT * FROM cuestionarios
                WHERE codigo_pin = %s AND profesor_id = %s
            """, (codigo_pin, session["user_id"]))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                flash("❌ Cuestionario no encontrado", "error")
                return redirect(url_for("dashboard_profesor"))

            # Obtener preguntas
            cursor.execute("""
                SELECT id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta
                FROM preguntas
                WHERE cuestionario_id = %s
                ORDER BY orden
            """, (cuestionario['id'],))
            preguntas = cursor.fetchall()

            # Obtener grupos activos para este cuestionario
            cursor.execute("""
                SELECT id, nombre_grupo
                FROM grupos
                WHERE active_pin = %s AND game_state IN ('waiting', 'playing')
            """, (codigo_pin,))
            grupos = cursor.fetchall()

            grupos_ids = [g['id'] for g in grupos]
            total_grupos = len(grupos_ids)

            print(f"✅ Total grupos activos: {total_grupos}")
            print(f"✅ Total preguntas: {len(preguntas)}")

            return render_template("profesor_vista_juego_grupal.html",
                                   cuestionario=cuestionario,
                                   preguntas=preguntas,
                                   grupos_ids=grupos_ids,
                                   total_grupos=total_grupos)

    except Exception as e:
        print(f"❌ Error en profesor_vista_juego_grupal: {e}")
        import traceback
        traceback.print_exc()
        flash("❌ Error al cargar la vista del juego", "error")
        return redirect(url_for("dashboard_profesor"))
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/miembros_grupo/<int:grupo_id>")
def api_miembros_grupo(grupo_id):
    """Obtiene los miembros de un grupo en tiempo real"""
    if "usuario" not in session:
        return jsonify({"error": "No autenticado"}), 403

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Verificar que el grupo existe
            cursor.execute("SELECT lider_id FROM grupos WHERE id = %s", (grupo_id,))
            grupo = cursor.fetchone()

            if not grupo:
                return jsonify({"error": "Grupo no encontrado"}), 404

            # Obtener miembros del grupo
            cursor.execute("""
                SELECT id, nombre
                FROM usuarios
                WHERE grupo_id = %s
                ORDER BY id
            """, (grupo_id,))

            miembros = cursor.fetchall()

            return jsonify({
                "miembros": miembros,
                "lider_id": grupo['lider_id'],
                "total": len(miembros)
            })

    except Exception as e:
        print(f"Error en api_miembros_grupo: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/sala_profesor/<codigo_pin>")
def sala_profesor(codigo_pin):
    """Sala donde el profesor ve los grupos esperando y puede iniciar la partida"""
    print(f"\n{'='*70}")
    print(f"🎮 SALA PROFESOR GRUPAL - PIN: {codigo_pin}")
    print(f"{'='*70}")

    if "usuario" not in session or session.get("rol") != "profesor":
        print("❌ No autorizado")
        return redirect(url_for("login"))

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Obtener información del cuestionario
            cursor.execute("""
                SELECT * FROM cuestionarios
                WHERE codigo_pin = %s AND profesor_id = %s
            """, (codigo_pin, session["user_id"]))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                print(f"❌ Cuestionario no encontrado para PIN: {codigo_pin}")
                flash("❌ Cuestionario no encontrado", "error")
                return redirect(url_for("dashboard_profesor"))

            print(f"✅ Cuestionario: {cuestionario['titulo']}")
            print(f"   Modo: {cuestionario['modo_juego']}")

            # 2. VALIDAR QUE SEA MODO GRUPAL
            if cuestionario['modo_juego'] != 'grupal':
                print(f"❌ Cuestionario es modo {cuestionario['modo_juego']}, no grupal")
                flash(f"❌ Este cuestionario está configurado para modo {cuestionario['modo_juego'].upper()}. Usa la sala correspondiente.", "error")
                return redirect(url_for("dashboard_profesor"))

            # 3. Obtener grupos que están esperando para jugar este cuestionario
            cursor.execute("""
                SELECT
                    g.id,
                    g.nombre_grupo,
                    g.game_state,
                    g.lider_id,
                    COUNT(u.id) as num_miembros
                FROM grupos g
                LEFT JOIN usuarios u ON g.id = u.grupo_id
                WHERE g.active_pin = %s
                GROUP BY g.id, g.nombre_grupo, g.game_state, g.lider_id
                ORDER BY g.fecha_creacion DESC
            """, (codigo_pin,))
            grupos_esperando = cursor.fetchall()

            print(f"✅ Grupos esperando: {len(grupos_esperando)}")

            # 4. Para cada grupo, obtener los nombres de los miembros
            for grupo in grupos_esperando:
                cursor.execute("""
                    SELECT nombre FROM usuarios
                    WHERE grupo_id = %s
                    ORDER BY id
                """, (grupo['id'],))
                miembros = cursor.fetchall()
                grupo['miembros'] = ', '.join([m['nombre'] for m in miembros]) if miembros else 'Sin miembros'
                print(f"   - Grupo: {grupo['nombre_grupo']} ({grupo['num_miembros']} miembros)")

            print(f"{'='*70}\n")

            return render_template("sala_profesor.html",
                                   cuestionario=cuestionario,
                                   grupos_esperando=grupos_esperando)

    except Exception as e:
        print(f"\n❌❌❌ ERROR EN SALA_PROFESOR ❌❌❌")
        print(f"Tipo: {type(e).__name__}")
        print(f"Mensaje: {str(e)}")
        import traceback
        traceback.print_exc()
        print(f"{'='*70}\n")

        flash(f"❌ Error al cargar la sala: {str(e)}", "error")
        return redirect(url_for("dashboard_profesor"))

    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/profesor_vista_juego/<codigo_pin>")
def profesor_vista_juego(codigo_pin):
    """Vista en vivo del profesor durante el juego individual"""
    print(f"\n{'='*70}")
    print(f"📺 PROFESOR VISTA JUEGO - PIN: {codigo_pin}")
    print(f"{'='*70}")

    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Obtener cuestionario
            cursor.execute("""
                SELECT * FROM cuestionarios
                WHERE codigo_pin = %s AND profesor_id = %s
            """, (codigo_pin, session["user_id"]))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                flash("❌ Cuestionario no encontrado", "error")
                return redirect(url_for("dashboard_profesor"))

            # Obtener preguntas
            cursor.execute("""
                SELECT id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta
                FROM preguntas
                WHERE cuestionario_id = %s
                ORDER BY orden
            """, (cuestionario['id'],))
            preguntas = cursor.fetchall()

            # Obtener sesión activa
            cursor.execute("""
                SELECT DISTINCT sesion_id
                FROM salas_espera
                WHERE codigo_pin = %s AND estado = 'playing'
                LIMIT 1
            """, (codigo_pin,))
            sesion_data = cursor.fetchone()

            if not sesion_data:
                flash("⚠️ No hay ninguna sesión activa para este cuestionario", "warning")
                return redirect(url_for("sala_profesor_individual", codigo_pin=codigo_pin))

            sesion_id = sesion_data['sesion_id']

            # Contar estudiantes en esta sesión
            cursor.execute("""
                SELECT COUNT(*) as total
                FROM salas_espera
                WHERE sesion_id = %s
            """, (sesion_id,))
            total_estudiantes = cursor.fetchone()['total']

            print(f"✅ Sesión ID: {sesion_id}")
            print(f"✅ Total estudiantes: {total_estudiantes}")
            print(f"✅ Total preguntas: {len(preguntas)}")

            return render_template("profesor_vista_juego_individual.html",
                                   cuestionario=cuestionario,
                                   preguntas=preguntas,
                                   sesion_id=sesion_id,
                                   total_estudiantes=total_estudiantes)

    except Exception as e:
        print(f"❌ Error en profesor_vista_juego: {e}")
        import traceback
        traceback.print_exc()
        flash("❌ Error al cargar la vista del juego", "error")
        return redirect(url_for("dashboard_profesor"))
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/api/estudiantes_en_sesion/<sesion_id>")
def api_estudiantes_en_sesion(sesion_id):
    """API para obtener estudiantes en tiempo real durante una sesión"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Obtener estudiantes de esta sesión
            cursor.execute("""
                SELECT
                    u.id,
                    u.nombre,
                    se.estado,
                    COALESCE(
                        (SELECT COUNT(DISTINCT r.pregunta_id)
                         FROM respuestas_individuales r
                         JOIN historial_individual h ON r.historial_id = h.id
                         WHERE h.usuario_id = u.id AND h.sesion_id = %s),
                        0
                    ) as pregunta_actual
                FROM salas_espera se
                JOIN usuarios u ON se.usuario_id = u.id
                WHERE se.sesion_id = %s
                ORDER BY u.nombre
            """, (sesion_id, sesion_id))

            estudiantes = cursor.fetchall()

            return jsonify({
                "success": True,
                "estudiantes": estudiantes
            })

    except Exception as e:
        print(f"❌ Error en api_estudiantes_en_sesion: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/ranking_final_sesion/<sesion_id>")
def api_ranking_final_sesion(sesion_id):
    """API para obtener el ranking final de una sesión"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Obtener ranking de esta sesión
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

            return jsonify({
                "success": True,
                "ranking": ranking
            })

    except Exception as e:
        print(f"❌ Error en api_ranking_final_sesion: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/profesor_iniciar_partidas/<codigo_pin>", methods=["POST"])
def profesor_iniciar_partidas(codigo_pin):
    """El profesor inicia todas las partidas grupales desde su dashboard"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Verificar que el cuestionario pertenece al profesor
            cursor.execute("""
                SELECT id FROM cuestionarios
                WHERE codigo_pin = %s AND profesor_id = %s
            """, (codigo_pin, session["user_id"]))

            if not cursor.fetchone():
                return jsonify({"success": False, "message": "Cuestionario no encontrado"}), 404

            # Iniciar todas las partidas de grupos en espera
            cursor.execute("""
                UPDATE grupos
                SET game_state = 'playing',
                    current_question_index = 0,
                    current_score = 0
                WHERE active_pin = %s AND game_state = 'waiting'
            """, (codigo_pin,))

            grupos_iniciados = cursor.rowcount
            conexion.commit()

            print(f"✅ Profesor inició {grupos_iniciados} partida(s) grupal(es) - PIN: {codigo_pin}")

            return jsonify({
                "success": True,
                "message": f"Se iniciaron {grupos_iniciados} partida(s)",
                "grupos_iniciados": grupos_iniciados
            })

    except Exception as e:
        print(f"❌ Error al iniciar partidas: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/api/grupos_esperando/<codigo_pin>")
def api_grupos_esperando(codigo_pin):
    """Obtiene la lista de grupos esperando en tiempo real"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"error": "No autorizado"}), 403

    conexion = obtener_conexion()
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
            return jsonify(grupos)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/sala_espera/<int:grupo_id>")
def sala_espera_grupo(grupo_id):
    """Sala de espera para el grupo antes de que inicie la partida"""
    print(f"\n{'='*70}")
    print(f"⏳ CARGANDO SALA DE ESPERA")
    print(f"📋 Grupo ID: {grupo_id}")
    print(f"{'='*70}")

    if "usuario" not in session:
        print("❌ No hay sesión")
        return redirect(url_for('login'))

    user_id = session["user_id"]
    print(f"👤 Usuario ID: {user_id}")

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Obtener información del grupo
            cursor.execute("""
                SELECT * FROM grupos WHERE id = %s
            """, (grupo_id,))
            grupo = cursor.fetchone()

            if not grupo:
                print(f"❌ Grupo {grupo_id} no encontrado")
                flash("❌ Grupo no encontrado", "error")
                return redirect(url_for('dashboard_estudiante'))

            print(f"✅ Grupo: {grupo['nombre_grupo']}")
            print(f"   Estado: {grupo['game_state']}")
            print(f"   PIN activo: {grupo.get('active_pin', 'N/A')}")

            # Obtener miembros del grupo
            cursor.execute("""
                SELECT id, nombre
                FROM usuarios
                WHERE grupo_id = %s
                ORDER BY id
            """, (grupo_id,))
            miembros = cursor.fetchall()

            print(f"✅ Miembros: {len(miembros)}")
            for miembro in miembros:
                lider_icon = "👑" if miembro['id'] == grupo['lider_id'] else "👤"
                print(f"   {lider_icon} {miembro['nombre']}")

            # Verificar que el usuario pertenece al grupo
            es_miembro = any(m['id'] == user_id for m in miembros)
            if not es_miembro:
                print(f"❌ Usuario {user_id} no pertenece al grupo")
                flash("❌ No perteneces a este grupo", "error")
                return redirect(url_for('dashboard_estudiante'))

            print(f"\n✅ Renderizando sala de espera")
            print(f"{'='*70}\n")

            return render_template('sala_espera_grupo.html',
                                   grupo=grupo,
                                   miembros=miembros,
                                   user_id=user_id)

    except Exception as e:
        print(f"\n❌❌❌ ERROR EN SALA_ESPERA_GRUPO ❌❌❌")
        print(f"Tipo: {type(e).__name__}")
        print(f"Mensaje: {str(e)}")
        import traceback
        traceback.print_exc()
        print(f"{'='*70}\n")

        flash("❌ Error al cargar la sala de espera", "error")
        return redirect(url_for('dashboard_estudiante'))

    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/iniciar_partida_grupal/<int:grupo_id>", methods=["POST"])
def iniciar_partida_grupal(grupo_id):
    """El líder inicia oficialmente la partida desde la sala de espera"""
    if "usuario" not in session:
        return jsonify({"success": False, "message": "No autenticado"}), 403

    user_id = session['user_id']
    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT lider_id, active_pin FROM grupos WHERE id = %s", (grupo_id,))
            grupo = cursor.fetchone()

            if not grupo:
                return jsonify({"success": False, "message": "Grupo no encontrado"}), 404

            if grupo['lider_id'] != user_id:
                return jsonify({"success": False, "message": "Solo el líder puede iniciar"}), 403

            if not grupo['active_pin']:
                return jsonify({"success": False, "message": "No hay cuestionario asignado"}), 400

            cursor.execute("""
                UPDATE grupos
                SET game_state = 'playing',
                    current_question_index = 0,
                    current_score = 0
                WHERE id = %s
            """, (grupo_id,))
            conexion.commit()

            print(f"✅ Partida iniciada - Grupo ID: {grupo_id}, Estado: playing")

            return jsonify({"success": True})

    except Exception as e:
        print(f"❌ Error en iniciar_partida_grupal: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/partida_grupal/<int:grupo_id>")
def partida_grupal(grupo_id):
    if "usuario" not in session: return redirect(url_for('login'))
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM grupos WHERE id = %s", (grupo_id,))
            grupo = cursor.fetchone()
            cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s", (grupo['active_pin'],))
            cuestionario = cursor.fetchone()
    finally:
        if conexion and conexion.open: conexion.close()

    return render_template("partida_grupal.html", grupo=grupo, cuestionario=cuestionario, user_id=session['user_id'])

@app.route("/resultados_grupo/<int:grupo_id>")
def resultados_grupo(grupo_id):
    """Muestra la página de resultados y guarda en el historial."""
    if "usuario" not in session:
        return redirect(url_for('login'))

    user_id = session.get("user_id")
    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            # 1. Obtener información del grupo
            cursor.execute("SELECT * FROM grupos WHERE id = %s", (grupo_id,))
            grupo = cursor.fetchone()

            # 2. Verificar que el usuario pertenece al grupo
            if grupo:
                cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
                usuario = cursor.fetchone()
                if not usuario or usuario['grupo_id'] != grupo_id:
                    flash("❌ No perteneces a este grupo", "error")
                    return redirect(url_for('dashboard_estudiante'))

            # 3. Obtener información del cuestionario (usando el active_pin si existe)
            cuestionario = None
            if grupo and grupo['active_pin']:
                cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s", (grupo['active_pin'],))
                cuestionario = cursor.fetchone()

            # 4. Obtener miembros (para mostrar en la tarjeta de resultados)
            cursor.execute("SELECT id, nombre FROM usuarios WHERE grupo_id = %s", (grupo_id,))
            miembros = cursor.fetchall()

            # 5. Si el juego acaba de terminar ('finished'), guardarlo en el historial
            if cuestionario and grupo and grupo.get('game_state') == 'finished':

                # Guardar en la tabla historial_partidas
                cursor.execute("""
                    INSERT INTO historial_partidas
                    (grupo_id, cuestionario_id, nombre_grupo, titulo_cuestionario, puntuacion_final, num_preguntas_total, num_miembros)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (grupo_id, cuestionario['id'], grupo['nombre_grupo'], cuestionario['titulo'],
                      grupo['current_score'], cuestionario['num_preguntas'], len(miembros)))

                partida_id = cursor.lastrowid

                # Guardar a los participantes en la tabla participantes_partida
                for miembro in miembros:
                    cursor.execute("""
                        INSERT INTO participantes_partida (partida_id, usuario_id, nombre_usuario)
                        VALUES (%s, %s, %s)
                    """, (partida_id, miembro['id'], miembro['nombre']))

                # Limpiar estado del grupo para futuras partidas
                cursor.execute("""
                    UPDATE grupos
                    SET active_pin = NULL,
                        game_state = 'archived',
                        current_question_index = 0
                    WHERE id = %s
                """, (grupo_id,))

                conexion.commit()
                print(f"✅ Partida guardada en historial, ID: {partida_id}. Estado del grupo limpiado.")

            # 6. Si no hay cuestionario (porque el estado ya se limpió o se disolvió el grupo),
            #    intentar cargar los datos desde el último historial.
            elif not cuestionario:
                print(f"⚠️ No se encontró cuestionario por active_pin. Buscando en historial...")
                cursor.execute("""
                    SELECT h.*, c.titulo, c.descripcion, c.num_preguntas, c.tiempo_pregunta, c.modo_juego
                    FROM historial_partidas h
                    JOIN cuestionarios c ON h.cuestionario_id = c.id
                    JOIN participantes_partida p ON h.id = p.partida_id
                    WHERE p.usuario_id = %s AND h.grupo_id = %s
                    ORDER BY h.fecha_partida DESC
                    LIMIT 1
                """, (user_id, grupo_id)) # Asegurarnos que el usuario participó
                historial = cursor.fetchone()

                if historial:
                    # Si encontramos historial, lo usamos para mostrar los datos
                    cuestionario = {
                        'titulo': historial['titulo'],
                        'descripcion': historial['descripcion'],
                        'num_preguntas': historial['num_preguntas'],
                        'tiempo_pregunta': historial['tiempo_pregunta'],
                        'modo_juego': historial['modo_juego']
                    }
                    if not grupo: # Si el grupo ya no existe, rellenar info mínima
                        grupo = {'nombre_grupo': historial['nombre_grupo'], 'current_score': historial['puntuacion_final']}
                    else:
                        grupo['current_score'] = historial['puntuacion_final'] # Asegurarnos de mostrar el score final

                    # Cargar los miembros que JUGARON esa partida
                    cursor.execute("SELECT nombre_usuario FROM participantes_partida WHERE partida_id = %s", (historial['id'],))
                    miembros_historial = cursor.fetchall()
                    miembros = [{'nombre': m['nombre_usuario']} for m in miembros_historial] # Formatear para el template

                    print(f"✅ Mostrando resultados desde historial ID: {historial['id']}")
                else:
                    # Si no hay ni juego activo ni historial, no podemos mostrar nada
                    flash("❌ No se encontraron resultados de la partida", "error")
                    return redirect(url_for('dashboard_estudiante'))

            # Si el grupo existe pero los miembros no (porque ya salieron), rellenar desde historial
            if grupo and not miembros:
                cursor.execute("""
                    SELECT p.nombre_usuario
                    FROM participantes_partida p
                    JOIN historial_partidas h ON p.partida_id = h.id
                    WHERE h.grupo_id = %s
                    ORDER BY h.fecha_partida DESC
                """, (grupo_id,))
                miembros_historial = cursor.fetchall()
                if miembros_historial:
                     miembros = [{'nombre': m['nombre_usuario']} for m in miembros_historial] # Tomar el más reciente
                     miembros = list({v['nombre']:v for v in miembros}.values()) # Hacer únicos


    except Exception as e:
        print(f"❌ Error en /resultados_grupo: {e}")
        import traceback
        traceback.print_exc()
        flash("❌ Error al cargar los resultados.", "error")
        return redirect(url_for('dashboard_estudiante'))
    finally:
        if 'conexion' in locals() and conexion.open:
            conexion.close()

    return render_template("resultados_grupo.html",
                           grupo=grupo,
                           cuestionario=cuestionario,
                           miembros=miembros)


# --- RUTA PARA SALA PROFESOR INDIVIDUAL ---
@app.route("/sala_profesor_individual/<codigo_pin>")
def sala_profesor_individual(codigo_pin):
    """Sala donde el profesor ve los estudiantes esperando (modo individual)"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Obtener información del cuestionario
            cursor.execute("""
                SELECT * FROM cuestionarios
                WHERE codigo_pin = %s AND profesor_id = %s
            """, (codigo_pin, session["user_id"]))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                flash("❌ Cuestionario no encontrado", "error")
                return redirect(url_for("dashboard_profesor"))

            # Verificar que sea modo individual
            if cuestionario['modo_juego'] != 'individual':
                flash("❌ Este cuestionario es grupal, no individual", "error")
                return redirect(url_for("dashboard_profesor"))

            return render_template("sala_profesor_individual.html",
                                   cuestionario=cuestionario)
    finally:
        if conexion and conexion.open:
            conexion.close()


# --- API PARA OBTENER ESTUDIANTES ESPERANDO (INDIVIDUAL) ---
@app.route("/api/estudiantes_esperando/<codigo_pin>")
def api_estudiantes_esperando(codigo_pin):
    """Obtiene la lista de estudiantes esperando en tiempo real"""
    print(f"\n{'='*70}")
    print(f"📡 API LLAMADO: /api/estudiantes_esperando/{codigo_pin}")
    print(f"{'='*70}")

    if "usuario" not in session or session.get("rol") != "profesor":
        print("❌ Usuario no autorizado o no es profesor")
        return jsonify({"error": "No autorizado"}), 403

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            print(f"🔍 Consultando estudiantes para PIN: {codigo_pin}")

            # Obtener estudiantes que están esperando para este cuestionario
            cursor.execute("""
                SELECT u.id, u.nombre, se.estado, se.fecha_ingreso
                FROM salas_espera se
                JOIN usuarios u ON se.usuario_id = u.id
                WHERE se.codigo_pin = %s
                ORDER BY se.fecha_ingreso ASC
            """, (codigo_pin,))

            estudiantes = cursor.fetchall()

            print(f"✅ Estudiantes encontrados: {len(estudiantes)}")

            if len(estudiantes) > 0:
                print("📋 Lista de estudiantes:")
                for est in estudiantes:
                    print(f"   - ID: {est['id']}, Nombre: {est['nombre']}, Estado: {est['estado']}")

            # Formatear timestamp
            for est in estudiantes:
                if est['fecha_ingreso']:
                    try:
                        tiempo_transcurrido = datetime.now() - est['fecha_ingreso']
                        segundos = int(tiempo_transcurrido.total_seconds())
                        if segundos < 60:
                            est['timestamp'] = f'Hace {segundos}s'
                        elif segundos < 3600:
                            est['timestamp'] = f'Hace {segundos // 60}m'
                        else:
                            est['timestamp'] = est['fecha_ingreso'].strftime('%H:%M')
                    except Exception as e:
                        print(f"⚠️ Error al formatear timestamp: {e}")
                        est['timestamp'] = 'Ahora'

            print(f"🚀 Devolviendo {len(estudiantes)} estudiante(s)")
            print(f"{'='*70}\n")

            return jsonify(estudiantes)

    except Exception as e:
        print(f"\n❌❌❌ ERROR EN API ❌❌❌")
        print(f"Tipo: {type(e).__name__}")
        print(f"Mensaje: {str(e)}")
        import traceback
        traceback.print_exc()
        print(f"{'='*70}\n")

        return jsonify({"error": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# --- API PARA INICIAR PARTIDAS INDIVIDUALES ---
@app.route("/profesor_iniciar_individuales/<codigo_pin>", methods=["POST"])
def profesor_iniciar_individuales(codigo_pin):
    """El profesor inicia todas las partidas individuales"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Verificar que el cuestionario pertenece al profesor
            cursor.execute("""
                SELECT id FROM cuestionarios
                WHERE codigo_pin = %s AND profesor_id = %s
            """, (codigo_pin, session["user_id"]))

            if not cursor.fetchone():
                return jsonify({"success": False, "message": "Cuestionario no encontrado"}), 404

            # Generar ID de sesión único
            import uuid
            sesion_id = f"SESION_{codigo_pin}_{uuid.uuid4().hex[:8]}"

            # Guardar el sesion_id en la sala de espera
            cursor.execute("""
                UPDATE salas_espera
                SET estado = 'playing', sesion_id = %s
                WHERE codigo_pin = %s AND estado = 'waiting'
            """, (sesion_id, codigo_pin))

            estudiantes_iniciados = cursor.rowcount
            conexion.commit()

            print(f"✅ Sesión creada: {sesion_id}")
            print(f"✅ Profesor inició {estudiantes_iniciados} partida(s) individual(es) - PIN: {codigo_pin}")

            return jsonify({
                "success": True,
                "message": f"Se iniciaron {estudiantes_iniciados} partida(s)",
                "estudiantes_iniciados": estudiantes_iniciados,
                "sesion_id": sesion_id,
                "redirect_url": f"/profesor_vista_juego/{codigo_pin}"  # NUEVO: URL para redirección
            })

    except Exception as e:
        print(f"❌ Error al iniciar partidas individuales: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# --- API PARA CONSULTAR ESTADO DEL ESTUDIANTE INDIVIDUAL ---
@app.route("/api/estado_individual/<int:usuario_id>")
def api_estado_individual(usuario_id):
    """Devuelve el estado actual del estudiante en la sala de espera individual"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT estado, codigo_pin
                FROM salas_espera
                WHERE usuario_id = %s
            """, (usuario_id,))
            registro = cursor.fetchone()
            if not registro:
                return jsonify({"error": "No encontrado"}), 404
            return jsonify({
                "estado": registro['estado'],
                "codigo_pin": registro['codigo_pin']
            })
    except Exception as e:
        print(f"❌ Error en api_estado_individual: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# --- API PARA SALIR DE LA SALA DE ESPERA INDIVIDUAL ---
@app.route("/api/salir_sala_individual/<int:usuario_id>", methods=["POST"])
def api_salir_sala_individual(usuario_id):
    """Permite a un estudiante salir de la sala de espera individual"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    if session["user_id"] != usuario_id:
        return jsonify({"success": False, "message": "No autorizado"}), 403

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Eliminar al estudiante de la sala de espera
            cursor.execute("""
                DELETE FROM salas_espera
                WHERE usuario_id = %s
            """, (usuario_id,))
            conexion.commit()

            print(f"✅ Estudiante {usuario_id} salió de la sala de espera individual")

            return jsonify({
                "success": True,
                "message": "Has salido de la sala de espera"
            })

    except Exception as e:
        print(f"❌ Error al salir de sala individual: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


# --- RUTA PARA SALA DE ESPERA INDIVIDUAL ---
@app.route("/sala_espera_individual/<codigo_pin>")
def sala_espera_individual(codigo_pin):
    """Muestra la sala de espera para estudiantes en modo individual"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))
    user_id = session["user_id"]

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Verificar o insertar el registro del usuario en salas_espera
            cursor.execute("""
                SELECT * FROM salas_espera WHERE usuario_id = %s AND codigo_pin = %s
            """, (user_id, codigo_pin))
            registro = cursor.fetchone()
            if not registro:
                cursor.execute("""
                    INSERT INTO salas_espera (usuario_id, codigo_pin, estado, fecha_ingreso)
                    VALUES (%s, %s, 'waiting', NOW())
                """, (user_id, codigo_pin))
                conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

    return render_template("sala_espera_individual.html",
                           user_id=user_id,
                           codigo_pin=codigo_pin,
                           nombre_estudiante=session["usuario"])


# --- RUTA PARA PARTIDA INDIVIDUAL ---
@app.route("/partida_individual/<codigo_pin>")
def partida_individual(codigo_pin):
    """Carga el cuestionario individual cuando inicia la partida"""
    print("\n" + "="*70)
    print("🎮 INICIANDO PARTIDA INDIVIDUAL")
    print(f"📌 PIN recibido: {codigo_pin}")
    print("="*70)

    if "usuario" not in session or session.get("rol") != "estudiante":
        print("❌ Usuario no autorizado o no es estudiante")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    nombre_estudiante = session["usuario"]
    print(f"👤 Usuario: {nombre_estudiante} (ID: {user_id})")

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            print("\n📊 Consultando base de datos...")

            # OBTENER SESION_ID DE LA SALA DE ESPERA
            cursor.execute("""
                SELECT sesion_id FROM salas_espera
                WHERE usuario_id = %s AND codigo_pin = %s
            """, (user_id, codigo_pin))
            sala_data = cursor.fetchone()

            sesion_id = sala_data['sesion_id'] if sala_data else None
            print(f"🎯 Sesión ID: {sesion_id}")

            # Obtener cuestionario
            cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s", (codigo_pin,))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                print(f"   ❌ NO se encontró cuestionario con PIN: {codigo_pin}")
                flash("❌ Cuestionario no encontrado. Verifica el código PIN.", "error")
                return redirect(url_for("dashboard_estudiante"))

            print(f"   ✅ Cuestionario encontrado: {cuestionario['titulo']}")

            # Obtener preguntas
            cursor.execute("""
                SELECT * FROM preguntas
                WHERE cuestionario_id = %s
                ORDER BY orden
            """, (cuestionario['id'],))
            preguntas = cursor.fetchall()

            print(f"   ✅ Preguntas encontradas: {len(preguntas)}")

            if not preguntas:
                print(f"   ❌ NO hay preguntas para este cuestionario")
                flash("❌ Este cuestionario no tiene preguntas disponibles", "error")
                return redirect(url_for("dashboard_estudiante"))

            # CREAR HISTORIAL INDIVIDUAL CON SESION_ID
            print(f"\n💾 Creando historial individual con sesion_id...")
            cursor.execute("""
                INSERT INTO historial_individual
                (usuario_id, cuestionario_id, nombre_estudiante, num_preguntas_total, fecha_realizacion, puntuacion_final, sesion_id)
                VALUES (%s, %s, %s, %s, NOW(), 0, %s)
            """, (user_id, cuestionario['id'], nombre_estudiante, cuestionario['num_preguntas'], sesion_id))
            conexion.commit()
            historial_id = cursor.lastrowid

            # Guardar en sesión
            session['historial_individual_id'] = historial_id
            print(f"   ✅ Historial creado con ID: {historial_id}, Sesión: {sesion_id}")

            print(f"\n✅ Configuración completa!")

    except Exception as e:
        print(f"\n❌❌❌ ERROR EN PARTIDA_INDIVIDUAL ❌❌❌")
        print(f"Tipo de error: {type(e).__name__}")
        print(f"Mensaje: {str(e)}")
        import traceback
        traceback.print_exc()

        flash(f"Error al cargar el cuestionario: {str(e)}", "error")
        return redirect(url_for("dashboard_estudiante"))
    finally:
        if conexion and conexion.open:
            conexion.close()

    # Renderizar
    return render_template("juego_individual.html",
                           cuestionario=cuestionario,
                           preguntas=preguntas,
                           nombre_estudiante=nombre_estudiante,
                           sesion_id=sesion_id)


# --- RUTA PARA UNIRSE A UN CUESTIONARIO INDIVIDUAL ---
@app.route("/unirse_individual", methods=["POST"])
def unirse_individual():
    """El estudiante se une a un cuestionario individual usando el código PIN"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    codigo_pin = request.form.get("codigo_pin")
    user_id = session["user_id"]

    if not codigo_pin:
        flash("❌ Debes ingresar un código PIN", "error")
        return redirect(url_for("dashboard_estudiante"))

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Verificar que el cuestionario exista y sea modo individual
            cursor.execute("""
                SELECT id, modo_juego, profesor_id
                FROM cuestionarios
                WHERE codigo_pin = %s
            """, (codigo_pin,))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                flash("❌ Código PIN no válido", "error")
                return redirect(url_for("dashboard_estudiante"))

            if cuestionario["modo_juego"] != "individual":
                flash("⚠️ Este PIN no corresponde a un cuestionario individual", "warning")
                return redirect(url_for("dashboard_estudiante"))

            # Registrar o actualizar al estudiante en la sala de espera
            cursor.execute("""
                SELECT * FROM salas_espera
                WHERE usuario_id = %s AND codigo_pin = %s
            """, (user_id, codigo_pin))
            registro = cursor.fetchone()

            if not registro:
                cursor.execute("""
                    INSERT INTO salas_espera (usuario_id, codigo_pin, estado, fecha_ingreso)
                    VALUES (%s, %s, 'waiting', NOW())
                """, (user_id, codigo_pin))
            else:
                cursor.execute("""
                    UPDATE salas_espera
                    SET estado = 'waiting', fecha_ingreso = NOW()
                    WHERE usuario_id = %s AND codigo_pin = %s
                """, (user_id, codigo_pin))

            conexion.commit()

        # ✅ Redirigir a la sala de espera individual
        return redirect(url_for("sala_espera_individual", codigo_pin=codigo_pin))

    except Exception as e:
        print(f"❌ Error al unirse a cuestionario individual: {e}")
        flash("Error al intentar unirse al cuestionario", "error")
        return redirect(url_for("dashboard_estudiante"))
    finally:
        if conexion and conexion.open:
            conexion.close()



# --- API INTERNA PARA JUEGO EN TIEMPO REAL ---

@app.route("/api/estado_grupo/<int:grupo_id>")
def api_estado_grupo(grupo_id):
    """Obtiene el estado actual del grupo"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT game_state, active_pin, current_question_index, current_score
                FROM grupos
                WHERE id = %s
            """, (grupo_id,))
            estado = cursor.fetchone()

            if not estado:
                return jsonify(None), 404

            return jsonify({
                'game_state': estado['game_state'],
                'active_pin': estado['active_pin'],
                'current_question_index': estado['current_question_index'],
                'current_score': estado['current_score']
            })
    except Exception as e:
        print(f"❌ Error en api_estado_grupo: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/api/get_pregunta/<int:grupo_id>")
def api_get_pregunta(grupo_id):
    """Obtiene la pregunta actual del juego grupal"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT g.active_pin, g.current_question_index, g.current_score, g.game_state
                FROM grupos g
                WHERE g.id = %s
            """, (grupo_id,))
            juego = cursor.fetchone()

            if not juego or not juego['active_pin']:
                return jsonify({"error": "No hay juego activo"}), 404

            cursor.execute("""
                SELECT id, num_preguntas, tiempo_pregunta
                FROM cuestionarios
                WHERE codigo_pin = %s
            """, (juego['active_pin'],))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                return jsonify({"error": "Cuestionario no encontrado"}), 404

            if juego['current_question_index'] >= cuestionario['num_preguntas']:
                return jsonify({
                    "finished": True,
                    "score": juego['current_score']
                })

            cursor.execute("""
                SELECT id, pregunta, opcion_a, opcion_b, opcion_c, opcion_d
                FROM preguntas
                WHERE cuestionario_id = %s
                ORDER BY orden
                LIMIT 1 OFFSET %s
            """, (cuestionario['id'], juego['current_question_index']))

            pregunta = cursor.fetchone()

            if not pregunta:
                return jsonify({"error": "Pregunta no encontrada"}), 404

            return jsonify({
                "pregunta": pregunta,
                "index": juego['current_question_index'],
                "total": cuestionario['num_preguntas'],
                "score": juego['current_score'],
                "tiempo_pregunta": cuestionario['tiempo_pregunta'],
                "game_state": juego['game_state'],
                "finished": False
            })

    except Exception as e:
        print(f"Error en api_get_pregunta: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Error del servidor: {str(e)}"}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/get_ultima_respuesta/<int:grupo_id>")
def api_get_ultima_respuesta(grupo_id):
    """Obtiene el resultado de la última respuesta del líder"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT g.current_question_index, g.current_score, g.game_state,
                       g.ultima_respuesta_correcta, c.id as cuestionario_id
                FROM grupos g
                JOIN cuestionarios c ON g.active_pin = c.codigo_pin
                WHERE g.id = %s
            """, (grupo_id,))
            juego = cursor.fetchone()

            if not juego:
                return jsonify({"error": "Juego no encontrado"}), 404

            # Si el estado es 'answered', obtener la respuesta de la pregunta ANTERIOR
            if juego['game_state'] == 'answered' and juego['current_question_index'] > 0:
                pregunta_index = juego['current_question_index'] - 1

                cursor.execute("""
                    SELECT respuesta_correcta
                    FROM preguntas
                    WHERE cuestionario_id = %s
                    ORDER BY orden
                    LIMIT 1 OFFSET %s
                """, (juego['cuestionario_id'], pregunta_index))

                pregunta = cursor.fetchone()

                if pregunta:
                    # Obtener si la última respuesta fue correcta desde la tabla grupos
                    fue_correcta = juego.get('ultima_respuesta_correcta', False)

                    return jsonify({
                        "tiene_respuesta": True,
                        "respuesta_correcta": pregunta['respuesta_correcta'],
                        "nuevo_score": juego['current_score'],
                        "fue_correcta": fue_correcta  # NUEVO: Indicar si fue correcta
                    })

            return jsonify({"tiene_respuesta": False})

    except Exception as e:
        print(f"Error en api_get_ultima_respuesta: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/responder/<int:grupo_id>", methods=["POST"])
def api_responder(grupo_id):
    """Procesa la respuesta del líder del grupo"""
    if "usuario" not in session:
        return jsonify({"success": False, "message": "No autenticado"}), 403

    user_id = session['user_id']
    respuesta_usuario = request.json.get('respuesta')

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # CORRECCIÓN para AttributeError: 'int' object has no attribute 'fetchone'
            cursor.execute("SELECT lider_id FROM grupos WHERE id = %s", (grupo_id,))
            grupo = cursor.fetchone()

            if not grupo or grupo['lider_id'] != user_id:
                return jsonify({"success": False, "message": "Solo el líder puede responder"}), 403

            cursor.execute("""
                SELECT g.current_question_index, g.current_score, c.id as cuestionario_id, c.num_preguntas
                FROM grupos g
                JOIN cuestionarios c ON g.active_pin = c.codigo_pin
                WHERE g.id = %s
            """, (grupo_id,))
            juego = cursor.fetchone()

            if not juego:
                return jsonify({"success": False, "message": "No se encontró el juego"}), 404

            if juego['current_question_index'] >= juego['num_preguntas']:
                return jsonify({"success": False, "message": "El juego ya terminó", "finished": True}), 400

            cursor.execute("""
                SELECT respuesta_correcta
                FROM preguntas
                WHERE cuestionario_id = %s
                ORDER BY orden
                LIMIT 1 OFFSET %s
            """, (juego['cuestionario_id'], juego['current_question_index']))

            pregunta_actual = cursor.fetchone()

            if not pregunta_actual:
                return jsonify({"success": False, "message": "No se encontró la pregunta"}), 404

            es_correcta = (respuesta_usuario == pregunta_actual['respuesta_correcta'])
            puntos_ganados = 0

            if es_correcta:
                puntos_ganados = 100
                nuevo_score = juego['current_score'] + puntos_ganados
                cursor.execute("UPDATE grupos SET current_score = %s WHERE id = %s",
                               (nuevo_score, grupo_id))

            nuevo_index = juego['current_question_index'] + 1

            es_ultima_pregunta = (nuevo_index >= juego['num_preguntas'])

            nuevo_estado = 'answered'
            if es_ultima_pregunta:
                nuevo_estado = 'finished'

            # Actualizar el índice y el estado
            cursor.execute("""
            UPDATE grupos
            SET current_question_index = %s,
            game_state = %s,
            ultima_respuesta_correcta = %s
            WHERE id = %s
             """, (nuevo_index, nuevo_estado, es_correcta, grupo_id))

            conexion.commit()

            return jsonify({
                "success": True,
                "es_correcta": es_correcta,
                "puntos_ganados": puntos_ganados,
                "respuesta_correcta": pregunta_actual['respuesta_correcta'],
                "respuesta_seleccionada": respuesta_usuario,
                "es_ultima_pregunta": es_ultima_pregunta,
                "nuevo_index": nuevo_index,
                "nuevo_score": juego['current_score'] + puntos_ganados if es_correcta else juego['current_score']
            })

    except Exception as e:
        print(f"Error en api_responder: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": f"Error del servidor: {str(e)}"}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/cambiar_datos_estudiante", methods=["GET", "POST"])
def cambiar_datos_estudiante():
    if "usuario" not in session or session.get("rol") != "estudiante": return redirect(url_for("login"))
    if request.method == "POST":
        nombre_nuevo, password_actual = request.form["nombre"], request.form["password_actual"]
        password_nueva, confirmar_nueva = request.form.get("password_nueva", ""), request.form.get("confirmar_nueva", "")
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("SELECT password FROM usuarios WHERE id=%s", (session["user_id"],))
                usuario = cursor.fetchone()
                if not usuario or usuario["password"] != password_actual:
                    flash("❌ La contraseña actual es incorrecta", "error")
                    return redirect(url_for("cambiar_datos_estudiante"))
                if password_nueva:
                    if password_nueva != confirmar_nueva:
                        flash("❌ Las contraseñas nuevas no coinciden", "error")
                        return redirect(url_for("cambiar_datos_estudiante"))
                    es_segura, msg = es_password_segura(password_nueva)
                    if not es_segura:
                        flash(f"❌ {msg}", "error")
                        return redirect(url_for("cambiar_datos_estudiante"))
                    cursor.execute("UPDATE usuarios SET nombre=%s, password=%s WHERE id=%s", (nombre_nuevo, password_nueva, session["user_id"]))
                else:
                    cursor.execute("UPDATE usuarios SET nombre=%s WHERE id=%s", (nombre_nuevo, session["user_id"]))
                conexion.commit()
            session["usuario"] = nombre_nuevo
            flash("✅ Datos actualizados correctamente", "success")
            return redirect(url_for("dashboard_estudiante"))
        finally:
            if conexion and conexion.open: conexion.close()
    return render_template("CambiarDatos_estudiante.html", nombre=session["usuario"], correo=session["correo"])

@app.route("/eliminar_cuenta_estudiante", methods=["POST"])
def eliminar_cuenta_estudiante():
    if "usuario" not in session or session.get("rol") != "estudiante": return redirect(url_for("login"))
    password_actual, user_id = request.form.get("password_actual"), session["user_id"]
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT password FROM usuarios WHERE id = %s", (user_id,))
            usuario = cursor.fetchone()
            if not usuario or usuario['password'] != password_actual:
                flash("❌ Contraseña incorrecta. No se pudo eliminar la cuenta.", "error")
                return redirect(url_for('cambiar_datos_estudiante'))
            cursor.execute("DELETE FROM usuarios WHERE id = %s", (user_id,))
            conexion.commit()
            session.clear()
            flash("✅ Tu cuenta ha sido eliminada permanentemente.", "success")
            return redirect(url_for('login'))
    finally:
        if conexion and conexion.open: conexion.close()

@app.route("/visualizar_cuestionario", methods=["POST"])
def visualizar_cuestionario():
    # 1. Verificación de sesión
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    # 2. Obtener el PIN del formulario
    pin = request.form.get("codigo_pin")
    if not pin:
        flash("❌ Debes ingresar un código PIN.", "error")
        return redirect(url_for("dashboard_estudiante"))

    # 3. Conexión a la base de datos
    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            # 4. Buscar el cuestionario
            cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s", (pin,))
            cuestionario = cursor.fetchone()

            # 5. Validar si existe
            if not cuestionario:
                flash(f"❌ No se encontró ningún cuestionario con el PIN '{pin}'.", "error")
                # ¡Importante! 'return' aquí dentro del 'try' SÍ ejecutará el 'finally' antes de salir.
                return redirect(url_for("dashboard_estudiante"))

            # 6. Validar que sea modo INDIVIDUAL
            if cuestionario['modo_juego'] == 'grupal':
                flash(f"❌ El PIN '{pin}' es para un juego GRUPAL. Únete a un grupo para jugarlo.", "error")
                return redirect(url_for("dashboard_estudiante"))


            cursor.execute("SELECT * FROM preguntas WHERE cuestionario_id = %s ORDER BY orden", (cuestionario['id'],))
            preguntas = cursor.fetchall()

    finally:

        if conexion and conexion.open:
            conexion.close()


    return redirect(url_for("sala_espera_individual", codigo_pin=pin))

@app.route("/exportar_resultados/<int:cuestionario_id>")
def exportar_resultados(cuestionario_id):
    """Página de opciones de exportación - SOPORTA INDIVIDUAL Y GRUPAL"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT titulo, num_preguntas, modo_juego FROM cuestionarios
                WHERE id = %s AND profesor_id = %s
            """, (cuestionario_id, session["user_id"]))

            cuestionario = cursor.fetchone()
            if not cuestionario:
                flash("❌ Cuestionario no encontrado", "error")
                return redirect(url_for("dashboard_profesor"))

            # Contar resultados según el modo de juego
            if cuestionario['modo_juego'] == 'grupal':
                cursor.execute("""
                    SELECT COUNT(*) as total FROM historial_partidas
                    WHERE cuestionario_id = %s
                """, (cuestionario_id,))
            else:  # individual
                cursor.execute("""
                    SELECT COUNT(*) as total FROM historial_individual
                    WHERE cuestionario_id = %s AND puntuacion_final > 0
                """, (cuestionario_id,))

            total_resultados = cursor.fetchone()['total']

    finally:
        if conexion and conexion.open:
            conexion.close()

    return render_template("exportar_opciones.html",
                           cuestionario=cuestionario,
                           cuestionario_id=cuestionario_id,
                           total_resultados=total_resultados)

@app.route("/descargar_excel/<int:cuestionario_id>")
def descargar_excel(cuestionario_id):
    """Descarga directa del Excel - SOPORTA INDIVIDUAL Y GRUPAL"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        import pandas as pd
        import openpyxl
        from flask import send_file

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # Verificar que el cuestionario pertenece al profesor
                cursor.execute("""
                    SELECT titulo, modo_juego, num_preguntas FROM cuestionarios
                    WHERE id = %s AND profesor_id = %s
                """, (cuestionario_id, session["user_id"]))

                cuestionario = cursor.fetchone()
                if not cuestionario:
                    flash("❌ Cuestionario no encontrado", "error")
                    return redirect(url_for("dashboard_profesor"))

                # ===== CONSULTA SEGÚN MODO DE JUEGO =====
                if cuestionario['modo_juego'] == 'grupal':
                    # Obtener resultados GRUPALES
                    cursor.execute("""
                        SELECT
                            h.id as partida_id,
                            h.nombre_grupo as identificador,
                            h.puntuacion_final,
                            h.num_preguntas_total,
                            h.num_miembros as extras,
                            h.fecha_partida as fecha,
                            GROUP_CONCAT(p.nombre_usuario SEPARATOR ', ') as participantes
                        FROM historial_partidas h
                        LEFT JOIN participantes_partida p ON h.id = p.partida_id
                        WHERE h.cuestionario_id = %s
                        GROUP BY h.id
                        ORDER BY h.fecha_partida DESC
                    """, (cuestionario_id,))
                else:
                    # Obtener resultados INDIVIDUALES
                    cursor.execute("""
                        SELECT
                            h.id as partida_id,
                            h.nombre_estudiante as identificador,
                            h.puntuacion_final,
                            h.num_preguntas_total,
                            h.tiempo_total as extras,
                            h.fecha_realizacion as fecha,
                            NULL as participantes
                        FROM historial_individual h
                        WHERE h.cuestionario_id = %s
                          AND h.puntuacion_final > 0
                        ORDER BY h.fecha_realizacion DESC
                    """, (cuestionario_id,))

                resultados = cursor.fetchall()

                if not resultados:
                    flash("⚠️ No hay resultados para exportar", "warning")
                    return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

                # Crear DataFrame
                df = pd.DataFrame(resultados)

                # Renombrar columnas según el modo
                if cuestionario['modo_juego'] == 'grupal':
                    df.columns = ['ID Partida', 'Grupo', 'Puntuación', 'Total Preguntas',
                                  'Miembros', 'Fecha', 'Participantes']

                    # Calcular estadísticas grupales
                    df['Porcentaje (%)'] = (df['Puntuación'] / (df['Total Preguntas'] * 100) * 100).round(2)
                    df['Preguntas Correctas'] = (df['Puntuación'] / 100).astype(int)
                    df['Preguntas Incorrectas'] = df['Total Preguntas'] - df['Preguntas Correctas']
                else:
                    df.columns = ['ID Partida', 'Estudiante', 'Puntuación', 'Total Preguntas',
                                  'Tiempo (seg)', 'Fecha', 'Participantes']
                    df = df.drop('Participantes', axis=1)  # No aplica en individual

                    # Calcular estadísticas individuales
                    # Para individual, puntos máximos = preguntas * 1000 (sistema de puntos por velocidad)
                    df['Porcentaje (%)'] = (df['Puntuación'] / (df['Total Preguntas'] * 1000) * 100).round(2)
                    df['Tiempo Promedio/Preg'] = (df['Tiempo (seg)'] / df['Total Preguntas']).round(1)

                # Crear archivo Excel en memoria con múltiples hojas
                output = BytesIO()
                with pd.ExcelWriter(output, engine='openpyxl') as writer:
                    # Hoja 1: Resultados detallados
                    df.to_excel(writer, sheet_name='Resultados Detallados', index=False)

                    # Hoja 2: Estadísticas generales
                    if cuestionario['modo_juego'] == 'grupal':
                        stats_data = {
                            'Métrica': [
                                'Total de Partidas',
                                'Total de Jugadores (sumado)',
                                'Puntuación Promedio',
                                'Puntuación Máxima',
                                'Puntuación Mínima',
                                'Porcentaje Promedio',
                                'Grupos con +80%',
                                'Grupos con +60%'
                            ],
                            'Valor': [
                                len(df),
                                df['Miembros'].sum(),
                                df['Puntuación'].mean().round(2),
                                df['Puntuación'].max(),
                                df['Puntuación'].min(),
                                df['Porcentaje (%)'].mean().round(2),
                                len(df[df['Porcentaje (%)'] >= 80]),
                                len(df[df['Porcentaje (%)'] >= 60])
                            ]
                        }
                    else:
                        stats_data = {
                            'Métrica': [
                                'Total de Partidas',
                                'Total de Estudiantes',
                                'Puntuación Promedio',
                                'Puntuación Máxima',
                                'Puntuación Mínima',
                                'Porcentaje Promedio',
                                'Estudiantes con +80%',
                                'Estudiantes con +60%',
                                'Tiempo Promedio Total',
                                'Mejor Tiempo'
                            ],
                            'Valor': [
                                len(df),
                                len(df),
                                df['Puntuación'].mean().round(2),
                                df['Puntuación'].max(),
                                df['Puntuación'].min(),
                                df['Porcentaje (%)'].mean().round(2),
                                len(df[df['Porcentaje (%)'] >= 80]),
                                len(df[df['Porcentaje (%)'] >= 60]),
                                df['Tiempo (seg)'].mean().round(1),
                                df['Tiempo (seg)'].min()
                            ]
                        }

                    stats_df = pd.DataFrame(stats_data)
                    stats_df.to_excel(writer, sheet_name='Estadísticas', index=False)

                    # Ajustar ancho de columnas en ambas hojas
                    for sheet_name in writer.sheets:
                        worksheet = writer.sheets[sheet_name]
                        for column in worksheet.columns:
                            max_length = 0
                            column_cells = [cell for cell in column]
                            for cell in column_cells:
                                try:
                                    if len(str(cell.value)) > max_length:
                                        max_length = len(str(cell.value))
                                except:
                                    pass
                            adjusted_width = min(max_length + 2, 50)
                            worksheet.column_dimensions[column_cells[0].column_letter].width = adjusted_width

                output.seek(0)

                # Nombre del archivo
                modo_texto = "Grupal" if cuestionario['modo_juego'] == 'grupal' else "Individual"
                filename = f"Resultados_{modo_texto}_{cuestionario['titulo'].replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

                return send_file(
                    output,
                    mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    as_attachment=True,
                    download_name=filename
                )

        finally:
            if conexion and conexion.open:
                conexion.close()

    except ImportError:
        flash("❌ Error: Necesitas instalar 'pandas' y 'openpyxl'. Ejecuta: pip install pandas openpyxl", "error")
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))
    except Exception as e:
        flash(f"❌ Error al exportar: {str(e)}", "error")
        print(f"Error en descargar_excel: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))


@app.route("/enviar_excel_correo/<int:cuestionario_id>", methods=["POST"])
def enviar_excel_correo(cuestionario_id):
    """Envía el archivo Excel por correo electrónico - SOPORTA INDIVIDUAL Y GRUPAL"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        import pandas as pd

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # Verificar que el cuestionario pertenece al profesor
                cursor.execute("""
                    SELECT titulo, modo_juego, num_preguntas FROM cuestionarios
                    WHERE id = %s AND profesor_id = %s
                """, (cuestionario_id, session["user_id"]))

                cuestionario = cursor.fetchone()
                if not cuestionario:
                    flash("❌ Cuestionario no encontrado", "error")
                    return redirect(url_for("dashboard_profesor"))

                # Obtener resultados según modo
                if cuestionario['modo_juego'] == 'grupal':
                    cursor.execute("""
                        SELECT
                            h.id as partida_id, h.nombre_grupo as identificador,
                            h.puntuacion_final, h.num_preguntas_total,
                            h.num_miembros as extras, h.fecha_partida as fecha,
                            GROUP_CONCAT(p.nombre_usuario SEPARATOR ', ') as participantes
                        FROM historial_partidas h
                        LEFT JOIN participantes_partida p ON h.id = p.partida_id
                        WHERE h.cuestionario_id = %s
                        GROUP BY h.id
                        ORDER BY h.fecha_partida DESC
                    """, (cuestionario_id,))
                else:
                    cursor.execute("""
                        SELECT
                            h.id as partida_id, h.nombre_estudiante as identificador,
                            h.puntuacion_final, h.num_preguntas_total,
                            h.tiempo_total as extras, h.fecha_realizacion as fecha,
                            NULL as participantes
                        FROM historial_individual h
                        WHERE h.cuestionario_id = %s AND h.puntuacion_final > 0
                        ORDER BY h.fecha_realizacion DESC
                    """, (cuestionario_id,))

                resultados = cursor.fetchall()

                if not resultados:
                    flash("⚠️ No hay resultados para exportar", "warning")
                    return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

                # Crear DataFrame y calcular estadísticas
                df = pd.DataFrame(resultados)

                if cuestionario['modo_juego'] == 'grupal':
                    df.columns = ['ID Partida', 'Grupo', 'Puntuación', 'Total Preguntas', 'Miembros', 'Fecha', 'Participantes']
                    df['Porcentaje (%)'] = (df['Puntuación'] / (df['Total Preguntas'] * 100) * 100).round(2)
                    df['Preguntas Correctas'] = (df['Puntuación'] / 100).astype(int)
                    df['Preguntas Incorrectas'] = df['Total Preguntas'] - df['Preguntas Correctas']

                    total_jugadores = int(df['Miembros'].sum())
                else:
                    df.columns = ['ID Partida', 'Estudiante', 'Puntuación', 'Total Preguntas', 'Tiempo (seg)', 'Fecha', 'Participantes']
                    df = df.drop('Participantes', axis=1)
                    df['Porcentaje (%)'] = (df['Puntuación'] / (df['Total Preguntas'] * 1000) * 100).round(2)
                    df['Tiempo Promedio/Preg'] = (df['Tiempo (seg)'] / df['Total Preguntas']).round(1)

                    total_jugadores = len(df)

                # Crear Excel en memoria
                output = BytesIO()
                with pd.ExcelWriter(output, engine='openpyxl') as writer:
                    df.to_excel(writer, sheet_name='Resultados Detallados', index=False)

                    # Estadísticas
                    if cuestionario['modo_juego'] == 'grupal':
                        stats_data = {
                            'Métrica': ['Total de Partidas', 'Total de Jugadores', 'Puntuación Promedio', 'Puntuación Máxima', 'Puntuación Mínima', 'Porcentaje Promedio', 'Grupos con +80%', 'Grupos con +60%'],
                            'Valor': [len(df), df['Miembros'].sum(), df['Puntuación'].mean().round(2), df['Puntuación'].max(), df['Puntuación'].min(), df['Porcentaje (%)'].mean().round(2), len(df[df['Porcentaje (%)'] >= 80]), len(df[df['Porcentaje (%)'] >= 60])]
                        }
                    else:
                        stats_data = {
                            'Métrica': ['Total de Partidas', 'Total de Estudiantes', 'Puntuación Promedio', 'Puntuación Máxima', 'Puntuación Mínima', 'Porcentaje Promedio', 'Estudiantes con +80%', 'Estudiantes con +60%', 'Tiempo Promedio'],
                            'Valor': [len(df), len(df), df['Puntuación'].mean().round(2), df['Puntuación'].max(), df['Puntuación'].min(), df['Porcentaje (%)'].mean().round(2), len(df[df['Porcentaje (%)'] >= 80]), len(df[df['Porcentaje (%)'] >= 60]), df['Tiempo (seg)'].mean().round(1)]
                        }

                    stats_df = pd.DataFrame(stats_data)
                    stats_df.to_excel(writer, sheet_name='Estadísticas', index=False)

                    for sheet_name in writer.sheets:
                        worksheet = writer.sheets[sheet_name]
                        for column in worksheet.columns:
                            max_length = 0
                            column_cells = [cell for cell in column]
                            for cell in column_cells:
                                try:
                                    if len(str(cell.value)) > max_length:
                                        max_length = len(str(cell.value))
                                except:
                                    pass
                            adjusted_width = min(max_length + 2, 50)
                            worksheet.column_dimensions[column_cells[0].column_letter].width = adjusted_width

                output.seek(0)
                modo_texto = "Grupal" if cuestionario['modo_juego'] == 'grupal' else "Individual"
                filename = f"Resultados_{modo_texto}_{cuestionario['titulo'].replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

                # Preparar correo
                correo_destino = session.get('correo')
                nombre_profesor = session.get('usuario')
                titulo_cuestionario = cuestionario['titulo']
                total_partidas = len(df)
                fecha_generacion = datetime.now().strftime('%d/%m/%Y a las %H:%M')

                msg = Message(
                    subject=f'Resultados del Cuestionario {modo_texto}: {titulo_cuestionario}',
                    recipients=[correo_destino]
                )

                # HTML del correo
                html_body = f'''<html><body style="font-family: Arial, sans-serif; background-color: #f5f6fa; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 15px; box-shadow: 0 5px 20px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;"><div style="font-size: 48px; margin-bottom: 15px;">📊</div>
                <h2 style="color: #667eea; margin: 0;">Resultados de Cuestionario {modo_texto}</h2></div>
                <p style="color: #333; font-size: 16px;">Hola <strong>{nombre_profesor}</strong>,</p>
                <p style="color: #666; line-height: 1.6;">Adjunto encontrarás el archivo Excel con los resultados detallados del cuestionario <strong>"{titulo_cuestionario}"</strong> (Modo: {modo_texto}).</p>
                <div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 20px; margin: 25px 0; border-radius: 8px;">
                <h3 style="color: #1976d2; margin-top: 0;">📄 Contenido del Archivo</h3><ul style="color: #0d47a1; line-height: 1.8;">
                <li><strong>Hoja 1:</strong> Resultados detallados de todas las partidas</li>
                <li><strong>Hoja 2:</strong> Estadísticas generales y promedios</li>
                <li><strong>Total de partidas:</strong> {total_partidas}</li>
                <li><strong>Total de {"jugadores" if cuestionario['modo_juego'] == 'grupal' else "estudiantes"}:</strong> {total_jugadores}</li></ul></div>
                <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0;">
                <p style="color: #856404; margin: 0; font-size: 14px;">💡 <strong>Consejo:</strong> Abre el archivo con Microsoft Excel, Google Sheets o LibreOffice Calc.</p></div>
                <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0;">
                <p style="color: #999; font-size: 12px; margin: 0;">Sistema de Cuestionarios Interactivos<br>Generado el {fecha_generacion}</p></div>
                </div></body></html>'''

                msg.html = html_body
                msg.attach(filename, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', output.getvalue())

                with app.app_context():
                    mail.send(msg)

                print(f"✅ Correo enviado exitosamente a {correo_destino}")
                flash(f"✅ ¡Correo enviado exitosamente a {correo_destino}! Revisa tu bandeja de entrada.", "success")
                return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

        finally:
            if conexion and conexion.open:
                conexion.close()

    except ImportError:
        flash("❌ Error: Necesitas instalar pandas y openpyxl", "error")
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))
    except Exception as e:
        flash(f"❌ Error al enviar el correo: {str(e)}", "error")
        print(f"Error en enviar_excel_correo: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

@app.route("/guardar_respuesta_individual", methods=["POST"])
def guardar_respuesta_individual():
    """Guarda la respuesta y espera a que todos terminen"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        data = request.get_json()
        pregunta_id = data.get('pregunta_id')
        respuesta = data.get('respuesta')
        tiempo_respuesta = data.get('tiempo_respuesta', 0)
        pregunta_index = data.get('pregunta_index', 0)  # NUEVO

        user_id = session["user_id"]
        historial_id = session.get('historial_individual_id')

        if not historial_id:
            return jsonify({"success": False, "message": "No hay sesión activa"}), 400

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # Obtener sesion_id
                cursor.execute("""
                    SELECT sesion_id FROM historial_individual WHERE id = %s
                """, (historial_id,))
                historial = cursor.fetchone()
                sesion_id = historial['sesion_id'] if historial else None

                # Obtener pregunta y calcular puntos (código existente)
                cursor.execute("""
                    SELECT p.respuesta_correcta, c.tiempo_pregunta
                    FROM preguntas p
                    JOIN cuestionarios c ON p.cuestionario_id = c.id
                    WHERE p.id = %s
                """, (pregunta_id,))
                pregunta = cursor.fetchone()

                if not pregunta:
                    return jsonify({"success": False, "message": "Pregunta no encontrada"}), 404

                puntos_obtenidos = 0
                es_correcta = False

                if respuesta is not None:
                    es_correcta = (respuesta == pregunta['respuesta_correcta'])

                    if es_correcta:
                        tiempo_limite = pregunta['tiempo_pregunta']
                        porcentaje_tiempo = (tiempo_respuesta / tiempo_limite) * 100 if tiempo_limite > 0 else 100

                        if porcentaje_tiempo <= 25:
                            puntos_obtenidos = 1000
                        elif porcentaje_tiempo <= 50:
                            puntos_obtenidos = 800
                        elif porcentaje_tiempo <= 75:
                            puntos_obtenidos = 600
                        else:
                            puntos_obtenidos = 400

                # Guardar respuesta
                cursor.execute("""
                    INSERT INTO respuestas_individuales
                    (historial_id, pregunta_id, respuesta_estudiante, tiempo_respuesta)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    respuesta_estudiante = VALUES(respuesta_estudiante),
                    tiempo_respuesta = VALUES(tiempo_respuesta)
                """, (historial_id, pregunta_id, respuesta, tiempo_respuesta))

                # Actualizar puntuación
                if es_correcta:
                    cursor.execute("""
                        UPDATE historial_individual
                        SET puntuacion_final = puntuacion_final + %s
                        WHERE id = %s
                    """, (puntos_obtenidos, historial_id))

                conexion.commit()

                # MARCAR COMO LISTO
                if sesion_id:
                    marcar_estudiante_listo_individual(user_id, sesion_id, pregunta_index)

                # VERIFICAR SI TODOS ESTÁN LISTOS
                todos_listos = verificar_todos_listos_individual(sesion_id, pregunta_index) if sesion_id else False

                # SI TODOS LISTOS, RESETEAR BARRERA
                if todos_listos and sesion_id:
                    resetear_barrera_individual(sesion_id)

                return jsonify({
                    "success": True,
                    "correcta": es_correcta,
                    "respuesta_correcta": pregunta['respuesta_correcta'],
                    "puntos": puntos_obtenidos,
                    "todos_listos": todos_listos  # NUEVO
                })

        finally:
            if conexion and conexion.open:
                conexion.close()

    except Exception as e:
        print(f"❌ Error al guardar respuesta individual: {e}")
        return jsonify({"success": False, "message": str(e)}), 500



@app.route("/finalizar_cuestionario_individual", methods=["POST"])
def finalizar_cuestionario_individual():
    """Finaliza el cuestionario individual y guarda los resultados finales CON RECOMPENSAS"""
    print("\n" + "="*70)
    print("🏁 FINALIZANDO CUESTIONARIO INDIVIDUAL")
    print("="*70)

    if "usuario" not in session or session.get("rol") != "estudiante":
        print("❌ No autorizado")
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        data = request.get_json()
        print(f"📥 Datos recibidos: {data}")

        puntuacion_final = data.get('puntuacion_final', 0)
        tiempo_total = data.get('tiempo_total', 0)

        historial_id = session.get('historial_individual_id')
        user_id = session["user_id"]

        print(f"👤 Usuario ID: {user_id}")
        print(f"📋 Historial ID: {historial_id}")
        print(f"💯 Puntuación final: {puntuacion_final}")
        print(f"⏱️ Tiempo total: {tiempo_total}s")

        if not historial_id:
            print("❌ No hay sesión activa (historial_id no encontrado)")
            return jsonify({"success": False, "message": "No hay sesión activa"}), 400

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # Verificar que el historial existe
                cursor.execute("""
                    SELECT h.*, c.num_preguntas
                    FROM historial_individual h
                    JOIN cuestionarios c ON h.cuestionario_id = c.id
                    WHERE h.id = %s
                """, (historial_id,))
                historial = cursor.fetchone()

                if not historial:
                    print(f"❌ Historial {historial_id} no encontrado")
                    return jsonify({"success": False, "message": "Historial no encontrado"}), 404

                if historial['usuario_id'] != user_id:
                    print(f"❌ Usuario {user_id} no es dueño del historial")
                    return jsonify({"success": False, "message": "No autorizado"}), 403

                # Actualizar el historial como finalizado
                print(f"💾 Actualizando historial {historial_id}...")
                cursor.execute("""
                    UPDATE historial_individual
                    SET puntuacion_final = %s,
                        tiempo_total = %s
                    WHERE id = %s
                """, (puntuacion_final, tiempo_total, historial_id))

                # Eliminar al estudiante de la sala de espera
                print(f"🚪 Eliminando usuario {user_id} de sala de espera...")
                cursor.execute("""
                    DELETE FROM salas_espera
                    WHERE usuario_id = %s
                """, (user_id,))

                # ====== SISTEMA DE RECOMPENSAS ======
                # Contar correctas e incorrectas
                cursor.execute("""
                    SELECT
                        SUM(CASE WHEN p.respuesta_correcta = r.respuesta_estudiante THEN 1 ELSE 0 END) as correctas,
                        SUM(CASE WHEN p.respuesta_correcta != r.respuesta_estudiante OR r.respuesta_estudiante IS NULL THEN 1 ELSE 0 END) as incorrectas
                    FROM respuestas_individuales r
                    JOIN preguntas p ON r.pregunta_id = p.id
                    WHERE r.historial_id = %s
                """, (historial_id,))
                stats_partida = cursor.fetchone()

                correctas = stats_partida['correctas'] or 0
                incorrectas = stats_partida['incorrectas'] or 0

                conexion.commit()

                print(f"✅ Cuestionario finalizado exitosamente")
                print(f"   - Historial ID: {historial_id}")
                print(f"   - Puntuación: {puntuacion_final}")
                print(f"   - Correctas: {correctas}")
                print(f"   - Incorrectas: {incorrectas}")

                # Procesar recompensas
                print("🎁 Procesando recompensas...")
                recompensas = actualizar_stats_despues_partida(user_id, puntuacion_final, correctas, incorrectas)
                print(f"   - XP ganada: {recompensas['xp_info']['xp_ganada']}")
                print(f"   - Monedas ganadas: {recompensas['monedas_ganadas']}")
                print(f"   - Insignias nuevas: {len(recompensas['insignias_nuevas'])}")

                session['recompensas_recientes'] = {
                "xp_ganada": recompensas['xp_info']['xp_ganada'],
                "monedas_ganadas": recompensas['monedas_ganadas'],
                "niveles_subidos": recompensas['xp_info']['niveles_subidos'],
                "insignias_nuevas": [{"nombre": i['nombre'], "icono": i['icono'], "tipo": i['tipo']} for i in recompensas['insignias_nuevas']],
                "nivel_actual": recompensas['xp_info']['nivel_actual'],
                "racha_actual": recompensas['racha_actual'],
                "es_mejor_puntaje": recompensas['es_mejor_puntaje']
            }

                # Limpiar sesión
                session.pop('historial_individual_id', None)

                # Incluir recompensas en la respuesta
                redirect_url = url_for('resultados_individual', historial_id=historial_id)

                return jsonify({
                    "success": True,
                    "redirect_url": redirect_url,
                    "message": "Cuestionario finalizado correctamente",
                    "recompensas": {
                        "xp_ganada": recompensas['xp_info']['xp_ganada'],
                        "monedas_ganadas": recompensas['monedas_ganadas'],
                        "niveles_subidos": recompensas['xp_info']['niveles_subidos'],
                        "insignias_nuevas": [{"nombre": i['nombre'], "icono": i['icono'], "tipo": i['tipo']} for i in recompensas['insignias_nuevas']],
                        "nivel_actual": recompensas['xp_info']['nivel_actual'],
                        "racha_actual": recompensas['racha_actual'],
                        "es_mejor_puntaje": recompensas['es_mejor_puntaje']
                    }
                })

        finally:
            if conexion and conexion.open:
                conexion.close()

    except Exception as e:
        print(f"❌ ERROR CRÍTICO al finalizar cuestionario:")
        print(f"    Tipo: {type(e).__name__}")
        print(f"    Mensaje: {str(e)}")
        import traceback
        traceback.print_exc()

        return jsonify({"success": False, "message": str(e)}), 500

# --- RUTA PARA VER RESULTADOS INDIVIDUALES (CORREGIDA CON DEBUG) ---
@app.route("/resultados_individual/<int:historial_id>")
def resultados_individual(historial_id):
    """Muestra los resultados del cuestionario individual con ranking"""
    print(f"\n{'='*70}")
    print(f"📊 CARGANDO RESULTADOS INDIVIDUALES CON RANKING")
    print(f"📋 Historial ID: {historial_id}")
    print(f"{'='*70}\n")

    if "usuario" not in session or session.get("rol") != "estudiante":
        print("❌ No autorizado")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    print(f"👤 Usuario ID: {user_id}")

    # Inicializar variables para evitar NameError
    respuestas_raw = []
    ranking_completo = []

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # 1. Obtener el historial con información del cuestionario
            print("\n📥 Consultando historial...")
            cursor.execute("""
                SELECT h.*,
                       c.titulo as titulo_cuestionario,
                       c.num_preguntas as num_preguntas_total,
                       u.nombre as nombre_estudiante
                FROM historial_individual h
                JOIN cuestionarios c ON h.cuestionario_id = c.id
                JOIN usuarios u ON h.usuario_id = u.id
                WHERE h.id = %s AND h.usuario_id = %s
            """, (historial_id, user_id))
            historial = cursor.fetchone()

            if not historial:
                print(f"❌ Historial {historial_id} no encontrado para usuario {user_id}")
                flash("❌ Resultados no encontrados", "error")
                return redirect(url_for("dashboard_estudiante"))

            print(f"✅ Historial encontrado:")
            print(f"   - Cuestionario: {historial['titulo_cuestionario']}")
            print(f"   - Puntuación final: {historial['puntuacion_final']}")

            # 2. Obtener RANKING solo de la sesión actual (jugadores que jugaron aproximadamente al mismo tiempo)
            print("\n🏆 Consultando ranking de la sesión actual...")

            # Obtener el sesion_id del historial actual
            sesion_id_actual = historial.get('sesion_id')
            print(f"   📌 Sesión ID actual: {sesion_id_actual}")

            if sesion_id_actual:
                # Solo mostrar jugadores de LA MISMA SESIÓN
                cursor.execute("""
                    SELECT
                        h.id,
                        u.nombre as nombre_estudiante,
                        h.puntuacion_final,
                        h.tiempo_total,
                        h.fecha_realizacion,
                        COUNT(DISTINCT r.pregunta_id) as preguntas_respondidas
                    FROM historial_individual h
                    JOIN usuarios u ON h.usuario_id = u.id
                    LEFT JOIN respuestas_individuales r ON h.id = r.historial_id
                    WHERE h.sesion_id = %s
                    GROUP BY h.id, u.nombre, h.puntuacion_final, h.tiempo_total, h.fecha_realizacion
                    ORDER BY h.puntuacion_final DESC, h.tiempo_total ASC
                """, (sesion_id_actual,))
            else:
                # Fallback: Si no hay sesion_id, usar ventana de 5 minutos
                cursor.execute("""
                    SELECT
                        h.id,
                        u.nombre as nombre_estudiante,
                        h.puntuacion_final,
                        h.tiempo_total,
                        h.fecha_realizacion,
                        COUNT(DISTINCT r.pregunta_id) as preguntas_respondidas
                    FROM historial_individual h
                    JOIN usuarios u ON h.usuario_id = u.id
                    LEFT JOIN respuestas_individuales r ON h.id = r.historial_id
                    WHERE h.cuestionario_id = %s
                      AND h.fecha_realizacion BETWEEN
                        DATE_SUB(%s, INTERVAL 5 MINUTE)
                        AND DATE_ADD(%s, INTERVAL 5 MINUTE)
                    GROUP BY h.id, u.nombre, h.puntuacion_final, h.tiempo_total, h.fecha_realizacion
                    ORDER BY h.puntuacion_final DESC, h.tiempo_total ASC
                """, (historial['cuestionario_id'], historial['fecha_realizacion'], historial['fecha_realizacion']))

            ranking_completo = cursor.fetchall()

            for participante in ranking_completo:
                if participante.get('fecha_realizacion'):
                    participante['fecha_realizacion'] = convertir_a_hora_peru(
                        participante['fecha_realizacion']
                    )

            # 3. Obtener el detalle de las respuestas para este historial
            print("\n📋 Consultando detalle de respuestas...")
            cursor.execute("""
                SELECT
                    p.id as pregunta_id, p.pregunta,
                    p.opcion_a, p.opcion_b, p.opcion_c, p.opcion_d,
                    p.respuesta_correcta, c.tiempo_pregunta,
                    r.respuesta_estudiante, r.tiempo_respuesta
                FROM respuestas_individuales r
                JOIN preguntas p ON r.pregunta_id = p.id
                JOIN cuestionarios c ON p.cuestionario_id = c.id
                WHERE r.historial_id = %s
                ORDER BY p.orden
            """, (historial_id,))
            respuestas_raw = cursor.fetchall()
            print(f"✅ Respuestas cargadas: {len(respuestas_raw)}") # ✅ FIX 1

            # 4. Calcular puntos basados en velocidad para cada respuesta
            respuestas = []
            correctas = 0
            incorrectas = 0
            tiempo_total_respuestas = 0

            for r in respuestas_raw:
                es_correcta = (r['respuesta_estudiante'] == r['respuesta_correcta'])

                # Calcular puntos usando la misma lógica que en guardar_respuesta
                puntos = 0
                if es_correcta:
                    tiempo_limite = r['tiempo_pregunta']
                    tiempo_respuesta = r['tiempo_respuesta']
                    porcentaje_tiempo = (tiempo_respuesta / tiempo_limite) * 100 if tiempo_limite > 0 else 100

                    if porcentaje_tiempo <= 25:
                        puntos = 1000
                    elif porcentaje_tiempo <= 50:
                        puntos = 800
                    elif porcentaje_tiempo <= 75:
                        puntos = 600
                    else:
                        puntos = 400

                if es_correcta:
                    correctas += 1
                else:
                    incorrectas += 1

                tiempo_total_respuestas += r['tiempo_respuesta']

                respuesta_completa = {
                    'pregunta_id': r['pregunta_id'],
                    'pregunta': r['pregunta'],
                    'opcion_a': r['opcion_a'],
                    'opcion_b': r['opcion_b'],
                    'opcion_c': r['opcion_c'],
                    'opcion_d': r['opcion_d'],
                    'respuesta_correcta': r['respuesta_correcta'],
                    'respuesta_estudiante': r['respuesta_estudiante'],
                    'tiempo_respuesta': r['tiempo_respuesta'],
                    'tiempo_pregunta': r['tiempo_pregunta'],
                    'es_correcta': es_correcta,
                    'puntos': puntos
                }

                respuestas.append(respuesta_completa)

            # 5. Determinar posición actual en el ranking
            posicion_actual = 0
            for i, participante in enumerate(ranking_completo, 1):
                if participante['id'] == historial_id:
                    posicion_actual = i
                    break
            print(f"   - Posición en ranking: {posicion_actual}")

            # 6. Calcular estadísticas
            total_respuestas = len(respuestas)
            if total_respuestas > 0:
                porcentaje = round((correctas / total_respuestas) * 100, 1)
                tiempo_promedio = round(tiempo_total_respuestas / total_respuestas, 1)
            else:
                porcentaje = 0
                tiempo_promedio = 0

            print(f"\n✅ Estadísticas calculadas:")
            print(f"   - Correctas: {correctas}")
            print(f"   - Incorrectas: {incorrectas}")
            print(f"   - Porcentaje: {porcentaje}%")
            print(f"   - Tiempo promedio: {tiempo_promedio}s")

            # 7. Formatear fecha
            try:
                fecha_realizacion_peru = convertir_a_hora_peru(historial['fecha_realizacion'])
                fecha_realizacion_str = fecha_realizacion_peru.strftime('%d/%m/%Y a las %H:%M')
            except Exception as e:
                print(f"⚠️ Error al formatear fecha: {e}")
                fecha_realizacion_str = "Fecha no disponible"

            print(f"\n✅ Todo listo para renderizar\n{'='*70}")

    except Exception as e:
        print(f"\n❌❌❌ ERROR CRÍTICO ❌❌❌")
        print(f"Tipo: {type(e).__name__}")
        print(f"Mensaje: {str(e)}")
        import traceback
        traceback.print_exc()

        flash("❌ Error al cargar los resultados.", "error")
        return redirect(url_for("dashboard_estudiante"))
    finally:
        if conexion and conexion.open:
            conexion.close()

    recompensas = session.pop('recompensas_recientes', None)
    return render_template("resultados_individual_con_ranking.html",
                           historial=historial,
                           respuestas=respuestas,
                           correctas=correctas,
                           incorrectas=incorrectas,
                           porcentaje=porcentaje,
                           tiempo_promedio=tiempo_promedio,
                           fecha_realizacion_str=fecha_realizacion_str,
                           ranking_completo=ranking_completo,
                           posicion_actual=posicion_actual,
                           recompensas=recompensas)

# ==================== SISTEMA DE RECOMPENSAS ====================

def inicializar_stats_estudiante(user_id):
    """Crea el registro de estadísticas para un nuevo estudiante"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # ✅ CORREGIDO: Usar 'user_id'
            cursor.execute("""
                INSERT INTO estudiantes_stats (user_id)
                VALUES (%s)
                ON DUPLICATE KEY UPDATE user_id=user_id
            """, (user_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def calcular_xp_necesaria(nivel):
    """Calcula XP necesaria para el siguiente nivel (escala progresiva)"""
    return 100 * nivel + (nivel - 1) * 50

def otorgar_xp(user_id, xp_ganada):
    """Otorga XP al estudiante y verifica si sube de nivel"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Obtener stats actuales
            # ✅ CORREGIDO: Usar 'user_id'
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

            # Verificar subidas de nivel
            while True:
                xp_necesaria = calcular_xp_necesaria(nivel_actual)
                if nuevo_xp_actual >= xp_necesaria:
                    nivel_actual += 1
                    nuevo_xp_actual -= xp_necesaria
                    niveles_subidos.append(nivel_actual)
                else:
                    break

            # Actualizar stats
            # ✅ CORREGIDO: Usar 'user_id'
            cursor.execute("""
                UPDATE estudiantes_stats
                SET experiencia_actual = %s,
                    experiencia_total = %s,
                    nivel = %s
                WHERE user_id = %s
            """, (nuevo_xp_actual, nuevo_xp_total, nivel_actual, user_id))
            conexion.commit()

            return {
                'niveles_subidos': niveles_subidos,
                'xp_ganada': xp_ganada,
                'nivel_actual': nivel_actual,
                'xp_actual': nuevo_xp_actual,
                'xp_necesaria': calcular_xp_necesaria(nivel_actual)
            }
    finally:
        if conexion and conexion.open:
            conexion.close()

def otorgar_monedas(user_id, monedas):
    """Otorga monedas al estudiante"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # ✅ CORREGIDO: Usar 'user_id'
            cursor.execute("""
                UPDATE estudiantes_stats
                SET monedas = monedas + %s
                WHERE user_id = %s
            """, (monedas, user_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def verificar_y_desbloquear_insignias(user_id):
    """Verifica y desbloquea insignias que el estudiante haya ganado"""
    conexion = obtener_conexion()
    insignias_desbloqueadas = []

    try:
        with conexion.cursor() as cursor:
            # Obtener stats del estudiante
            # ✅ CORREGIDO: Usar 'user_id'
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()

            if not stats:
                return []

            # Obtener insignias que aún no tiene
            # NOTA: La tabla estudiantes_insignias usa la columna usuario_id
            cursor.execute("""
                SELECT i.* FROM insignias i
                WHERE i.id NOT IN (
                    SELECT insignia_id FROM estudiantes_insignias WHERE usuario_id = %s
                )
            """, (user_id,))
            insignias_disponibles = cursor.fetchall()

            for insignia in insignias_disponibles:
                debe_desbloquear = False

                # Verificar requisitos según tipo
                if insignia['requisito_tipo'] == 'partidas':
                    if stats['total_partidas'] >= insignia['requisito_valor']:
                        debe_desbloquear = True

                elif insignia['requisito_tipo'] == 'nivel':
                    if stats['nivel'] >= insignia['requisito_valor']:
                        debe_desbloquear = True

                elif insignia['requisito_tipo'] == 'racha':
                    if stats['mejor_racha'] >= insignia['requisito_valor']:
                        debe_desbloquear = True

                elif insignia['requisito_tipo'] == 'puntaje':
                    if stats['mejor_puntaje'] >= insignia['requisito_valor']:
                        debe_desbloquear = True

                # Desbloquear si cumple requisitos
                if debe_desbloquear:
                    # NOTA: La tabla estudiantes_insignias usa la columna usuario_id
                    cursor.execute("""
                        INSERT INTO estudiantes_insignias (usuario_id, insignia_id)
                        VALUES (%s, %s)
                    """, (user_id, insignia['id']))

                    # Otorgar recompensas
                    if insignia['recompensa_xp'] > 0:
                        # ✅ CORREGIDO: Usar 'user_id'
                        cursor.execute("""
                            UPDATE estudiantes_stats
                            SET experiencia_total = experiencia_total + %s,
                                experiencia_actual = experiencia_actual + %s
                            WHERE user_id = %s
                        """, (insignia['recompensa_xp'], insignia['recompensa_xp'], user_id))

                    if insignia['recompensa_monedas'] > 0:
                        # ✅ CORREGIDO: Usar 'user_id'
                        cursor.execute("""
                            UPDATE estudiantes_stats
                            SET monedas = monedas + %s
                            WHERE user_id = %s
                        """, (insignia['recompensa_monedas'], user_id))

                    insignias_desbloqueadas.append(insignia)

            conexion.commit()

    finally:
        if conexion and conexion.open:
            conexion.close()

    return insignias_desbloqueadas

def actualizar_stats_despues_partida(user_id, puntuacion, correctas, incorrectas):
    """Actualiza las estadísticas del estudiante después de una partida"""
    from datetime import datetime, date

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Inicializar stats si no existen
            # ✅ CORREGIDO: Usar 'user_id'
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()

            if not stats:
                inicializar_stats_estudiante(user_id)
                cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
                stats = cursor.fetchone()

            # Calcular nueva racha
            hoy = date.today()
            if stats['ultima_partida']:
                diferencia = (hoy - stats['ultima_partida']).days
                if diferencia == 1:
                    nueva_racha = stats['racha_actual'] + 1
                elif diferencia == 0:
                    nueva_racha = stats['racha_actual']
                else:
                    nueva_racha = 1
            else:
                nueva_racha = 1

            mejor_racha = max(stats['mejor_racha'], nueva_racha)
            mejor_puntaje = max(stats['mejor_puntaje'], puntuacion)

            # Actualizar stats
            # ✅ CORREGIDO: Usar 'user_id'
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

            # Calcular XP basada en rendimiento
            xp_base = 50  # XP base por completar
            xp_por_correcta = 10
            xp_bonus_perfecto = 100 if correctas > 0 and incorrectas == 0 else 0

            total_xp = xp_base + (correctas * xp_por_correcta) + xp_bonus_perfecto

            # Otorgar XP y monedas
            resultado_xp = otorgar_xp(user_id, total_xp)
            monedas_ganadas = 5 + (correctas * 2)
            otorgar_monedas(user_id, monedas_ganadas)

            # Verificar insignias
            insignias_nuevas = verificar_y_desbloquear_insignias(user_id)

            return {
                'xp_info': resultado_xp,
                'monedas_ganadas': monedas_ganadas,
                'insignias_nuevas': insignias_nuevas,
                'racha_actual': nueva_racha,
                'es_mejor_puntaje': puntuacion == mejor_puntaje and puntuacion > stats['mejor_puntaje']
            }

    finally:
        if conexion and conexion.open:
            conexion.close()

# Ruta para ver el perfil de recompensas
@app.route("/perfil_recompensas")
def perfil_recompensas():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            # Obtener stats
            # ✅ CORREGIDO: Usar 'user_id'
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()

            if not stats:
                inicializar_stats_estudiante(user_id)
                cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
                stats = cursor.fetchone()

            # ✅ ROBUSTEZ: Asegurar que stats no es None
            if not stats:
                flash("❌ Error al cargar tu perfil. Inténtalo de nuevo.", "error")
                return redirect(url_for("dashboard_estudiante"))

            # Obtener insignias desbloqueadas
            # NOTA: La tabla estudiantes_insignias usa la columna usuario_id
            cursor.execute("""
                SELECT i.*, ei.fecha_desbloqueo
                FROM estudiantes_insignias ei
                JOIN insignias i ON ei.insignia_id = i.id
                WHERE ei.usuario_id = %s
                ORDER BY ei.fecha_desbloqueo DESC
            """, (user_id,))
            insignias_desbloqueadas = cursor.fetchall()

            # Obtener todas las insignias para mostrar progreso
            cursor.execute("SELECT * FROM insignias ORDER BY requisito_valor ASC")
            todas_insignias = cursor.fetchall()

            # Calcular progreso del nivel
            xp_necesaria = calcular_xp_necesaria(stats['nivel'])
            progreso_nivel = (stats['experiencia_actual'] / xp_necesaria) * 100

    finally:
        if conexion and conexion.open:
            conexion.close()

    return render_template("perfil_recompensas.html",
                         stats=stats,
                         insignias_desbloqueadas=insignias_desbloqueadas,
                         todas_insignias=todas_insignias,
                         progreso_nivel=progreso_nivel,
                         xp_necesaria=xp_necesaria)

# ==================== TIENDA DE RECOMPENSAS ====================

@app.route("/tienda")
def tienda():
    """Muestra la tienda de items"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            # Obtener stats del estudiante (para mostrar monedas y nivel)
            # ✅ CORREGIDO: Usar 'user_id'
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()

            if not stats:
                inicializar_stats_estudiante(user_id)
                cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
                stats = cursor.fetchone()

            # ✅ ROBUSTEZ: Asegurar que stats no es None
            if not stats:
                stats = {'nivel': 1, 'monedas': 0}


            # Obtener items de la tienda
            cursor.execute("""
                SELECT * FROM tienda_items
                WHERE disponible = 1
                ORDER BY requisito_nivel ASC, precio ASC
            """)
            items_tienda = cursor.fetchall()

            # Obtener items que el usuario ya compró
            # NOTA: La tabla estudiantes_items usa la columna usuario_id
            cursor.execute("""
                SELECT item_id FROM estudiantes_items
                WHERE usuario_id = %s
            """, (user_id,))
            items_comprados_ids = [item['item_id'] for item in cursor.fetchall()]

            # Marcar items como comprados
            for item in items_tienda:
                item['comprado'] = item['id'] in items_comprados_ids
                item['puede_comprar'] = (
                    stats['monedas'] >= item['precio'] and
                    stats['nivel'] >= item['requisito_nivel'] and
                    not item['comprado']
                )

    finally:
        if conexion and conexion.open:
            conexion.close()

    return render_template("tienda.html",
                         stats=stats,
                         items=items_tienda,
                         nombre=session["usuario"])


@app.route("/api/comprar_item/<int:item_id>", methods=["POST"])
def comprar_item(item_id):
    """Compra un item de la tienda"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    user_id = session["user_id"]
    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            # Obtener stats del estudiante
            # ✅ CORREGIDO: Usar 'user_id'
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()

            # Obtener info del item
            cursor.execute("SELECT * FROM tienda_items WHERE id = %s AND disponible = 1", (item_id,))
            item = cursor.fetchone()

            if not item:
                return jsonify({"success": False, "message": "Item no disponible"}), 404

            # Verificar si ya lo compró
            # NOTA: La tabla estudiantes_items usa la columna usuario_id
            cursor.execute("""
                SELECT id FROM estudiantes_items
                WHERE usuario_id = %s AND item_id = %s
            """, (user_id, item_id))

            if cursor.fetchone():
                return jsonify({"success": False, "message": "Ya tienes este item"}), 400

            # Verificar requisitos
            if stats['monedas'] < item['precio']:
                return jsonify({
                    "success": False,
                    "message": f"Necesitas {item['precio']} monedas (tienes {stats['monedas']})"
                }), 400

            if stats['nivel'] < item['requisito_nivel']:
                return jsonify({
                    "success": False,
                    "message": f"Necesitas nivel {item['requisito_nivel']} (eres nivel {stats['nivel']})"
                }), 400

            # Realizar la compra
            # NOTA: La tabla estudiantes_items usa la columna usuario_id
            cursor.execute("""
                INSERT INTO estudiantes_items (usuario_id, item_id)
                VALUES (%s, %s)
            """, (user_id, item_id))

            # Descontar monedas
            # ✅ CORREGIDO: Usar 'user_id'
            cursor.execute("""
                UPDATE estudiantes_stats
                SET monedas = monedas - %s
                WHERE user_id = %s
            """, (item['precio'], user_id))

            conexion.commit()

            return jsonify({
                "success": True,
                "message": f"¡Compraste {item['nombre']}!",
                "monedas_restantes": stats['monedas'] - item['precio']
            })

    except Exception as e:
        print(f"❌ Error al comprar item: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/equipar_item/<int:item_id>", methods=["POST"])
def equipar_item(item_id):
    """Equipa un item comprado (avatar, marco, título)"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    user_id = session["user_id"]
    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            # Verificar que el item fue comprado
            # NOTA: La tabla estudiantes_items usa la columna usuario_id
            cursor.execute("""
                SELECT ei.*, ti.tipo
                FROM estudiantes_items ei
                JOIN tienda_items ti ON ei.item_id = ti.id
                WHERE ei.usuario_id = %s AND ei.item_id = %s
            """, (user_id, item_id))

            item_comprado = cursor.fetchone()

            if not item_comprado:
                return jsonify({"success": False, "message": "No tienes este item"}), 404

            tipo_item = item_comprado['tipo']

            # Desequipar todos los items del mismo tipo
            # NOTA: La tabla estudiantes_items usa la columna usuario_id
            cursor.execute("""
                UPDATE estudiantes_items ei
                JOIN tienda_items ti ON ei.item_id = ti.id
                SET ei.equipado = 0
                WHERE ei.usuario_id = %s AND ti.tipo = %s
            """, (user_id, tipo_item))

            # Equipar el nuevo item
            # NOTA: La tabla estudiantes_items usa la columna usuario_id
            cursor.execute("""
                UPDATE estudiantes_items
                SET equipado = 1
                WHERE usuario_id = %s AND item_id = %s
            """, (user_id, item_id))

            conexion.commit()

            return jsonify({"success": True, "message": "Item equipado correctamente"})

    except Exception as e:
        print(f"❌ Error al equipar item: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/mi_inventario")
def mi_inventario():
    """Muestra los items comprados del estudiante"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            # Obtener items comprados
            # NOTA: La tabla estudiantes_items usa la columna usuario_id
            cursor.execute("""
                SELECT ti.*, ei.equipado, ei.fecha_compra
                FROM estudiantes_items ei
                JOIN tienda_items ti ON ei.item_id = ti.id
                WHERE ei.usuario_id = %s
                ORDER BY ei.equipado DESC, ei.fecha_compra DESC
            """, (user_id,))

            items_comprados = cursor.fetchall()

            # Obtener stats
            # ✅ CORREGIDO: Usar 'user_id'
            cursor.execute("SELECT * FROM estudiantes_stats WHERE user_id = %s", (user_id,))
            stats = cursor.fetchone()

    finally:
        if conexion and conexion.open:
            conexion.close()

    return render_template("inventario.html",
                         items=items_comprados,
                         stats=stats,
                         nombre=session["usuario"])

@app.route("/descargar_plantilla_preguntas")
def descargar_plantilla_preguntas():
    """Descarga una plantilla Excel vacía para importar preguntas"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        import pandas as pd
        from io import BytesIO
        from flask import send_file

        # Crear DataFrame con la estructura de la plantilla
        plantilla_data = {
            'Pregunta': [
                '¿Cuál es la capital de Francia?',
                '¿Cuánto es 2+2?',
                '(Agrega más preguntas siguiendo este formato)'
            ],
            'Opcion_A': ['París', '3', ''],
            'Opcion_B': ['Londres', '4', ''],
            'Opcion_C': ['Madrid', '5', ''],
            'Opcion_D': ['Roma', '6', ''],
            'Respuesta_Correcta': ['A', 'B', '']
        }

        df = pd.DataFrame(plantilla_data)

        # Crear archivo Excel en memoria
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Preguntas', index=False)

            # Ajustar anchos de columna
            worksheet = writer.sheets['Preguntas']
            worksheet.column_dimensions['A'].width = 50
            worksheet.column_dimensions['B'].width = 30
            worksheet.column_dimensions['C'].width = 30
            worksheet.column_dimensions['D'].width = 30
            worksheet.column_dimensions['E'].width = 30
            worksheet.column_dimensions['F'].width = 20

        output.seek(0)

        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='Plantilla_Preguntas_Cuestionario.xlsx'
        )

    except Exception as e:
        flash(f"❌ Error al generar plantilla: {str(e)}", "error")
        print(f"Error en descargar_plantilla_preguntas: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for("dashboard_profesor"))


@app.route("/importar_preguntas/<int:cuestionario_id>", methods=["GET", "POST"])
def importar_preguntas(cuestionario_id):
    """Importa preguntas desde un archivo Excel"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    if request.method == "GET":
        # Mostrar página de importación
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM cuestionarios
                    WHERE id = %s AND profesor_id = %s
                """, (cuestionario_id, session["user_id"]))
                cuestionario = cursor.fetchone()

                if not cuestionario:
                    flash("❌ Cuestionario no encontrado", "error")
                    return redirect(url_for("dashboard_profesor"))

                return render_template("importar_preguntas.html",
                                     cuestionario=cuestionario)
        finally:
            if conexion and conexion.open:
                conexion.close()

    # POST: Procesar archivo Excel
    try:
        import pandas as pd

        # Verificar que se subió un archivo
        if 'archivo_excel' not in request.files:
            flash("❌ No se seleccionó ningún archivo", "error")
            return redirect(url_for("importar_preguntas", cuestionario_id=cuestionario_id))

        archivo = request.files['archivo_excel']

        if archivo.filename == '':
            flash("❌ No se seleccionó ningún archivo", "error")
            return redirect(url_for("importar_preguntas", cuestionario_id=cuestionario_id))

        # Verificar extensión
        if not archivo.filename.endswith(('.xlsx', '.xls')):
            flash("❌ El archivo debe ser un Excel (.xlsx o .xls)", "error")
            return redirect(url_for("importar_preguntas", cuestionario_id=cuestionario_id))

        # Leer el archivo Excel
        df = pd.read_excel(archivo)

        # Validar columnas requeridas
        columnas_requeridas = ['Pregunta', 'Opcion_A', 'Opcion_B', 'Opcion_C',
                              'Opcion_D', 'Respuesta_Correcta']

        columnas_faltantes = [col for col in columnas_requeridas if col not in df.columns]
        if columnas_faltantes:
            flash(f"❌ Faltan columnas en el Excel: {', '.join(columnas_faltantes)}", "error")
            return redirect(url_for("importar_preguntas", cuestionario_id=cuestionario_id))

        # Limpiar datos vacíos
        df = df.dropna(subset=['Pregunta'])

        if len(df) == 0:
            flash("❌ El archivo no contiene preguntas válidas", "error")
            return redirect(url_for("importar_preguntas", cuestionario_id=cuestionario_id))

        # Validar respuestas correctas
        respuestas_validas = ['A', 'B', 'C', 'D']
        for idx, row in df.iterrows():
            respuesta = str(row['Respuesta_Correcta']).strip().upper()
            if respuesta not in respuestas_validas:
                flash(f"❌ Error en fila {idx + 2}: Respuesta correcta debe ser A, B, C o D (encontrado: {respuesta})", "error")
                return redirect(url_for("importar_preguntas", cuestionario_id=cuestionario_id))

        # Guardar preguntas en la base de datos
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # Verificar que el cuestionario pertenece al profesor
                cursor.execute("""
                    SELECT num_preguntas FROM cuestionarios
                    WHERE id = %s AND profesor_id = %s
                """, (cuestionario_id, session["user_id"]))

                cuestionario = cursor.fetchone()
                if not cuestionario:
                    flash("❌ Cuestionario no encontrado", "error")
                    return redirect(url_for("dashboard_profesor"))

                # Verificar que el número de preguntas coincide
                if len(df) != cuestionario['num_preguntas']:
                    flash(f"⚠️ El cuestionario requiere {cuestionario['num_preguntas']} preguntas, pero el Excel contiene {len(df)}. Se importarán las primeras {cuestionario['num_preguntas']}.", "warning")

                # Limitar al número de preguntas del cuestionario
                df = df.head(cuestionario['num_preguntas'])

                # Eliminar preguntas existentes
                cursor.execute("""
                    DELETE FROM preguntas WHERE cuestionario_id = %s
                """, (cuestionario_id,))

                # Insertar nuevas preguntas
                for idx, row in df.iterrows():
                    sql = """
                        INSERT INTO preguntas
                        (cuestionario_id, pregunta, opcion_a, opcion_b, opcion_c,
                         opcion_d, respuesta_correcta, orden)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    cursor.execute(sql, (
                        cuestionario_id,
                        str(row['Pregunta']).strip(),
                        str(row['Opcion_A']).strip(),
                        str(row['Opcion_B']).strip(),
                        str(row['Opcion_C']).strip(),
                        str(row['Opcion_D']).strip(),
                        str(row['Respuesta_Correcta']).strip().upper(),
                        idx + 1
                    ))

                conexion.commit()

                flash(f"✅ Se importaron {len(df)} preguntas exitosamente", "success")
                return redirect(url_for("dashboard_profesor"))

        finally:
            if conexion and conexion.open:
                conexion.close()

    except Exception as e:
        flash(f"❌ Error al procesar el archivo: {str(e)}", "error")
        print(f"Error en importar_preguntas: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for("importar_preguntas", cuestionario_id=cuestionario_id))

@app.route("/crear_cuestionario_desde_excel", methods=["POST"])
def crear_cuestionario_desde_excel():
    """Crea un cuestionario completo importando preguntas desde Excel"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        import pandas as pd

        # Obtener datos del formulario
        titulo = request.form.get('titulo')
        descripcion = request.form.get('descripcion')
        modo_juego = request.form.get('modo_juego')
        tiempo_pregunta = int(request.form.get('tiempo_pregunta'))

        # Verificar que se subió un archivo
        if 'archivo_excel' not in request.files:
            flash("❌ No se seleccionó ningún archivo", "error")
            return redirect(url_for("dashboard_profesor"))

        archivo = request.files['archivo_excel']

        if archivo.filename == '':
            flash("❌ No se seleccionó ningún archivo", "error")
            return redirect(url_for("dashboard_profesor"))

        # Verificar extensión
        if not archivo.filename.endswith(('.xlsx', '.xls')):
            flash("❌ El archivo debe ser un Excel (.xlsx o .xls)", "error")
            return redirect(url_for("dashboard_profesor"))

        # Leer el archivo Excel
        df = pd.read_excel(archivo)

        # Validar columnas requeridas
        columnas_requeridas = ['Pregunta', 'Opcion_A', 'Opcion_B', 'Opcion_C',
                              'Opcion_D', 'Respuesta_Correcta']

        columnas_faltantes = [col for col in columnas_requeridas if col not in df.columns]
        if columnas_faltantes:
            flash(f"❌ Faltan columnas en el Excel: {', '.join(columnas_faltantes)}", "error")
            return redirect(url_for("dashboard_profesor"))

        # Limpiar datos vacíos
        df = df.dropna(subset=['Pregunta'])

        if len(df) == 0:
            flash("❌ El archivo no contiene preguntas válidas", "error")
            return redirect(url_for("dashboard_profesor"))

        # Validar respuestas correctas
        respuestas_validas = ['A', 'B', 'C', 'D']
        for idx, row in df.iterrows():
            respuesta = str(row['Respuesta_Correcta']).strip().upper()
            if respuesta not in respuestas_validas:
                flash(f"❌ Error en fila {idx + 2}: Respuesta correcta debe ser A, B, C o D (encontrado: {respuesta})", "error")
                return redirect(url_for("dashboard_profesor"))

        # El número de preguntas se determina por el Excel
        num_preguntas = len(df)

        # Generar PIN único
        codigo_pin = generar_pin()
        profesor_id = session["user_id"]

        # Crear el cuestionario en la base de datos
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # Insertar cuestionario
                sql_cuestionario = """
                    INSERT INTO cuestionarios
                    (titulo, descripcion, modo_juego, tiempo_pregunta, num_preguntas, codigo_pin, profesor_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql_cuestionario, (
                    titulo, descripcion, modo_juego, tiempo_pregunta,
                    num_preguntas, codigo_pin, profesor_id
                ))

                cuestionario_id = cursor.lastrowid

                # Insertar todas las preguntas
                for idx, row in df.iterrows():
                    sql_pregunta = """
                        INSERT INTO preguntas
                        (cuestionario_id, pregunta, opcion_a, opcion_b, opcion_c,
                         opcion_d, respuesta_correcta, orden)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    cursor.execute(sql_pregunta, (
                        cuestionario_id,
                        str(row['Pregunta']).strip(),
                        str(row['Opcion_A']).strip(),
                        str(row['Opcion_B']).strip(),
                        str(row['Opcion_C']).strip(),
                        str(row['Opcion_D']).strip(),
                        str(row['Respuesta_Correcta']).strip().upper(),
                        idx + 1
                    ))

                conexion.commit()

                flash(f"✅ Cuestionario '{titulo}' creado exitosamente con {num_preguntas} preguntas importadas desde Excel", "success")
                return redirect(url_for("dashboard_profesor"))

        finally:
            if conexion and conexion.open:
                conexion.close()

    except ImportError:
        flash("❌ Error: Necesitas instalar pandas. Ejecuta: pip install pandas openpyxl", "error")
        return redirect(url_for("dashboard_profesor"))
    except Exception as e:
        flash(f"❌ Error al crear cuestionario desde Excel: {str(e)}", "error")
        print(f"Error en crear_cuestionario_desde_excel: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for("dashboard_profesor"))

@app.template_filter('hora_peru')
def hora_peru_filter(fecha_utc):
    """Filtro para convertir fechas a hora de Perú"""
    if fecha_utc is None:
        return "Fecha no disponible"

    PERU_TZ = pytz.timezone('America/Lima')

    # Si la fecha no tiene timezone, asumimos que es UTC
    if fecha_utc.tzinfo is None:
        fecha_utc = pytz.utc.localize(fecha_utc)

    # Convertir a hora de Perú
    fecha_peru = fecha_utc.astimezone(PERU_TZ)
    return fecha_peru.strftime('%d/%m/%Y %H:%M')
@app.route("/api/verificar_sincronizacion_individual/<sesion_id>/<int:pregunta_index>")
def api_verificar_sincronizacion_individual(sesion_id, pregunta_index):
    """API para que los estudiantes verifiquen si todos están listos"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        todos_listos = verificar_todos_listos_individual(sesion_id, pregunta_index)

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # Contar cuántos están listos
                cursor.execute("""
                    SELECT COUNT(*) as listos
                    FROM salas_espera
                    WHERE sesion_id = %s
                    AND pregunta_actual >= %s
                    AND listo_para_siguiente = TRUE
                """, (sesion_id, pregunta_index))
                listos = cursor.fetchone()['listos']

                cursor.execute("""
                    SELECT COUNT(*) as total
                    FROM salas_espera
                    WHERE sesion_id = %s
                """, (sesion_id,))
                total = cursor.fetchone()['total']

                return jsonify({
                    "todos_listos": todos_listos,
                    "listos": listos,
                    "total": total
                })
        finally:
            if conexion and conexion.open:
                conexion.close()

    except Exception as e:
        print(f"❌ Error en verificar sincronización: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/verificar_sincronizacion_grupal/<int:grupo_id>/<int:pregunta_index>")
def api_verificar_sincronizacion_grupal(grupo_id, pregunta_index):
    """API para que los miembros del grupo verifiquen si todos están listos"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        todos_listos = verificar_todos_listos_grupal(grupo_id, pregunta_index)

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(DISTINCT usuario_id) as respondidos
                    FROM progreso_grupal
                    WHERE grupo_id = %s
                    AND pregunta_index = %s
                    AND respondio = TRUE
                """, (grupo_id, pregunta_index))
                respondidos = cursor.fetchone()['respondidos']

                cursor.execute("""
                    SELECT COUNT(*) as total
                    FROM usuarios
                    WHERE grupo_id = %s
                """, (grupo_id,))
                total = cursor.fetchone()['total']

                return jsonify({
                    "todos_listos": todos_listos,
                    "respondidos": respondidos,
                    "total": total
                })
        finally:
            if conexion and conexion.open:
                conexion.close()

    except Exception as e:
        print(f"❌ Error en verificar sincronización grupal: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


# ==================== LOGIN FACIAL ====================

@app.route("/login_facial")
def login_facial():
    """Muestra la página de login con reconocimiento facial"""
    return render_template("login_facial.html")


@app.route("/verificar_rostro_login", methods=["POST"])
def verificar_rostro_login():
    try:
        data = request.get_json()
        embedding_capturado = data.get('embedding')

        if not embedding_capturado or len(embedding_capturado) != 128:
            return jsonify({
                "success": False,
                "message": "Datos de rostro inválidos"
            }), 400

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # CORRECCIÓN CRÍTICA: Leer la codificacion_facial de la tabla usuarios
                cursor.execute("""
                    SELECT id as usuario_id, codificacion_facial as embedding, nombre, correo, rol, verificado
                    FROM usuarios
                    WHERE codificacion_facial IS NOT NULL
                """)

                usuarios_registrados = cursor.fetchall()

                if not usuarios_registrados:
                    return jsonify({
                        "success": False,
                        "message": "No hay usuarios con reconocimiento facial registrado"
                    }), 404

                # (La lógica de distancia euclidiana sigue igual)
                mejor_coincidencia = None
                mejor_similitud = float('inf')
                umbral_similitud = 0.6

                for usuario in usuarios_registrados:
                    # El campo 'embedding' (codificacion_facial) está en formato JSON
                    embedding_db = json.loads(usuario['embedding'])

                    # Calcular distancia euclidiana
                    distancia = sum((a - b) ** 2 for a, b in zip(embedding_capturado, embedding_db)) ** 0.5

                    if distancia < mejor_similitud:
                        mejor_similitud = distancia
                        mejor_coincidencia = usuario

                # Verificar si la similitud es suficiente
                if mejor_coincidencia and mejor_similitud < umbral_similitud:
                    if not mejor_coincidencia['verificado']:
                        return jsonify({
                            "success": False,
                            "message": "Tu cuenta aún no está verificada. Revisa tu correo."
                        }), 403

                    # Login exitoso - crear sesión
                    session.permanent = True
                    session['usuario'] = mejor_coincidencia['nombre']
                    session['correo'] = mejor_coincidencia['correo']
                    session['rol'] = mejor_coincidencia['rol']
                    session['user_id'] = mejor_coincidencia['usuario_id']

                    print(f"✅ Login facial exitoso: {mejor_coincidencia['nombre']} ({mejor_coincidencia['rol']})")

                    return jsonify({
                        "success": True,
                        "message": "Identidad verificada correctamente",
                        "rol": mejor_coincidencia['rol']
                    })
                else:
                    return jsonify({
                        "success": False,
                        "message": "No se pudo verificar tu identidad. Intenta con login normal."
                    }), 401

        finally:
            if conexion and conexion.open:
                conexion.close()

    except Exception as e:
        print(f"❌ Error en verificar_rostro_login: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": f"Error del servidor: {str(e)}"
        }), 500

# ===== API PARA ESTADO DEL PROFESOR (SINCRONIZACIÓN) =====
@app.route("/api/estado_pregunta_profesor/<sesion_id>")
def api_estado_pregunta_profesor(sesion_id):
    """API para que los estudiantes consulten en qué pregunta está el profesor"""
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
                # Si no existe, crearlo
                cursor.execute("""
                    INSERT INTO control_sesiones (sesion_id, pregunta_actual, estado, tiempo_restante)
                    VALUES (%s, 0, 'playing', 0)
                """, (sesion_id,))
                conexion.commit()
                return jsonify({
                    "pregunta_actual": 0,
                    "estado": "playing",
                    "tiempo_restante": 0
                })

            return jsonify({
                "pregunta_actual": estado['pregunta_actual'],
                "estado": estado['estado'],
                "tiempo_restante": estado['tiempo_restante']
            })

    except Exception as e:
        print(f"❌ Error en api_estado_pregunta_profesor: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conexion and conexion.open:
            conexion.close()


@app.route("/api/actualizar_pregunta_profesor/<sesion_id>", methods=["POST"])
def api_actualizar_pregunta_profesor(sesion_id):
    """API para que el profesor actualice la pregunta actual de la sesión"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        data = request.get_json()
        nueva_pregunta = data.get('pregunta_actual')
        nuevo_estado = data.get('estado', 'playing')
        tiempo_restante = data.get('tiempo_restante', 0)

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # Actualizar o insertar estado
                cursor.execute("""
                    INSERT INTO control_sesiones (sesion_id, pregunta_actual, estado, tiempo_restante, ultima_actualizacion)
                    VALUES (%s, %s, %s, %s, NOW())
                    ON DUPLICATE KEY UPDATE
                        pregunta_actual = %s,
                        estado = %s,
                        tiempo_restante = %s,
                        ultima_actualizacion = NOW()
                """, (sesion_id, nueva_pregunta, nuevo_estado, tiempo_restante,
                      nueva_pregunta, nuevo_estado, tiempo_restante))
                conexion.commit()

                return jsonify({"success": True})
        finally:
            if conexion and conexion.open:
                conexion.close()

    except Exception as e:
        print(f"❌ Error en api_actualizar_pregunta_profesor: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

# --- REGISTRO FACIAL ---
@app.route("/registro_facial")
def registro_facial():
    if "usuario" not in session:
        return redirect(url_for("login"))

    rol = session.get("rol")
    return render_template("registro_facial.html", rol=rol)

@app.route("/guardar_embedding_facial", methods=["POST"])
def guardar_embedding_facial():
    if "usuario" not in session:
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        data = request.get_json()
        embedding = data.get('embedding')

        if not embedding or len(embedding) != 128:
            return jsonify({"success": False, "message": "Embedding inválido"}), 400

        user_id = session["user_id"]
        embedding_json = json.dumps(embedding)

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # CORRECCIÓN CRÍTICA: Actualizar la columna codificacion_facial en la tabla usuarios
                cursor.execute("""
                    UPDATE usuarios
                    SET codificacion_facial = %s
                    WHERE id = %s
                """, (embedding_json, user_id))
                conexion.commit()

                return jsonify({
                    "success": True,
                    "message": "✅ Reconocimiento facial registrado exitosamente"
                })
        finally:
            if conexion and conexion.open:
                conexion.close()

    except Exception as e:
        print(f"❌ Error en guardar_embedding_facial: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


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
@token_requerido
def api_obtener_reconocimiento_facial(usuario_id, rol):
    """GET: Obtiene todos los registros de reconocimiento facial"""
    conexion = None
    try:
        conexion = obtener_conexion()
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
                    r['fecha_registro'] = r['fecha_registro'].strftime('%Y-%m-%d %H:%M:%S')
                r['tiene_embedding'] = True

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
@token_requerido
def api_obtener_reconocimiento_facial_por_id(usuario_id, rol, reconocimiento_id):
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
@token_requerido
def api_registrar_reconocimiento_facial(usuario_id, rol):
    """POST: Registra un embedding facial"""
    try:
        data = request.get_json()

        # Validaciones
        if not data.get('usuario_id') or not data.get('embedding'):
            return jsonify({
                "success": False,
                "message": "usuario_id y embedding son requeridos"
            }), 400

        # Verificar que el usuario solo pueda registrar su propio embedding (o ser profesor)
        if rol != 'profesor' and data.get('usuario_id') != usuario_id:
            return jsonify({
                "success": False,
                "message": "No puedes registrar el embedding de otro usuario"
            }), 403

        # Validar que el embedding tenga 128 dimensiones
        if len(data.get('embedding')) != 128:
            return jsonify({
                "success": False,
                "message": "El embedding debe tener 128 dimensiones"
            }), 400

        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT id FROM reconocimiento_facial WHERE usuario_id = %s
            """, (data.get('usuario_id'),))

            existing = cursor.fetchone()

            embedding_json = json.dumps(data.get('embedding'))

            if existing:
                cursor.execute("""
                    UPDATE reconocimiento_facial
                    SET embedding = %s, fecha_registro = NOW()
                    WHERE usuario_id = %s
                """, (embedding_json, data.get('usuario_id')))
                registro_id = existing['id']
                mensaje = "Reconocimiento facial actualizado exitosamente"
            else:
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
@token_requerido
def api_actualizar_reconocimiento_facial(usuario_id, rol, reconocimiento_id):
    """PUT: Actualiza un registro de reconocimiento facial"""
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
            cursor.execute("SELECT usuario_id FROM reconocimiento_facial WHERE id = %s", (reconocimiento_id,))
            registro = cursor.fetchone()

            if not registro:
                return jsonify({
                    "success": False,
                    "message": "Registro no encontrado"
                }), 404

            # Verificar permisos
            if rol != 'profesor' and registro['usuario_id'] != usuario_id:
                return jsonify({
                    "success": False,
                    "message": "No tienes permisos para actualizar este registro"
                }), 403

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
@token_requerido
@rol_requerido(['profesor'])  # Solo profesores pueden eliminar
def api_eliminar_reconocimiento_facial(usuario_id, rol, reconocimiento_id):
    """DELETE: Elimina un registro de reconocimiento facial"""
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

# --- MANEJO DE ERRORES ---

@app.errorhandler(500)
def error_interno(error):
    print(f"Error 500: {error}")
    import traceback
    traceback.print_exc()
    return render_template("error.html"), 500

# ---------------- INICIAR APP ----------------
if __name__ == "__main__":
    app.run(debug=True, port=8080)