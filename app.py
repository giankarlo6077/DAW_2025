from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, make_response
from flask_mail import Mail, Message
import controlador_apis as controlador
import controlador_auth as auth_db
import controlador_estudiante as estu_db
import controlador_profesor as profe_db
import controlador_facial as facial_db
import controlador_juego as juego_db
import controlador_recompensas as recompensas_db
import random
import string
from functools import wraps
import re
import secrets
from datetime import datetime, timedelta, date
from io import BytesIO
import json
import pandas as pd
import traceback
import pytz
import hashlib
import jwt

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

def encriptar_password(password):
    """Encripta una contraseña usando SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def encriptar_dato_cookie(dato):
    """Crea un hash SHA256 de un dato (ID o Nombre) para usarlo como valor de cookie de validación"""
    return hashlib.sha256(str(dato).encode()).hexdigest()

def generar_codigo_verificacion():
    """Genera código de verificación de 6 dígitos"""
    return auth_db.generar_codigo_verificacion_simple()

def es_password_segura(password):
    """Valida que la contraseña sea segura"""
    return auth_db.validar_password_segura(password)

# ========== FUNCIONES Y DECORADORES JWT ==========

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
    @wraps(f)
    def decorador(*args, **kwargs):
        token = None

        # 1. Obtener token
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'success': False, 'mensaje': 'Formato inválido'}), 401
        elif 'token_jwt' in request.cookies:
            token = request.cookies.get('token_jwt')

        if not token:
            return jsonify({'success': False, 'mensaje': 'Token faltante'}), 401

        try:
            # 2. Decodificar
            datos = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            usuario_id = datos['usuario_id']
            rol = datos['rol']

            # 3. Verificar existencia USANDO EL CONTROLADOR CORRECTO
            usuario = auth_db.verificar_usuario_token(usuario_id)  # ✅ CORREGIDO

            if not usuario:
                return jsonify({'success': False, 'mensaje': 'Usuario no encontrado'}), 401

        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'mensaje': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'mensaje': 'Token inválido'}), 401
        except Exception as e:
            print(f"Error token: {e}")
            return jsonify({'success': False, 'mensaje': 'Error autenticación'}), 401

        return f(usuario_id, rol, *args, **kwargs)
    return decorador


def rol_requerido(roles_permitidos):
    def decorador_rol(f):
        @wraps(f)
        def wrapper(usuario_id, rol, *args, **kwargs):
            if rol not in roles_permitidos:
                return jsonify({'success': False, 'mensaje': 'No tienes permisos para esta acción'}), 403
            return f(usuario_id, rol, *args, **kwargs)
        return wrapper
    return decorador_rol


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


#----RUTAS CONTROLADOR AUTH ------------

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

        try:
            password_encriptada = encriptar_password(password)
            codigo = generar_codigo_verificacion()
            fecha_codigo = datetime.now()

            usuario_id = auth_db.registrar_usuario_pendiente(
                nombre, correo, password_encriptada, rol, codigo, fecha_codigo
            )

            if usuario_id is None:
                flash("❌ Ese correo ya está registrado.", "error")
                return render_template("registro.html", nombre=nombre, correo=correo, rol_seleccionado=rol)

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

    return render_template("registro.html")

@app.route("/verificar_cuenta", methods=["GET", "POST"])
def verificar_cuenta():
    if "temp_correo" not in session: return redirect(url_for("registro"))

    if request.method == "POST":
        codigo_ingresado = request.form["codigo"]

        try:
            # Llamada al CONTROLADOR
            usuario = auth_db.obtener_usuario_verificacion(session["temp_usuario_id"], codigo_ingresado)

            if not usuario:
                flash("❌ Código incorrecto.", "error")
                return redirect(url_for("verificar_cuenta"))

            # Verificar expiración (Lógica de negocio)
            if datetime.now() - usuario["fecha_codigo"] > timedelta(minutes=15):
                flash("❌ El código ha expirado. Solicita uno nuevo.", "error")
                return redirect(url_for("reenviar_codigo"))

            # Confirmar verificación en BD
            auth_db.marcar_usuario_como_verificado(session["temp_usuario_id"])

            # Crear sesión final
            session.permanent = True
            session["usuario"] = session["temp_nombre"]
            session["correo"] = session["temp_correo"]
            session["rol"] = session["temp_rol"]
            session["user_id"] = session["temp_usuario_id"]

            # Limpiar temporales
            for key in ["temp_usuario_id", "temp_correo", "temp_nombre", "temp_rol"]:
                session.pop(key, None)

            flash("✅ ¡Cuenta verificada exitosamente!", "success")
            return render_template("bienvenido.html", nombre=session["usuario"], rol=session["rol"])

        except Exception as e:
            print(f"Error verificando cuenta: {e}")
            flash("❌ Error interno al verificar.", "error")
            return redirect(url_for("verificar_cuenta"))

    return render_template("verificar_cuenta.html", correo=session["temp_correo"])

@app.route("/reenviar_codigo")
def reenviar_codigo():
    if "temp_usuario_id" not in session:
        flash("Tu sesión ha expirado. Por favor, intenta registrarte de nuevo.", "error")
        return redirect(url_for("registro"))

    try:
        codigo = generar_codigo_verificacion()
        fecha_codigo = datetime.now()

        # Llamada al CONTROLADOR
        auth_db.actualizar_codigo_verificacion(session["temp_usuario_id"], codigo, fecha_codigo)

        if enviar_correo_verificacion_mejorado(session["temp_correo"], codigo, session["temp_nombre"]):
            flash("✅ Se ha reenviado un nuevo código a tu correo.", "success")
        else:
            flash("❌ Hubo un error al reenviar el código.", "error")

    except Exception as e:
        print(f"Error reenviando código: {e}")
        flash("❌ Error al procesar la solicitud.", "error")

    return redirect(url_for("verificar_cuenta"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")

        if not correo or not password:
            flash("Por favor, ingresa tu correo y contraseña.", "warning")
            return render_template("iniciosesion.html")

        try:
            # Llamada al CONTROLADOR
            usuario = auth_db.buscar_usuario_por_correo(correo)

            # Encriptar password ingresada para comparación
            password_ingresada_encriptada = encriptar_password(password)

            if usuario and usuario["password"] == password_ingresada_encriptada:
                # 1. Crear la sesión Flask
                session.permanent = True
                session["user_id"] = usuario["id"]
                session["usuario"] = usuario["nombre"]
                session["rol"] = usuario["rol"]
                session["correo"] = usuario["correo"]

                # 2. Generar token JWT
                token = generar_token_jwt(usuario["id"], usuario["rol"])

                if usuario["rol"] == "profesor":
                    response = redirect(url_for("dashboard_profesor"))
                else:
                    response = redirect(url_for("dashboard_estudiante"))

                # 3. Cookies
                response = make_response(response)
                user_id_hash = encriptar_dato_cookie(usuario["id"])
                user_name_hash = encriptar_dato_cookie(usuario["nombre"])

                response.set_cookie('token_jwt', token, httponly=True, secure=False, samesite='Lax')
                response.set_cookie('user_id_enc', user_id_hash, httponly=True, secure=False, samesite='Lax')
                response.set_cookie('user_name_enc', user_name_hash, httponly=True, secure=False, samesite='Lax')

                flash(f"¡Bienvenido, {usuario['nombre']}!", "success")
                return response
            else:
                flash("Correo o contraseña incorrectos.", "danger")

        except Exception as e:
            print(f"Error login: {e}")
            flash("Error al iniciar sesión", "danger")

    return render_template("iniciosesion.html")

@app.route("/api/auth/token", methods=["POST"])
def obtener_token():
    """Endpoint para obtener un token JWT mediante credenciales"""
    try:
        data = request.get_json()
        correo = data.get('correo', '').strip().lower()
        password = data.get('password', '')

        if not correo or not password:
            return jsonify({'success': False, 'mensaje': 'Correo y contraseña son requeridos'}), 400

        # Llamada al CONTROLADOR
        usuario = auth_db.buscar_usuario_por_correo(correo)

        if not usuario or usuario['password'] != password:
            # NOTA: Aquí asumí que la password en DB ya estaba encriptada o que la API
            # manda la pass cruda. Si la API manda cruda, deberías encriptarla antes de comparar:
            # if not usuario or usuario['password'] != encriptar_password(password):
            return jsonify({'success': False, 'mensaje': 'Credenciales inválidas'}), 401

        token = generar_token_jwt(usuario['id'], usuario['rol'])

        if not token:
            return jsonify({'success': False, 'mensaje': 'Error generando token'}), 500

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
        return jsonify({'success': False, 'mensaje': f'Error del servidor: {str(e)}'}), 500

@app.route("/recuperar_password", methods=["GET", "POST"])
def recuperar_password():
    if request.method == "POST":
        correo = request.form["correo"]
        try:
            # Llamada al CONTROLADOR
            usuario = auth_db.buscar_usuario_por_correo(correo)

            if usuario:
                token = secrets.token_urlsafe(16)
                expiracion = datetime.now() + timedelta(hours=1)

                auth_db.guardar_token_recuperacion(usuario['id'], token, expiracion)
                enviar_correo_recuperacion(correo, token)

            flash("✅ Si tu correo está registrado, recibirás un enlace para restablecer tu contraseña.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            print(f"Error recuperar pass: {e}")
            flash("Error al procesar solicitud", "error")

    return render_template("recuperar_password.html")

@app.route("/resetear_password/<token>", methods=["GET", "POST"])
def resetear_password(token):
    try:
        # Llamada al CONTROLADOR
        usuario = auth_db.obtener_usuario_por_reset_token(token)

        if not usuario or datetime.now() > usuario['reset_token_expiration']:
            flash("❌ El enlace de recuperación es inválido o ha expirado.", "error")
            return redirect(url_for("login"))

        if request.method == "POST":
            password = request.form["password"]
            confirmar = request.form["confirmar"]

            if password != confirmar:
                flash("❌ Las nuevas contraseñas no coinciden.", "error")
                return render_template("resetear_password.html", token=token)

            es_segura, mensaje_error = es_password_segura(password)
            if not es_segura:
                flash(f"❌ {mensaje_error}", "error")
                return render_template("resetear_password.html", token=token)

            password_encriptada = encriptar_password(password)

            # Llamada al CONTROLADOR
            auth_db.actualizar_password_reseteada(usuario['id'], password_encriptada)

            flash("✅ Tu contraseña ha sido actualizada. Ya puedes iniciar sesión.", "success")
            return redirect(url_for("login"))

    except Exception as e:
        print(f"Error reset password: {e}")
        flash("Error al restablecer contraseña", "error")
        return redirect(url_for("login"))

    return render_template("resetear_password.html", token=token)

@app.route("/logout")
def logout():
    session.clear()
    response = redirect(url_for("login"))
    response = make_response(response)
    response.set_cookie('token_jwt', '', expires=0, httponly=True, secure=False, samesite='Lax')
    response.set_cookie('user_id_enc', '', expires=0, httponly=True, secure=False, samesite='Lax')
    response.set_cookie('user_name_enc', '', expires=0, httponly=True, secure=False, samesite='Lax')
    return response



# ========================================
# RUTAS DASHBOARD PROFESOR
# ========================================

@app.route("/dashboard_profesor")
def dashboard_profesor():
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR
        datos = profe_db.obtener_datos_dashboard(session["user_id"])

        return render_template("dashboard_profesor.html",
                               nombre=session["usuario"],
                               cuestionarios=datos["cuestionarios"],
                               total_cuestionarios=datos["total_cuestionarios"],
                               total_preguntas=datos["total_preguntas"])
    except Exception as e:
        print(f"Error dashboard: {e}")
        flash("Error cargando dashboard", "error")
        return redirect(url_for("login"))

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
        profesor_id = session["user_id"]

        # Llamada al CONTROLADOR
        cuestionario_id = profe_db.crear_nuevo_cuestionario(
            titulo, descripcion, modo_juego, tiempo_pregunta, num_preguntas, profesor_id
        )

        return redirect(url_for("agregar_preguntas", cuestionario_id=cuestionario_id))
    except Exception as e:
        flash(f"❌ Error al crear cuestionario: {str(e)}", "error")
        return redirect(url_for("dashboard_profesor"))

@app.route("/agregar_preguntas/<int:cuestionario_id>")
def agregar_preguntas(cuestionario_id):
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR (Validación de propiedad)
        cuestionario = profe_db.obtener_cuestionario_propio(cuestionario_id, session["user_id"])

        if not cuestionario:
            flash("❌ Cuestionario no encontrado o acceso denegado", "error")
            return redirect(url_for("dashboard_profesor"))

        return render_template("agregar_preguntas.html", cuestionario=cuestionario, preguntas=[])
    except Exception as e:
        flash("Error al cargar interfaz", "error")
        return redirect(url_for("dashboard_profesor"))

@app.route("/guardar_preguntas/<int:cuestionario_id>", methods=["POST"])
def guardar_preguntas(cuestionario_id):
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "Acceso denegado"}), 403
    try:
        data = request.get_json()
        preguntas = data.get("preguntas", [])

        # Llamada al CONTROLADOR
        profe_db.guardar_preguntas_batch(cuestionario_id, preguntas)

        return jsonify({"success": True, "message": "Preguntas guardadas correctamente"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

@app.route("/editar_cuestionario/<int:cuestionario_id>")
def editar_cuestionario(cuestionario_id):
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR
        datos = profe_db.obtener_datos_edicion(cuestionario_id, session["user_id"])

        if not datos["cuestionario"]:
            flash("❌ Cuestionario no encontrado", "error")
            return redirect(url_for("dashboard_profesor"))

        return render_template("editar_cuestionario.html",
                               cuestionario=datos["cuestionario"],
                               preguntas=datos["preguntas"])
    except Exception as e:
        flash(f"❌ Error al cargar el cuestionario: {str(e)}", "error")
        return redirect(url_for("dashboard_profesor"))

@app.route("/actualizar_cuestionario/<int:cuestionario_id>", methods=["POST"])
def actualizar_cuestionario(cuestionario_id):
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "Acceso denegado"}), 403
    try:
        data = request.get_json()

        # Llamada al CONTROLADOR
        profe_db.actualizar_cuestionario_completo(
            cuestionario_id,
            data['titulo'],
            data['descripcion'],
            data['modo_juego'],
            data['tiempo_pregunta'],
            data['preguntas']
        )

        return jsonify({"success": True, "message": "Cuestionario actualizado"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/eliminar_cuestionario/<int:cuestionario_id>", methods=["POST"])
def eliminar_cuestionario(cuestionario_id):
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "Acceso denegado"}), 403
    try:
        # Llamada al CONTROLADOR
        exito = profe_db.eliminar_cuestionario_cascada(cuestionario_id, session['user_id'])

        if exito:
            return jsonify({"success": True, "message": "Cuestionario eliminado"})
        else:
            return jsonify({"success": False, "message": "No se pudo eliminar o no eres el dueño"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# ========================================
# RUTAS PERFIL PROFESOR
# ========================================

@app.route("/cambiar_datos_profesor", methods=["GET", "POST"])
def cambiar_datos_profesor():
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    # Cargar correo si no está en sesión
    if 'correo' not in session and 'user_id' in session:
        correo = profe_db.obtener_correo_por_id(session["user_id"])
        if correo: session['correo'] = correo

    if request.method == "POST":
        nombre_nuevo = request.form["nombre"]
        password_actual = request.form["password_actual"]
        password_nueva = request.form.get("password_nueva", "")
        confirmar_nueva = request.form.get("confirmar_nueva", "")

        try:
            # 1. Obtener password real desde CONTROLADOR
            pass_db = profe_db.obtener_password_actual(session["user_id"])
            pass_actual_enc = encriptar_password(password_actual)

            if not pass_db or pass_db != pass_actual_enc:
                flash("❌ La contraseña actual es incorrecta", "error")
                return redirect(url_for("cambiar_datos_profesor"))

            password_nueva_enc = None
            if password_nueva:
                if password_nueva != confirmar_nueva:
                    flash("❌ Las contraseñas nuevas no coinciden", "error")
                    return redirect(url_for("cambiar_datos_profesor"))

                es_segura, msg = es_password_segura(password_nueva)
                if not es_segura:
                    flash(f"❌ {msg}", "error")
                    return redirect(url_for("cambiar_datos_profesor"))

                password_nueva_enc = encriptar_password(password_nueva)

            # 2. Actualizar en CONTROLADOR
            profe_db.actualizar_perfil(session["user_id"], nombre_nuevo, password_nueva_enc)

            session["usuario"] = nombre_nuevo
            flash("✅ Datos actualizados correctamente", "success")
            return redirect(url_for("dashboard_profesor"))

        except Exception as e:
            flash(f"Error al actualizar: {e}", "error")
            return redirect(url_for("cambiar_datos_profesor"))

    return render_template("CambiarDatos_profesor.html", nombre=session.get("usuario"), correo=session.get("correo"))

@app.route("/eliminar_cuenta_profesor", methods=["POST"])
def eliminar_cuenta_profesor():
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    password_actual = request.form.get("password_actual")
    user_id = session["user_id"]

    try:
        # 1. Validar contraseña
        pass_db = profe_db.obtener_password_actual(user_id)
        pass_actual_enc = encriptar_password(password_actual)

        if not pass_db or pass_db != pass_actual_enc:
            flash("❌ Contraseña incorrecta. No se pudo eliminar la cuenta.", "error")
            return redirect(url_for('cambiar_datos_profesor'))

        # 2. Eliminar todo en cascada vía CONTROLADOR
        profe_db.eliminar_cuenta_completa_profesor(user_id)

        session.clear()
        flash("✅ Tu cuenta y todos tus datos han sido eliminados permanentemente.", "success")
        return redirect(url_for('login'))

    except Exception as e:
        flash("❌ Ocurrió un error al intentar eliminar la cuenta.", "error")
        print(f"Error al eliminar cuenta: {e}")
        return redirect(url_for('cambiar_datos_profesor'))




# ========================================
# RUTAS DASHBOARD ESTUDIANTE
# ========================================

@app.route("/dashboard_estudiante")
def dashboard_estudiante():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    user_id = session.get("user_id")

    try:
        # --- 1. Información del Grupo ---
        grupo_info, miembros = estu_db.obtener_grupo_y_miembros(user_id)

        # --- 2. Historial Combinado ---
        cuestionarios_recientes = estu_db.obtener_historial_combinado(user_id)

        # --- 3. Estadísticas (Stats) ---
        stats = estu_db.obtener_stats_aseguradas(user_id)

        # --- 4. Items Equipados ---
        items_equipados = estu_db.obtener_items_equipados(user_id)

        # Logs de control (Opcional, puedes quitarlos para limpiar más)
        print(f"\n✅ Dashboard cargado para: {session['usuario']}")
        print(f"   - Grupo: {'Sí' if grupo_info else 'No'}")

        return render_template("dashboard_estudiante.html",
                               nombre=session["usuario"],
                               grupo=grupo_info,
                               miembros=miembros,
                               user_id=user_id,
                               cuestionarios_recientes=cuestionarios_recientes,
                               items_equipados=items_equipados,
                               stats=stats)

    except Exception as e:
        print(f"❌ Error crítico dashboard estudiante: {e}")
        flash("Error al cargar el panel de estudiante", "error")
        # Retornar template básico para no romper la app
        return render_template("dashboard_estudiante.html", nombre=session["usuario"], stats={})


@app.route("/crear_grupo", methods=["POST"])
def crear_grupo():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    nombre_grupo = request.form.get("nombre_grupo")
    user_id = session["user_id"]

    if not nombre_grupo:
        flash("❌ Debes darle un nombre a tu grupo.", "error")
        return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")

    try:
        # Llamada al CONTROLADOR
        exito, mensaje = estu_db.crear_nuevo_grupo(user_id, nombre_grupo)

        if exito:
            flash(f"✅ {mensaje}", "success")
        else:
            flash(f"❌ {mensaje}", "error")

    except Exception as e:
        print(f"Error crear_grupo: {e}")
        flash("❌ Error interno al crear grupo.", "error")

    return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")


@app.route("/unirse_grupo", methods=["POST"])
def unirse_grupo():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    codigo_grupo = request.form.get("codigo_grupo")
    user_id = session["user_id"]

    if not codigo_grupo:
        flash("❌ Debes ingresar un código de grupo.", "error")
        return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")

    try:
        # Llamada al CONTROLADOR
        exito, mensaje = estu_db.unirse_a_grupo_existente(user_id, codigo_grupo)

        if exito:
            flash(f"✅ {mensaje}", "success")
        else:
            flash(f"❌ {mensaje}", "error")

    except Exception as e:
        print(f"Error unirse_grupo: {e}")
        flash("❌ Error interno al unirse al grupo.", "error")

    return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")


@app.route("/salir_grupo")
def salir_grupo():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    user_id = session["user_id"]

    try:
        # Llamada al CONTROLADOR
        exito, mensaje = estu_db.procesar_salida_grupo(user_id)

        if exito:
            flash(f"✅ {mensaje}", "success")
        else:
            flash(f"❌ {mensaje}", "error")

    except Exception as e:
        print(f"Error salir_grupo: {e}")
        flash("❌ Error interno al salir del grupo.", "error")

    return redirect(url_for("dashboard_estudiante") + "?seccion=grupal")


# ========================================
# RUTAS DE JUEGO (ESTUDIANTE)
# ========================================

@app.route("/juego_grupo", methods=["POST"])
def juego_grupo():
    """Maneja el inicio (Líder) o la unión (Miembro) a un juego grupal."""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    pin = request.form.get("pin")
    user_id = session["user_id"]

    if not pin:
        flash("❌ Debes ingresar un código PIN.", "error")
        return redirect(url_for("dashboard_estudiante"))

    try:
        # Llamada al CONTROLADOR
        exito, mensaje, grupo_id = juego_db.procesar_ingreso_juego_grupal(user_id, pin)

        if not exito:
            flash(f"❌ {mensaje}", "error")
            return redirect(url_for('dashboard_estudiante'))

        # Redirección a sala de espera
        return redirect(url_for('sala_espera_grupo', grupo_id=grupo_id))

    except Exception as e:
        print(f"Error juego_grupo: {e}")
        flash(f"❌ Error al iniciar el juego grupal: {str(e)}", "error")
        return redirect(url_for('dashboard_estudiante'))


@app.route("/sala_espera/<int:grupo_id>")
def sala_espera_grupo(grupo_id):
    """Sala de espera para el grupo antes de que inicie la partida"""
    if "usuario" not in session:
        return redirect(url_for('login'))

    user_id = session["user_id"]

    try:
        # Llamada al CONTROLADOR
        datos = juego_db.obtener_datos_sala_espera(grupo_id, user_id)

        if not datos["grupo"]:
            flash("❌ Grupo no encontrado", "error")
            return redirect(url_for('dashboard_estudiante'))

        if not datos["es_miembro"]:
            flash("❌ No perteneces a este grupo", "error")
            return redirect(url_for('dashboard_estudiante'))

        return render_template('sala_espera_grupo.html',
                               grupo=datos["grupo"],
                               miembros=datos["miembros"],
                               user_id=user_id)
    except Exception as e:
        print(f"Error sala_espera: {e}")
        flash("❌ Error al cargar la sala de espera", "error")
        return redirect(url_for('dashboard_estudiante'))


@app.route("/iniciar_partida_grupal/<int:grupo_id>", methods=["POST"])
def iniciar_partida_grupal(grupo_id):
    """El líder inicia oficialmente la partida desde la sala de espera"""
    if "usuario" not in session:
        return jsonify({"success": False, "message": "No autenticado"}), 403

    try:
        # Llamada al CONTROLADOR
        exito, mensaje = juego_db.iniciar_partida_lider(grupo_id, session['user_id'])

        if exito:
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "message": mensaje}), 403

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/partida_grupal/<int:grupo_id>")
def partida_grupal(grupo_id):
    if "usuario" not in session: return redirect(url_for('login'))

    try:
        # Llamada al CONTROLADOR
        datos = juego_db.obtener_datos_partida_activa(grupo_id)
        return render_template("partida_grupal.html",
                               grupo=datos["grupo"],
                               cuestionario=datos["cuestionario"],
                               user_id=session['user_id'])
    except Exception as e:
        print(f"Error partida_grupal: {e}")
        return redirect(url_for('dashboard_estudiante'))


@app.route("/resultados_grupo/<int:grupo_id>")
def resultados_grupo(grupo_id):
    """Muestra la página de resultados y guarda en el historial."""
    if "usuario" not in session: return redirect(url_for('login'))

    try:
        # Llamada al CONTROLADOR (Toda la lógica de guardado está aquí)
        res = juego_db.procesar_resultados_grupo(grupo_id, session.get("user_id"))

        if res.get("error"):
            flash(f"❌ {res['error']}", "error")
            return redirect(url_for('dashboard_estudiante'))

        return render_template("resultados_grupo.html",
                               grupo=res["grupo"],
                               cuestionario=res["cuestionario"],
                               miembros=res["miembros"])
    except Exception as e:
        print(f"Error resultados_grupo: {e}")
        flash("❌ Error al cargar los resultados.", "error")
        return redirect(url_for('dashboard_estudiante'))


@app.route("/guardar_respuesta_individual", methods=["POST"])
def guardar_respuesta_individual():
    """Guarda la respuesta de un estudiante en modo individual"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        data = request.get_json()
        pregunta_id = data.get('pregunta_id')
        respuesta = data.get('respuesta')
        tiempo_respuesta = data.get('tiempo_respuesta', 0)

        user_id = session["user_id"]

        # Llamada al CONTROLADOR
        resultado, error = juego_db.guardar_respuesta_estudiante(
            user_id, pregunta_id, respuesta, tiempo_respuesta
        )

        if error:
            return jsonify({"success": False, "message": error}), 404

        return jsonify(resultado)

    except Exception as e:
        print(f"Error guardar_respuesta_individual: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/finalizar_cuestionario_individual", methods=["POST"])
def finalizar_cuestionario_individual():
    """Finaliza el cuestionario y redirige a resultados"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        data = request.get_json()
        tiempo_total = data.get('tiempo_total', 0)

        user_id = session["user_id"]

        # Llamada al CONTROLADOR
        resultado, error = juego_db.finalizar_partida_individual(user_id, tiempo_total)

        if error:
            return jsonify({"success": False, "message": error}), 404

        # Actualizar estadísticas de gamificación
        recompensas_resultado = None
        try:
            recompensas_resultado = recompensas_db.actualizar_stats_despues_partida(
                user_id,
                resultado['puntuacion_final'],
                resultado['correctas'],
                resultado['incorrectas']
            )
            # Guardar en sesión para mostrar en resultados
            session['ultima_recompensa'] = recompensas_resultado
        except Exception as e:
            print(f"Error actualizando stats de recompensas: {e}")

        # Redirigir a la página de resultados con ranking
        return jsonify({
            "success": True,
            "message": "Cuestionario finalizado",
            "redirect_url": f"/resultados_individual/{resultado['historial_id']}"
        })

    except Exception as e:
        print(f"Error finalizar_cuestionario_individual: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/resultados_individual/<int:historial_id>")
def resultados_individual(historial_id):
    """Muestra la página de resultados con ranking"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    user_id = session["user_id"]

    try:
        # Llamada al CONTROLADOR
        datos, error = juego_db.obtener_datos_resultados_individual(historial_id, user_id)

        if error:
            flash(f"❌ {error}", "error")
            return redirect(url_for("dashboard_estudiante"))

        # Obtener recompensas de la sesión (si existen)
        recompensas = session.pop('ultima_recompensa', None)

        # Formatear fecha para mostrar
        fecha_realizacion_str = "Fecha no disponible"
        if datos["historial"].get('fecha_realizacion'):
            fecha_realizacion_str = datos["historial"]['fecha_realizacion'].strftime('%d/%m/%Y %H:%M')

        return render_template("resultados_individual_con_ranking.html",
                               historial=datos["historial"],
                               respuestas=datos["respuestas"],
                               ranking_completo=datos["ranking_completo"],
                               posicion_actual=datos["posicion_actual"],
                               correctas=datos["correctas"],
                               incorrectas=datos["incorrectas"],
                               porcentaje=datos["porcentaje"],
                               tiempo_promedio=datos["tiempo_promedio"],
                               recompensas=recompensas,
                               fecha_realizacion_str=fecha_realizacion_str)

    except Exception as e:
        print(f"Error resultados_individual: {e}")
        import traceback
        traceback.print_exc()
        flash("❌ Error al cargar los resultados", "error")
        return redirect(url_for("dashboard_estudiante"))
# ========================================
# RUTAS DE JUEGO (VISTAS PROFESOR)
# ========================================

@app.route("/sala_profesor/<codigo_pin>")
def sala_profesor(codigo_pin):
    """Sala donde el profesor ve los grupos esperando"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR
        datos = juego_db.obtener_datos_sala_profesor_grupal(codigo_pin, session["user_id"])

        if not datos["cuestionario"]:
            flash("❌ Cuestionario no encontrado", "error")
            return redirect(url_for("dashboard_profesor"))

        if datos["cuestionario"]['modo_juego'] != 'grupal':
            flash("❌ Este cuestionario no es grupal.", "error")
            return redirect(url_for("dashboard_profesor"))

        return render_template("sala_profesor.html",
                               cuestionario=datos["cuestionario"],
                               grupos_esperando=datos["grupos"])
    except Exception as e:
        print(f"Error sala_profesor: {e}")
        flash(f"❌ Error al cargar la sala: {str(e)}", "error")
        return redirect(url_for("dashboard_profesor"))




@app.route("/profesor_vista_juego_grupal/<codigo_pin>")
def profesor_vista_juego_grupal(codigo_pin):
    """Vista en vivo del profesor durante el juego grupal"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR
        datos = juego_db.obtener_vista_live_profesor_grupal(codigo_pin, session["user_id"])

        if not datos["cuestionario"]:
            flash("❌ Cuestionario no encontrado", "error")
            return redirect(url_for("dashboard_profesor"))

        return render_template("profesor_vista_juego_grupal.html",
                               cuestionario=datos["cuestionario"],
                               preguntas=datos["preguntas"],
                               grupos_ids=datos["grupos_ids"],
                               total_grupos=datos["total_grupos"])
    except Exception as e:
        print(f"Error vista juego grupal: {e}")
        flash("❌ Error al cargar la vista del juego", "error")
        return redirect(url_for("dashboard_profesor"))


@app.route("/profesor_vista_juego/<codigo_pin>")
def profesor_vista_juego(codigo_pin):
    """Vista en vivo del profesor durante el juego individual"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR
        datos = juego_db.obtener_vista_live_profesor_individual(codigo_pin, session["user_id"])

        if not datos["cuestionario"]:
            flash("❌ Cuestionario no encontrado", "error")
            return redirect(url_for("dashboard_profesor"))

        if not datos["sesion_id"]:
            flash("⚠️ No hay ninguna sesión activa para este cuestionario", "warning")
            # Redirigir a donde corresponda si no hay sesión, quizas sala de espera indiv.
            # return redirect(url_for("sala_profesor_individual", codigo_pin=codigo_pin))
            pass

        return render_template("profesor_vista_juego_individual.html",
                               cuestionario=datos["cuestionario"],
                               preguntas=datos["preguntas"],
                               sesion_id=datos["sesion_id"],
                               total_estudiantes=datos["total_estudiantes"])
    except Exception as e:
        print(f"Error vista juego indiv: {e}")
        flash("❌ Error al cargar la vista del juego", "error")
        return redirect(url_for("dashboard_profesor"))


# ========================================
# APIS AUXILIARES (POLLING AJAX)
# ========================================

@app.route("/api/miembros_grupo/<int:grupo_id>")
def api_miembros_grupo(grupo_id):
    if "usuario" not in session: return jsonify({"error": "No autenticado"}), 403
    try:
        data = juego_db.api_obtener_miembros_grupo(grupo_id)
        if not data: return jsonify({"error": "Grupo no encontrado"}), 404

        return jsonify({
            "miembros": data["miembros"],
            "lider_id": data["lider_id"],
            "total": len(data["miembros"])
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/api/estudiantes_en_sesion/<sesion_id>")
def api_estudiantes_en_sesion_route(sesion_id):
    """Obtener lista de estudiantes en una sesión con su progreso"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        estudiantes = profe_db.obtener_estudiantes_en_sesion(sesion_id)

        return jsonify({
            "success": True,
            "estudiantes": estudiantes
        })

    except Exception as e:
        print(f"Error en api_estudiantes_en_sesion: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/ranking_final_sesion/<sesion_id>")
def api_ranking_final_sesion_route(sesion_id):
    """Obtener el ranking final de una sesión"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        ranking = profe_db.obtener_ranking_final_sesion(sesion_id)

        return jsonify({
            "success": True,
            "ranking": ranking
        })

    except Exception as e:
        print(f"Error en api_ranking_final_sesion: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


# ========================================
# RUTAS DE JUEGO Y RESULTADOS
# ========================================

@app.route("/profesor_iniciar_partidas/<codigo_pin>", methods=["POST"])
def profesor_iniciar_partidas(codigo_pin):
    """El profesor inicia todas las partidas grupales desde su dashboard"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        # Llamada al CONTROLADOR
        exito, mensaje, count = juego_db.iniciar_partidas_masivo_profesor(codigo_pin, session["user_id"])

        if exito:
            return jsonify({
                "success": True,
                "message": f"Se iniciaron {count} partida(s)",
                "grupos_iniciados": count
            })
        else:
            return jsonify({"success": False, "message": mensaje}), 404

    except Exception as e:
        print(f"Error iniciar partidas: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/grupos_esperando/<codigo_pin>")
def api_grupos_esperando(codigo_pin):
    """Obtiene la lista de grupos esperando en tiempo real"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"error": "No autorizado"}), 403

    try:
        # Llamada al CONTROLADOR
        grupos = juego_db.obtener_lista_grupos_esperando(codigo_pin)
        return jsonify(grupos)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ========================================
# RUTAS DE SALA DE ESPERA (INDIVIDUAL)
# ========================================

@app.route("/sala_profesor_individual/<codigo_pin>")
def sala_profesor_individual(codigo_pin):
    """Sala donde el profesor ve los estudiantes esperando (modo individual)"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR
        cuestionario = juego_db.obtener_datos_sala_profesor_individual(codigo_pin, session["user_id"])

        if not cuestionario:
            flash("❌ Cuestionario no encontrado", "error")
            return redirect(url_for("dashboard_profesor"))

        if cuestionario['modo_juego'] != 'individual':
            flash("❌ Este cuestionario es grupal, no individual", "error")
            return redirect(url_for("dashboard_profesor"))

        return render_template("sala_profesor_individual.html", cuestionario=cuestionario)
    except Exception as e:
        print(f"Error sala individual: {e}")
        return redirect(url_for("dashboard_profesor"))


@app.route("/api/estudiantes_esperando/<codigo_pin>")
def api_estudiantes_esperando(codigo_pin):
    """Obtiene la lista de estudiantes esperando en tiempo real"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"error": "No autorizado"}), 403

    try:
        # Llamada al CONTROLADOR (Incluye lógica de timestamps)
        estudiantes = juego_db.obtener_estudiantes_esperando_lista(codigo_pin)
        return jsonify(estudiantes)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/profesor_iniciar_individuales/<codigo_pin>", methods=["POST"])
def profesor_iniciar_individuales(codigo_pin):
    """El profesor inicia todas las partidas individuales"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        # Llamada al CONTROLADOR
        exito, resultado = juego_db.iniciar_partidas_individuales_masivo(codigo_pin, session["user_id"])

        if not exito:
            return jsonify({"success": False, "message": resultado}), 404 # resultado es msg error

        # resultado es dict con datos de éxito
        return jsonify({
            "success": True,
            "message": f"Se iniciaron {resultado['estudiantes_iniciados']} partida(s)",
            "estudiantes_iniciados": resultado['estudiantes_iniciados'],
            "sesion_id": resultado['sesion_id'],
            "redirect_url": f"/profesor_vista_juego/{codigo_pin}"
        })

    except Exception as e:
        print(f"Error iniciar individuales: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/estado_individual/<int:usuario_id>")
def api_estado_individual(usuario_id):
    """API para consultar estado del estudiante (Polling del lado cliente)"""
    try:
        # Llamada al CONTROLADOR
        registro = juego_db.obtener_estado_estudiante_individual(usuario_id)

        if not registro:
            return jsonify({"error": "No encontrado"}), 404

        return jsonify({
            "estado": registro['estado'],
            "codigo_pin": registro['codigo_pin']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/salir_sala_individual/<int:usuario_id>", methods=["POST"])
def api_salir_sala_individual(usuario_id):
    """Permite a un estudiante salir de la sala de espera individual"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    if session["user_id"] != usuario_id:
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        # Llamada al CONTROLADOR
        juego_db.salir_sala_espera_individual(usuario_id)

        return jsonify({
            "success": True,
            "message": "Has salido de la sala de espera"
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/sala_espera_individual/<codigo_pin>")
def sala_espera_individual(codigo_pin):
    """Muestra la sala de espera para estudiantes en modo individual"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    user_id = session["user_id"]

    try:
        # Llamada al CONTROLADOR (Maneja el INSERT si no existe)
        juego_db.ingresar_sala_espera_individual(user_id, codigo_pin)

        return render_template("sala_espera_individual.html",
                               user_id=user_id,
                               codigo_pin=codigo_pin,
                               nombre_estudiante=session["usuario"])
    except Exception as e:
        print(f"Error sala individual estudiante: {e}")
        flash("Error al ingresar a la sala", "error")
        return redirect(url_for("dashboard_estudiante"))


# ========================================
# RUTAS: JUEGO INDIVIDUAL
# ========================================

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

    try:
        # Llamada al CONTROLADOR
        exito, mensaje = juego_db.procesar_union_individual(user_id, codigo_pin)

        if not exito:
            flash(f"❌ {mensaje}", "error")
            return redirect(url_for("dashboard_estudiante"))

        # Redirigir a la sala de espera individual
        return redirect(url_for("sala_espera_individual", codigo_pin=codigo_pin))

    except Exception as e:
        print(f"Error unirse individual: {e}")
        flash("Error al intentar unirse al cuestionario", "error")
        return redirect(url_for("dashboard_estudiante"))


@app.route("/partida_individual/<codigo_pin>")
def partida_individual(codigo_pin):
    """Carga el cuestionario individual cuando inicia la partida"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    user_id = session["user_id"]
    nombre_estudiante = session["usuario"]

    try:
        # Llamada al CONTROLADOR
        exito, datos = juego_db.iniciar_juego_individual_logica(user_id, codigo_pin, nombre_estudiante)

        if not exito:
            # datos contiene el mensaje de error en este caso
            flash(f"❌ {datos}", "error")
            return redirect(url_for("dashboard_estudiante"))

        # Guardar ID historial en sesión (opcional, útil para trackear)
        if "historial_id" in datos:
            session['historial_individual_id'] = datos["historial_id"]

        return render_template("juego_individual.html",
                               cuestionario=datos["cuestionario"],
                               preguntas=datos["preguntas"],
                               nombre_estudiante=nombre_estudiante,
                               sesion_id=datos["sesion_id"])

    except Exception as e:
        print(f"Error partida individual: {e}")
        flash(f"Error al cargar el cuestionario: {str(e)}", "error")
        return redirect(url_for("dashboard_estudiante"))


# ========================================
# RUTAS: APIs TIEMPO REAL (Juego Grupal)
# ========================================

@app.route("/api/estado_grupo/<int:grupo_id>")
def api_estado_grupo(grupo_id):
    """Obtiene el estado actual del grupo"""
    try:
        estado = juego_db.api_obtener_estado_grupo(grupo_id)
        if not estado:
            return jsonify(None), 404

        return jsonify({
            'game_state': estado['game_state'],
            'active_pin': estado['active_pin'],
            'current_question_index': estado['current_question_index'],
            'current_score': estado['current_score']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/get_pregunta/<int:grupo_id>")
def api_get_pregunta(grupo_id):
    """Obtiene la pregunta actual del juego grupal"""
    try:
        resultado, error = juego_db.api_obtener_pregunta_actual(grupo_id)

        if error:
            return jsonify({"error": error}), 404

        return jsonify(resultado)
    except Exception as e:
        print(f"Error api_get_pregunta: {e}")
        return jsonify({"error": f"Error del servidor: {str(e)}"}), 500


@app.route("/api/get_ultima_respuesta/<int:grupo_id>")
def api_get_ultima_respuesta(grupo_id):
    """Obtiene el resultado de la última respuesta del líder"""
    try:
        data = juego_db.api_obtener_resultado_ultima(grupo_id)

        if data is None:
            return jsonify({"error": "Juego no encontrado"}), 404

        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/responder/<int:grupo_id>", methods=["POST"])
def api_responder(grupo_id):
    """Procesa la respuesta del líder del grupo"""
    if "usuario" not in session:
        return jsonify({"success": False, "message": "No autenticado"}), 403

    user_id = session['user_id']
    respuesta_usuario = request.json.get('respuesta')

    try:
        # Llamada al CONTROLADOR
        exito, resultado = juego_db.api_procesar_respuesta_lider(grupo_id, user_id, respuesta_usuario)

        if not exito:
            # resultado contiene el mensaje de error
            return jsonify({"success": False, "message": resultado}), 403

        # resultado contiene los datos de éxito
        return jsonify({
            "success": True,
            "es_correcta": resultado["es_correcta"],
            "puntos_ganados": resultado["puntos_ganados"],
            "respuesta_correcta": resultado["respuesta_correcta"],
            "respuesta_seleccionada": respuesta_usuario,
            "es_ultima_pregunta": resultado["es_ultima_pregunta"],
            "nuevo_score": resultado["nuevo_score"]
        })

    except Exception as e:
        print(f"Error api_responder: {e}")
        return jsonify({"success": False, "message": f"Error del servidor: {str(e)}"}), 500


# ========================================
# RUTAS PERFIL ESTUDIANTE
# ========================================

@app.route("/cambiar_datos_estudiante", methods=["GET", "POST"])
def cambiar_datos_estudiante():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    # 1. Cargar datos actuales si faltan en sesión
    if 'correo' not in session and 'user_id' in session:
        datos_db = estu_db.obtener_datos_perfil(session["user_id"])
        if datos_db:
            session['correo'] = datos_db['correo']

    if request.method == "POST":
        nombre_nuevo = request.form["nombre"]
        password_actual = request.form["password_actual"]
        password_nueva = request.form.get("password_nueva", "")
        confirmar_nueva = request.form.get("confirmar_nueva", "")

        try:
            # 2. Obtener datos reales para validación desde CONTROLADOR
            datos_usuario = estu_db.obtener_datos_perfil(session["user_id"])

            if not datos_usuario:
                flash("❌ Error al cargar datos de usuario", "error")
                return redirect(url_for("login"))

            # Validar contraseña actual
            pass_actual_enc = encriptar_password(password_actual)
            if datos_usuario["password"] != pass_actual_enc:
                flash("❌ La contraseña actual es incorrecta", "error")
                return redirect(url_for("cambiar_datos_estudiante"))

            # Validar nueva contraseña si existe
            password_nueva_enc = None
            if password_nueva:
                if password_nueva != confirmar_nueva:
                    flash("❌ Las contraseñas nuevas no coinciden", "error")
                    return redirect(url_for("cambiar_datos_estudiante"))

                es_segura, msg = es_password_segura(password_nueva)
                if not es_segura:
                    flash(f"❌ {msg}", "error")
                    return redirect(url_for("cambiar_datos_estudiante"))

                password_nueva_enc = encriptar_password(password_nueva)

            # 3. Actualizar vía CONTROLADOR
            estu_db.actualizar_perfil_estudiante(session["user_id"], nombre_nuevo, password_nueva_enc)

            session["usuario"] = nombre_nuevo
            flash("✅ Datos actualizados correctamente", "success")
            return redirect(url_for("dashboard_estudiante"))

        except Exception as e:
            print(f"Error al actualizar perfil: {e}")
            flash("❌ Ocurrió un error interno", "error")
            return redirect(url_for("cambiar_datos_estudiante"))

    return render_template("CambiarDatos_estudiante.html",
                           nombre=session.get("usuario"),
                           correo=session.get("correo"))


@app.route("/eliminar_cuenta_estudiante", methods=["POST"])
def eliminar_cuenta_estudiante():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    password_actual = request.form.get("password_actual")
    user_id = session["user_id"]

    try:
        # 1. Obtener contraseña real para validación
        datos_usuario = estu_db.obtener_datos_perfil(user_id)

        pass_actual_enc = encriptar_password(password_actual)

        if not datos_usuario or datos_usuario['password'] != pass_actual_enc:
            flash("❌ Contraseña incorrecta. No se pudo eliminar la cuenta.", "error")
            return redirect(url_for('cambiar_datos_estudiante'))

        # 2. Eliminar cuenta vía CONTROLADOR
        estu_db.eliminar_cuenta_estudiante_definitiva(user_id)

        # Limpiar sesión y cookies
        session.clear()
        response = redirect(url_for('login'))

        # Si usas las cookies encriptadas del login, límpialas también aquí
        response = make_response(response)
        response.set_cookie('token_jwt', '', expires=0)

        flash("✅ Tu cuenta ha sido eliminada permanentemente.", "success")
        return response

    except Exception as e:
        print(f"Error al eliminar cuenta: {e}")
        flash("❌ Ocurrió un error al intentar eliminar la cuenta.", "error")
        return redirect(url_for('cambiar_datos_estudiante'))


# ========================================
# RUTAS: VISUALIZACIÓN Y EXPORTACIÓN
# ========================================


@app.route('/enviar_resultados_profesor/<int:cuestionario_id>', methods=['POST'])
def enviar_resultados_profesor(cuestionario_id):
    """Envía los resultados del cuestionario al correo que indique el profesor"""
    if 'user_id' not in session or session.get('role') != 'profesor':
        return jsonify({'success': False, 'error': 'No autorizado'}), 401

    # Obtener el correo destino del formulario
    correo_destino = request.form.get('correo_destino')

    if not correo_destino:
        flash('Debe indicar un correo de destino', 'error')
        return redirect(url_for('exportar_resultados', cuestionario_id=cuestionario_id))

    try:
        # Generar el Excel con los resultados
        from controlador_exportar import generar_excel_resultados
        excel_data, nombre_archivo, error = generar_excel_resultados(cuestionario_id, session['user_id'])

        if error:
            flash(f'Error al generar resultados: {error}', 'error')
            return redirect(url_for('exportar_resultados', cuestionario_id=cuestionario_id))

        # Obtener info del cuestionario para el asunto
        from controlador_cuestionario import obtener_cuestionario_por_id
        cuestionario, _ = obtener_cuestionario_por_id(cuestionario_id)
        nombre_cuestionario = cuestionario['titulo'] if cuestionario else f'Cuestionario #{cuestionario_id}'

        # Crear el mensaje
        msg = Message(
            subject=f'Resultados: {nombre_cuestionario}',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[correo_destino]  # ← AQUÍ VA EL OUTLOOK DEL PROFESOR
        )

        msg.body = f'''
Estimado profesor,

Adjunto encontrará los resultados del cuestionario "{nombre_cuestionario}".

Este correo fue enviado automáticamente desde el sistema de cuestionarios.

Saludos,
Sistema KahootSG4
'''

        msg.html = f'''
<html>
<body style="font-family: Arial, sans-serif;">
    <h2 style="color: #2c3e50;">Resultados del Cuestionario</h2>
    <p>Estimado profesor,</p>
    <p>Adjunto encontrará los resultados del cuestionario <strong>"{nombre_cuestionario}"</strong>.</p>
    <hr>
    <p style="color: #7f8c8d; font-size: 12px;">
        Este correo fue enviado automáticamente desde el sistema de cuestionarios KahootSG4.
    </p>
</body>
</html>
'''

        # Adjuntar el Excel
        msg.attach(
            filename=nombre_archivo,
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            data=excel_data.getvalue()
        )

        # Enviar el correo
        mail.send(msg)

        flash(f'Resultados enviados correctamente a {correo_destino}', 'success')
        return redirect(url_for('dashboard_profesor'))

    except OSError as e:
        if e.errno == 101:
            flash('Error de red: El servidor no puede enviar correos en este momento. Use la descarga directa.', 'error')
        else:
            flash(f'Error de conexión: {str(e)}', 'error')
        return redirect(url_for('exportar_resultados', cuestionario_id=cuestionario_id))
    except Exception as e:
        flash(f'Error al enviar correo: {str(e)}', 'error')
        return redirect(url_for('exportar_resultados', cuestionario_id=cuestionario_id))

@app.route("/visualizar_cuestionario", methods=["POST"])
def visualizar_cuestionario():
    if "usuario" not in session:
        return redirect(url_for("login"))

    pin = request.form.get("codigo_pin")
    if not pin:
        flash("❌ Debes ingresar un código PIN.", "error")
        return redirect(url_for("dashboard_estudiante"))

    try:
        # Llamada al CONTROLADOR
        exito, resultado = juego_db.procesar_visualizacion_cuestionario(pin, session.get("rol"))

        if not exito:
            flash(f"❌ {resultado}", "error")
            return redirect(url_for("dashboard_estudiante"))

        return redirect(url_for("sala_espera_individual", codigo_pin=resultado))

    except Exception as e:
        print(f"Error visualizar: {e}")
        flash("Error al procesar solicitud", "error")
        return redirect(url_for("dashboard_estudiante"))


@app.route("/exportar_resultados/<int:cuestionario_id>")
def exportar_resultados(cuestionario_id):
    """Página de opciones de exportación"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR
        datos = juego_db.obtener_datos_exportacion(cuestionario_id, session["user_id"])

        if not datos["cuestionario"]:
            flash("❌ Cuestionario no encontrado", "error")
            return redirect(url_for("dashboard_profesor"))

        return render_template("exportar_opciones.html",
                               cuestionario=datos["cuestionario"],
                               cuestionario_id=cuestionario_id,
                               total_resultados=datos["total_resultados"])
    except Exception as e:
        print(f"Error exportar: {e}")
        flash("Error al cargar opciones", "error")
        return redirect(url_for("dashboard_profesor"))


@app.route("/descargar_excel/<int:cuestionario_id>")
def descargar_excel(cuestionario_id):
    """Descarga directa del Excel"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR
        filename, output = juego_db.generar_excel_resultados(cuestionario_id, session["user_id"])

        if not filename:
            # output contiene el mensaje de error en este caso
            flash(f"❌ {output}", "warning")
            return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )

    except ImportError:
        flash("❌ Error: Librerías faltantes (pandas/openpyxl)", "error")
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))
    except Exception as e:
        print(f"Error descarga excel: {e}")
        flash(f"❌ Error al exportar: {str(e)}", "error")
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))


@app.route("/enviar_excel_correo/<int:cuestionario_id>", methods=["POST"])
def enviar_excel_correo(cuestionario_id):
    """Envía el archivo Excel por correo electrónico"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # Reutilizamos la lógica del controlador para generar el excel
        filename, output = juego_db.generar_excel_resultados(cuestionario_id, session["user_id"])

        if not filename:
            flash(f"❌ {output}", "warning")
            return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

        # Preparar correo (Lógica de Flask-Mail se queda aquí o en utils)
        correo_destino = session.get('correo')
        msg = Message(
            subject=f'Resultados: {filename}',
            recipients=[correo_destino],
            html=f'<p>Adjunto encontrarás los resultados del cuestionario.</p>'
        )
        msg.attach(filename, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', output.getvalue())

        with app.app_context():
            mail.send(msg)

        flash(f"✅ Correo enviado a {correo_destino}", "success")
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

    except Exception as e:
        print(f"Error enviar correo: {e}")
        flash(f"❌ Error al enviar: {str(e)}", "error")
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))


# ========================================
# RUTAS: SISTEMA DE RECOMPENSAS
# ========================================

@app.route("/perfil_recompensas")
def perfil_recompensas():
    """Muestra el perfil gamificado del estudiante"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR
        datos = recompensas_db.obtener_datos_perfil_completo(session["user_id"])

        return render_template("perfil_recompensas.html",
                               stats=datos['stats'],
                               insignias_desbloqueadas=datos['insignias_desbloqueadas'],
                               todas_insignias=datos['todas_insignias'],
                               progreso_nivel=datos['progreso_nivel'],
                               xp_necesaria=datos['xp_necesaria'])
    except Exception as e:
        print(f"Error perfil recompensas: {e}")
        flash("Error al cargar perfil", "error")
        return redirect(url_for("dashboard_estudiante"))


@app.route("/tienda")
def tienda():
    """Muestra la tienda de items"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR
        datos = recompensas_db.obtener_datos_tienda_completo(session["user_id"])

        return render_template("tienda.html",
                               stats=datos['stats'],
                               items=datos['items'],
                               nombre=session["usuario"])
    except Exception as e:
        print(f"Error tienda: {e}")
        return redirect(url_for("dashboard_estudiante"))


@app.route("/api/comprar_item/<int:item_id>", methods=["POST"])
def comprar_item(item_id):
    """Compra un item de la tienda"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        # Llamada al CONTROLADOR
        exito, resultado = recompensas_db.procesar_compra_item(session["user_id"], item_id)

        if exito:
            return jsonify({
                "success": True,
                "message": resultado["message"],
                "monedas_restantes": resultado["monedas_restantes"]
            })
        else:
            return jsonify({"success": False, "message": resultado}), 400 # resultado es el mensaje de error

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/equipar_item/<int:item_id>", methods=["POST"])
def equipar_item(item_id):
    """Equipa un item comprado"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        # Llamada al CONTROLADOR
        exito, mensaje = recompensas_db.procesar_equipamiento_item(session["user_id"], item_id)

        if exito:
            return jsonify({"success": True, "message": mensaje})
        else:
            return jsonify({"success": False, "message": mensaje}), 404

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/mi_inventario")
def mi_inventario():
    """Muestra los items comprados del estudiante"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR
        datos = recompensas_db.obtener_datos_inventario(session["user_id"])

        return render_template("inventario.html",
                               items=datos['items'],
                               stats=datos['stats'],
                               nombre=session["usuario"])
    except Exception as e:
        print(f"Error inventario: {e}")
        return redirect(url_for("dashboard_estudiante"))



# ========================================
# RUTAS: GESTIÓN EXCEL (PROFESOR)
# ========================================

@app.route("/descargar_plantilla_preguntas")
def descargar_plantilla_preguntas():
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # Llamada al CONTROLADOR PROFESOR
        output = profe_db.generar_plantilla_preguntas()

        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='Plantilla_Preguntas_Cuestionario.xlsx'
        )
    except Exception as e:
        flash(f"❌ Error al generar plantilla: {str(e)}", "error")
        return redirect(url_for("dashboard_profesor"))

@app.route("/importar_preguntas/<int:cuestionario_id>", methods=["GET", "POST"])
def importar_preguntas(cuestionario_id):
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    # GET: Mostrar formulario
    if request.method == "GET":
        try:
            # Reutilizamos función de obtención segura
            cuestionario = profe_db.obtener_cuestionario_propio(cuestionario_id, session["user_id"])
            if not cuestionario:
                flash("❌ Cuestionario no encontrado", "error")
                return redirect(url_for("dashboard_profesor"))
            return render_template("importar_preguntas.html", cuestionario=cuestionario)
        except Exception as e:
            return redirect(url_for("dashboard_profesor"))

    # POST: Procesar archivo
    try:
        if 'archivo_excel' not in request.files:
            flash("❌ No se seleccionó ningún archivo", "error")
            return redirect(url_for("importar_preguntas", cuestionario_id=cuestionario_id))

        archivo = request.files['archivo_excel']
        if not archivo.filename.endswith(('.xlsx', '.xls')):
            flash("❌ Formato inválido. Use Excel (.xlsx)", "error")
            return redirect(url_for("importar_preguntas", cuestionario_id=cuestionario_id))

        # Leer Excel aquí para pasar DataFrame al controlador
        df = pd.read_excel(archivo)

        # Llamada al CONTROLADOR PROFESOR
        exito, mensaje = profe_db.importar_preguntas_desde_excel(cuestionario_id, session["user_id"], df)

        if exito:
            flash(f"✅ {mensaje}", "success")
            return redirect(url_for("dashboard_profesor"))
        else:
            flash(f"❌ {mensaje}", "error")
            return redirect(url_for("importar_preguntas", cuestionario_id=cuestionario_id))

    except Exception as e:
        flash(f"❌ Error crítico: {str(e)}", "error")
        return redirect(url_for("importar_preguntas", cuestionario_id=cuestionario_id))

@app.route("/crear_cuestionario_desde_excel", methods=["POST"])
def crear_cuestionario_desde_excel():
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        titulo = request.form.get('titulo')
        descripcion = request.form.get('descripcion')
        modo_juego = request.form.get('modo_juego')
        tiempo_pregunta = int(request.form.get('tiempo_pregunta'))

        if 'archivo_excel' not in request.files:
            flash("❌ Falta el archivo", "error")
            return redirect(url_for("dashboard_profesor"))

        archivo = request.files['archivo_excel']
        if not archivo.filename.endswith(('.xlsx', '.xls')):
            flash("❌ Formato inválido", "error")
            return redirect(url_for("dashboard_profesor"))

        # Leer Excel
        df = pd.read_excel(archivo)

        # Validar columnas básicas antes de enviar al controlador
        req_cols = ['Pregunta', 'Respuesta_Correcta']
        if not all(col in df.columns for col in req_cols):
             flash("❌ El Excel no tiene el formato correcto (Faltan columnas Pregunta o Respuesta)", "error")
             return redirect(url_for("dashboard_profesor"))

        # Llamada al CONTROLADOR PROFESOR
        exito, titulo_res, num_res = profe_db.crear_cuestionario_completo_excel(
            session["user_id"], titulo, descripcion, modo_juego, tiempo_pregunta, df
        )

        flash(f"✅ Cuestionario '{titulo_res}' creado con {num_res} preguntas.", "success")
        return redirect(url_for("dashboard_profesor"))

    except Exception as e:
        flash(f"❌ Error: {str(e)}", "error")
        return redirect(url_for("dashboard_profesor"))

# ========================================
# RUTAS: APIs SINCRONIZACIÓN (JUEGO)
# ========================================

@app.route("/api/verificar_sincronizacion_individual/<sesion_id>/<int:pregunta_index>")
def api_verificar_sincronizacion_individual(sesion_id, pregunta_index):
    """API para verificar barrera de sincronización individual"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        # Llamada al CONTROLADOR JUEGO
        data = juego_db.api_verificar_sincronizacion_individual(sesion_id, pregunta_index)
        return jsonify(data)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/verificar_sincronizacion_grupal/<int:grupo_id>/<int:pregunta_index>")
def api_verificar_sincronizacion_grupal(grupo_id, pregunta_index):
    """API para verificar barrera de sincronización grupal"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        # Llamada al CONTROLADOR JUEGO
        data = juego_db.api_verificar_sincronizacion_grupal(grupo_id, pregunta_index)
        return jsonify(data)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# ========================================
# FILTROS TEMPLATE
# ========================================
@app.template_filter('hora_peru')
def hora_peru_filter(fecha_utc):
    if fecha_utc is None: return "Fecha no disponible"
    import pytz
    PERU_TZ = pytz.timezone('America/Lima')
    if fecha_utc.tzinfo is None:
        fecha_utc = pytz.utc.localize(fecha_utc)
    return fecha_utc.astimezone(PERU_TZ).strftime('%d/%m/%Y %H:%M')


# ========================================
# RUTAS: LOGIN FACIAL
# ========================================

@app.route("/login_facial")
def login_facial():
    """Muestra la página de login con reconocimiento facial"""
    return render_template("login_facial.html")


@app.route("/verificar_rostro_login", methods=["POST"])
def verificar_rostro_login():
    """Procesa la verificación facial y crea la sesión"""
    try:
        data = request.get_json()
        embedding_capturado = data.get('embedding')

        # Llamada al CONTROLADOR
        exito, resultado = facial_db.procesar_autenticacion_facial(embedding_capturado)

        if exito:
            # Login exitoso: resultado contiene los datos del usuario
            usuario = resultado

            session.permanent = True
            session['usuario'] = usuario['nombre']
            session['correo'] = usuario['correo']
            session['rol'] = usuario['rol']
            session['user_id'] = usuario['usuario_id']

            print(f"✅ Login facial exitoso: {usuario['nombre']} ({usuario['rol']})")

            return jsonify({
                "success": True,
                "message": "Identidad verificada correctamente",
                "rol": usuario['rol']
            })
        else:
            # Login fallido: resultado contiene el mensaje de error
            return jsonify({
                "success": False,
                "message": resultado
            }), 401

    except Exception as e:
        print(f"❌ Error en verificar_rostro_login: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": f"Error del servidor: {str(e)}"
        }), 500


# ========================================
# RUTAS: APIs SINCRONIZACIÓN PROFESOR
# ========================================

@app.route("/api/estado_pregunta_profesor/<sesion_id>")
def api_estado_pregunta_profesor(sesion_id):
    """API para que los estudiantes consulten en qué pregunta está el profesor"""
    try:
        estado = profe_db.obtener_estado_pregunta_profesor(sesion_id)

        if not estado:
            return jsonify({
                'success': False,
                'error': 'Sesión no encontrada'
            }), 404

        return jsonify({
            'success': True,
            'estado': estado['estado'],
            'pregunta_actual': estado['pregunta_actual'],
            'tiempo_restante': estado['tiempo_restante']
        })

    except Exception as e:
        print(f"Error en api_estado_pregunta_profesor: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/actualizar_tiempo_profesor/<sesion_id>", methods=["POST"])
def api_actualizar_tiempo_profesor(sesion_id):
    """API para que el profesor actualice el tiempo restante cada segundo"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        data = request.get_json()
        tiempo_restante = data.get('tiempo_restante')

        if tiempo_restante is None:
            return jsonify({
                "success": False,
                "message": "Tiempo restante no proporcionado"
            }), 400

        success = profe_db.actualizar_tiempo_profesor(sesion_id, tiempo_restante)

        if not success:
            return jsonify({
                "success": False,
                "message": "Error al actualizar tiempo"
            }), 500

        return jsonify({"success": True})

    except Exception as e:
        print(f"Error en api_actualizar_tiempo_profesor: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/actualizar_pregunta_profesor/<sesion_id>", methods=["POST"])
def api_actualizar_pregunta_profesor(sesion_id):
    """API para que el profesor actualice la pregunta actual de la sesión"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        data = request.get_json()
        pregunta_actual = data.get('pregunta_actual')
        estado = data.get('estado', 'playing')
        tiempo_restante = data.get('tiempo_restante')

        if pregunta_actual is None or tiempo_restante is None:
            return jsonify({
                "success": False,
                "message": "Datos incompletos"
            }), 400

        success = profe_db.actualizar_estado_pregunta_profesor(
            sesion_id,
            pregunta_actual,
            estado,
            tiempo_restante
        )

        if not success:
            return jsonify({
                "success": False,
                "message": "Error al actualizar estado"
            }), 500

        return jsonify({"success": True})

    except Exception as e:
        print(f"Error en api_actualizar_pregunta_profesor: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

# ========================================
# RUTAS: REGISTRO FACIAL
# ========================================

@app.route("/registro_facial")
def registro_facial():
    """Muestra la interfaz para registrar el rostro"""
    if "usuario" not in session:
        return redirect(url_for("login"))

    rol = session.get("rol")
    return render_template("registro_facial.html", rol=rol)


@app.route("/guardar_embedding_facial", methods=["POST"])
def guardar_embedding_facial():
    """API para guardar los datos biométricos del usuario"""
    if "usuario" not in session:
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        data = request.get_json()
        embedding = data.get('embedding')
        user_id = session["user_id"]

        exito, mensaje = facial_db.registrar_rostro_usuario(user_id, embedding)

        if exito:
            return jsonify({
                "success": True,
                "message": f"✅ {mensaje}"
            })
        else:
            return jsonify({
                "success": False,
                "message": mensaje
            }), 400

    except Exception as e:
        print(f"Error guardar facial: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

#------------------------AAAAAAAAAAAAAAAAAAAAAAAAAAAPPPPPPPPPPPPPPPPPPPPPPPPPPPPIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIISSSSSSSSSSSSSSSSSSSSS-------------------------


# ========================================
# TABLA: cuestionarios (RUTAS)
# ========================================

@app.route("/api/cuestionarios", methods=["GET"])
def api_obtener_cuestionarios():
    """GET: Lista todos los cuestionarios"""
    try:
        cuestionarios = controlador.obtener_todos_cuestionarios()
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


@app.route("/api/cuestionarios/<int:cuestionario_id>", methods=["GET"])
def api_obtener_cuestionario_por_id(cuestionario_id):
    """GET: Lista un solo cuestionario por ID"""
    try:
        cuestionario = controlador.obtener_cuestionario_por_id(cuestionario_id)

        if not cuestionario:
            return jsonify({
                "success": False,
                "message": "Cuestionario no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "data": cuestionario
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener cuestionario: {str(e)}"
        }), 500


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

        resultado = controlador.crear_cuestionario(
            titulo=data.get('titulo'),
            descripcion=data.get('descripcion', ''),
            modo_juego=data.get('modo_juego', 'individual'),
            tiempo_pregunta=data.get('tiempo_pregunta', 30),
            num_preguntas=data.get('num_preguntas', 0),
            profesor_id=data.get('profesor_id'),
            estado=data.get('estado', 'activo')
        )

        return jsonify({
            "success": True,
            "message": "Cuestionario creado exitosamente",
            "data": resultado
        }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar cuestionario: {str(e)}"
        }), 500


@app.route("/api/cuestionarios/<int:cuestionario_id>", methods=["PUT"])
def api_actualizar_cuestionario(cuestionario_id):
    """POST/PUT: Actualiza un cuestionario existente"""
    try:
        data = request.get_json()

        exito = controlador.actualizar_cuestionario(
            cuestionario_id=cuestionario_id,
            titulo=data.get('titulo'),
            descripcion=data.get('descripcion'),
            modo_juego=data.get('modo_juego'),
            tiempo_pregunta=data.get('tiempo_pregunta'),
            estado=data.get('estado')
        )

        if not exito:
            return jsonify({
                "success": False,
                "message": "Cuestionario no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Cuestionario actualizado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar cuestionario: {str(e)}"
        }), 500


@app.route("/api/cuestionarios/<int:cuestionario_id>", methods=["DELETE"])
def api_eliminar_cuestionario(cuestionario_id):
    """POST/DELETE: Elimina (lógicamente) un cuestionario"""
    try:
        exito = controlador.eliminar_cuestionario_logico(cuestionario_id)

        if not exito:
            return jsonify({
                "success": False,
                "message": "Cuestionario no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Cuestionario eliminado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar cuestionario: {str(e)}"
        }), 500


# ========================================
# TABLA: preguntas (RUTAS)
# ========================================

@app.route("/api/preguntas", methods=["GET"])
def api_obtener_preguntas():
    """GET: Lista todas las preguntas"""
    try:
        cuestionario_id = request.args.get('cuestionario_id')
        preguntas = controlador.obtener_todas_preguntas(cuestionario_id)

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


@app.route("/api/preguntas/<int:pregunta_id>", methods=["GET"])
def api_obtener_pregunta_por_id(pregunta_id):
    """GET: Obtiene una pregunta específica"""
    try:
        pregunta = controlador.obtener_pregunta_id(pregunta_id)

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

        nuevo_id = controlador.crear_pregunta(
            cuestionario_id=data.get('cuestionario_id'),
            pregunta_texto=data.get('pregunta'),
            op_a=data.get('opcion_a', ''),
            op_b=data.get('opcion_b', ''),
            op_c=data.get('opcion_c', ''),
            op_d=data.get('opcion_d', ''),
            correcta=data.get('respuesta_correcta'),
            orden=data.get('orden', 0)
        )

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


@app.route("/api/preguntas/<int:pregunta_id>", methods=["PUT"])
def api_actualizar_pregunta(pregunta_id):
    """POST/PUT: Actualiza una pregunta existente"""
    try:
        data = request.get_json()

        exito = controlador.actualizar_pregunta(
            pregunta_id=pregunta_id,
            pregunta_texto=data.get('pregunta'),
            op_a=data.get('opcion_a'),
            op_b=data.get('opcion_b'),
            op_c=data.get('opcion_c'),
            op_d=data.get('opcion_d'),
            correcta=data.get('respuesta_correcta'),
            orden=data.get('orden')
        )

        if not exito:
            return jsonify({
                "success": False,
                "message": "Pregunta no encontrada"
            }), 404

        return jsonify({
            "success": True,
            "message": "Pregunta actualizada exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar pregunta: {str(e)}"
        }), 500


@app.route("/api/preguntas/<int:pregunta_id>", methods=["DELETE"])
def api_eliminar_pregunta(pregunta_id):
    """POST/DELETE: Elimina una pregunta"""
    try:
        exito = controlador.eliminar_pregunta_logico(pregunta_id)

        if not exito:
            return jsonify({
                "success": False,
                "message": "Pregunta no encontrada"
            }), 404

        return jsonify({
            "success": True,
            "message": "Pregunta eliminada exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar pregunta: {str(e)}"
        }), 500


# ========================================
# TABLA: usuarios (RUTAS)
# ========================================

@app.route("/api/usuarios", methods=["GET"])
def api_obtener_usuarios():
    """GET: Lista todos los usuarios"""
    try:
        rol = request.args.get('rol')
        usuarios = controlador.obtener_todos_usuarios(rol)

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


@app.route("/api/usuarios/<int:usuario_id>", methods=["GET"])
def api_obtener_usuario_por_id(usuario_id):
    """GET: Obtiene un usuario específico"""
    try:
        usuario = controlador.obtener_usuario_por_id(usuario_id)

        if not usuario:
            return jsonify({
                "success": False,
                "message": "Usuario no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "data": usuario
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener usuario: {str(e)}"
        }), 500


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

        nuevo_id = controlador.crear_usuario(
            nombre=data.get('nombre'),
            correo=data.get('correo'),
            password=data.get('password'), # Recordatorio: Hashear esto en producción
            rol=data.get('rol', 'estudiante'),
            verificado=data.get('verificado', 0),
            codigo_verificacion=data.get('codigo_verificacion', '')
        )

        if nuevo_id is None:
            # Si devolvió None, asumimos que es por correo duplicado (según la lógica del controlador)
            return jsonify({
                "success": False,
                "message": "El correo ya está registrado"
            }), 400

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


@app.route("/api/usuarios/<int:usuario_id>", methods=["PUT"])
def api_actualizar_usuario(usuario_id):
    """POST/PUT: Actualiza un usuario existente"""
    try:
        data = request.get_json()

        exito = controlador.actualizar_usuario(
            usuario_id=usuario_id,
            nombre=data.get('nombre'),
            correo=data.get('correo'),
            rol=data.get('rol'),
            verificado=data.get('verificado'),
            grupo_id=data.get('grupo_id')
        )

        if not exito:
            return jsonify({
                "success": False,
                "message": "Usuario no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Usuario actualizado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar usuario: {str(e)}"
        }), 500


@app.route("/api/usuarios/<int:usuario_id>", methods=["DELETE"])
def api_eliminar_usuario(usuario_id):
    """POST/DELETE: Elimina un usuario"""
    try:
        exito = controlador.eliminar_usuario_fisico(usuario_id)

        if not exito:
            return jsonify({
                "success": False,
                "message": "Usuario no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Usuario eliminado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar usuario: {str(e)}"
        }), 500


# ========================================
# TABLA: grupos (RUTAS)
# ========================================

@app.route("/api/grupos", methods=["GET"])
def api_obtener_grupos():
    """GET: Lista todos los grupos"""
    try:
        grupos = controlador.obtener_todos_grupos()
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


@app.route("/api/grupos/<int:grupo_id>", methods=["GET"])
def api_obtener_grupo_por_id(grupo_id):
    """GET: Obtiene un grupo específico con sus miembros"""
    try:
        grupo = controlador.obtener_grupo_completo(grupo_id)

        if not grupo:
            return jsonify({
                "success": False,
                "message": "Grupo no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "data": grupo
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener grupo: {str(e)}"
        }), 500


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

        resultado = controlador.crear_grupo(
            nombre_grupo=data.get('nombre_grupo'),
            leader_id=data.get('leader_id'),
            active_min=data.get('active_min', ''),
            game_state=data.get('game_state', '')
        )

        return jsonify({
            "success": True,
            "message": "Grupo creado exitosamente",
            "data": resultado
        }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar grupo: {str(e)}"
        }), 500


@app.route("/api/grupos/<int:grupo_id>", methods=["PUT"])
def api_actualizar_grupo(grupo_id):
    """POST/PUT: Actualiza un grupo existente"""
    try:
        data = request.get_json()

        exito = controlador.actualizar_grupo(
            grupo_id=grupo_id,
            nombre_grupo=data.get('nombre_grupo'),
            leader_id=data.get('leader_id'),
            active_min=data.get('active_min'),
            game_state=data.get('game_state'),
            active_pin=data.get('active_pin')
        )

        if not exito:
            return jsonify({
                "success": False,
                "message": "Grupo no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Grupo actualizado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar grupo: {str(e)}"
        }), 500


@app.route("/api/grupos/<int:grupo_id>", methods=["DELETE"])
def api_eliminar_grupo(grupo_id):
    """POST/DELETE: Elimina un grupo"""
    try:
        exito = controlador.eliminar_grupo_cascada(grupo_id)

        if not exito:
            return jsonify({
                "success": False,
                "message": "Grupo no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Grupo eliminado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar grupo: {str(e)}"
        }), 500


# ========================================
# TABLA: historial_individual (RUTAS)
# ========================================

@app.route("/api/historial_individual", methods=["GET"])
def api_obtener_historial_individual():
    """GET: Lista todo el historial individual"""
    try:
        usuario_id = request.args.get('usuario_id')
        cuestionario_id = request.args.get('cuestionario_id')

        historial = controlador.obtener_historial_individual(usuario_id, cuestionario_id)

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


@app.route("/api/historial_individual/<int:historial_id>", methods=["GET"])
def api_obtener_historial_individual_por_id(historial_id):
    """GET: Obtiene un registro específico del historial"""
    try:
        registro = controlador.obtener_historial_individual_id(historial_id)

        if not registro:
            return jsonify({
                "success": False,
                "message": "Historial no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "data": registro
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener historial: {str(e)}"
        }), 500


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

        nuevo_id = controlador.crear_historial_individual(
            cuestionario_id=data.get('cuestionario_id'),
            usuario_id=data.get('usuario_id'),
            nombre_estudiante=data.get('nombre_estudiante'),
            puntuacion=data.get('puntuacion_final', 0),
            num_preguntas=data.get('num_preguntas_total', 0),
            tiempo=data.get('tiempo_total', 0),
            sesion_id=data.get('sesion_id')
        )

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


@app.route("/api/historial_individual/<int:historial_id>", methods=["PUT"])
def api_actualizar_historial_individual(historial_id):
    """POST/PUT: Actualiza un registro del historial"""
    try:
        data = request.get_json()

        exito = controlador.actualizar_historial_individual(
            historial_id=historial_id,
            puntuacion=data.get('puntuacion_final'),
            num_preguntas=data.get('num_preguntas_total'),
            tiempo=data.get('tiempo_total')
        )

        if not exito:
            return jsonify({
                "success": False,
                "message": "Historial no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Historial actualizado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar historial: {str(e)}"
        }), 500


@app.route("/api/historial_individual/<int:historial_id>", methods=["DELETE"])
def api_eliminar_historial_individual(historial_id):
    """POST/DELETE: Elimina un registro del historial"""
    try:
        exito = controlador.eliminar_historial_individual(historial_id)

        if not exito:
            return jsonify({
                "success": False,
                "message": "Historial no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Historial eliminado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar historial: {str(e)}"
        }), 500


# ========================================
# TABLA: historial_partidas (RUTAS)
# ========================================

@app.route("/api/historial_partidas", methods=["GET"])
def api_obtener_historial_partidas():
    """GET: Lista todo el historial de partidas grupales"""
    try:
        grupo_id = request.args.get('grupo_id')
        partidas = controlador.obtener_historial_partidas(grupo_id)

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


@app.route("/api/historial_partidas/<int:partida_id>", methods=["GET"])
def api_obtener_historial_partida_por_id(partida_id):
    """GET: Obtiene una partida específica"""
    try:
        partida = controlador.obtener_partida_por_id(partida_id)

        if not partida:
            return jsonify({
                "success": False,
                "message": "Partida no encontrada"
            }), 404

        return jsonify({
            "success": True,
            "data": partida
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener partida: {str(e)}"
        }), 500


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

        nuevo_id = controlador.crear_historial_partida(
            grupo_id=data.get('grupo_id'),
            cuestionario_id=data.get('cuestionario_id'),
            nombre_grupo=data.get('nombre_grupo'),
            titulo_cuestionario=data.get('titulo_cuestionario'),
            puntuacion=data.get('puntuacion_final', 0),
            num_preguntas=data.get('num_preguntas_total', 0),
            num_miembros=data.get('num_miembros', 0)
        )

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


@app.route("/api/historial_partidas/<int:partida_id>", methods=["PUT"])
def api_actualizar_historial_partida(partida_id):
    """POST/PUT: Actualiza una partida grupal"""
    try:
        data = request.get_json()

        exito = controlador.actualizar_historial_partida(
            partida_id=partida_id,
            puntuacion=data.get('puntuacion_final'),
            num_preguntas=data.get('num_preguntas_total'),
            num_miembros=data.get('num_miembros')
        )

        if not exito:
            return jsonify({
                "success": False,
                "message": "Partida no encontrada"
            }), 404

        return jsonify({
            "success": True,
            "message": "Partida actualizada exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar partida: {str(e)}"
        }), 500


@app.route("/api/historial_partidas/<int:partida_id>", methods=["DELETE"])
def api_eliminar_historial_partida(partida_id):
    """POST/DELETE: Elimina una partida grupal"""
    try:
        exito = controlador.eliminar_historial_partida(partida_id)

        if not exito:
            return jsonify({
                "success": False,
                "message": "Partida no encontrada"
            }), 404

        return jsonify({
            "success": True,
            "message": "Partida eliminada exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar partida: {str(e)}"
        }), 500


# ========================================
# TABLA: estudiantes_stats (RUTAS)
# ========================================

@app.route("/api/estudiantes_stats", methods=["GET"])
def api_obtener_estudiantes_stats():
    """GET: Lista todas las estadísticas de estudiantes"""
    try:
        usuario_id = request.args.get('user_id')
        stats = controlador.obtener_todas_stats(usuario_id)

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


@app.route("/api/estudiantes_stats/<int:user_id>", methods=["GET"])
def api_obtener_estudiante_stats_por_id(user_id):
    """GET: Obtiene las estadísticas de un estudiante específico"""
    try:
        stats = controlador.obtener_stats_por_usuario(user_id)

        if not stats:
            return jsonify({
                "success": False,
                "message": "Estadísticas no encontradas"
            }), 404

        return jsonify({
            "success": True,
            "data": stats
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener estadísticas: {str(e)}"
        }), 500


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

        nuevo_id = controlador.crear_stats_estudiante(
            user_id=data.get('user_id'),
            nivel=data.get('nivel', 1),
            exp_actual=data.get('experiencia_actual', 0),
            exp_total=data.get('experiencia_total', 0),
            monedas=data.get('monedas', 0),
            total_partidas=data.get('total_partidas', 0),
            correctas=data.get('total_preguntas_correctas', 0),
            incorrectas=data.get('total_preguntas_incorrectas', 0),
            mejor_puntaje=data.get('mejor_puntaje', 0),
            racha=data.get('racha_actual', 0),
            mejor_racha=data.get('mejor_racha', 0)
        )

        if nuevo_id is None:
            return jsonify({
                "success": False,
                "message": "Las estadísticas ya existen para este usuario"
            }), 400

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


@app.route("/api/estudiantes_stats/<int:user_id>", methods=["PUT"])
def api_actualizar_estudiante_stats(user_id):
    """POST/PUT: Actualiza las estadísticas de un estudiante"""
    try:
        data = request.get_json()

        exito = controlador.actualizar_stats_estudiante(
            user_id=user_id,
            nivel=data.get('nivel'),
            exp_actual=data.get('experiencia_actual'),
            exp_total=data.get('experiencia_total'),
            monedas=data.get('monedas'),
            total_partidas=data.get('total_partidas'),
            correctas=data.get('total_preguntas_correctas'),
            incorrectas=data.get('total_preguntas_incorrectas'),
            mejor_puntaje=data.get('mejor_puntaje'),
            racha=data.get('racha_actual'),
            mejor_racha=data.get('mejor_racha'),
            ultima_partida=data.get('ultima_partida')
        )

        if not exito:
            return jsonify({
                "success": False,
                "message": "Estadísticas no encontradas"
            }), 404

        return jsonify({
            "success": True,
            "message": "Estadísticas actualizadas exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar estadísticas: {str(e)}"
        }), 500


@app.route("/api/estudiantes_stats/<int:user_id>", methods=["DELETE"])
def api_eliminar_estudiante_stats(user_id):
    """POST/DELETE: Elimina las estadísticas de un estudiante"""
    try:
        exito = controlador.eliminar_stats_estudiante(user_id)

        if not exito:
            return jsonify({
                "success": False,
                "message": "Estadísticas no encontradas"
            }), 404

        return jsonify({
            "success": True,
            "message": "Estadísticas eliminadas exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar estadísticas: {str(e)}"
        }), 500


# ========================================
# TABLA: participantes_partida (RUTAS)
# ========================================

@app.route("/api/participantes_partida", methods=["GET"])
def api_obtener_participantes_partida():
    """GET: Lista participantes de partidas"""
    try:
        partida_id = request.args.get('partida_id')
        usuario_id = request.args.get('usuario_id')

        participantes = controlador.obtener_participantes(partida_id, usuario_id)

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


@app.route("/api/participantes_partida/<int:participante_id>", methods=["GET"])
def api_obtener_participante_partida_por_id(participante_id):
    """GET: Obtiene un participante específico"""
    try:
        participante = controlador.obtener_participante_id(participante_id)

        if not participante:
            return jsonify({
                "success": False,
                "message": "Participante no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "data": participante
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener participante: {str(e)}"
        }), 500


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

        nuevo_id = controlador.registrar_participante(
            partida_id=data.get('partida_id'),
            usuario_id=data.get('usuario_id'),
            nombre_usuario=data.get('nombre_usuario')
        )

        if nuevo_id is None:
            return jsonify({
                "success": False,
                "message": "El participante ya está registrado en esta partida"
            }), 400

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


@app.route("/api/participantes_partida/<int:participante_id>", methods=["PUT"])
def api_actualizar_participante_partida(participante_id):
    """POST/PUT: Actualiza un participante de partida"""
    try:
        data = request.get_json()

        exito = controlador.actualizar_participante(
            participante_id=participante_id,
            nombre_usuario=data.get('nombre_usuario')
        )

        if not exito:
            return jsonify({
                "success": False,
                "message": "Participante no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Participante actualizado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar participante: {str(e)}"
        }), 500


@app.route("/api/participantes_partida/<int:participante_id>", methods=["DELETE"])
def api_eliminar_participante_partida(participante_id):
    """POST/DELETE: Elimina un participante de una partida"""
    try:
        exito = controlador.eliminar_participante(participante_id)

        if not exito:
            return jsonify({
                "success": False,
                "message": "Participante no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Participante eliminado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar participante: {str(e)}"
        }), 500


# ========================================
# TABLA: progreso_grupal (RUTAS)
# ========================================

@app.route("/api/progreso_grupal", methods=["GET"])
def api_obtener_progreso_grupal():
    """GET: Lista el progreso grupal"""
    try:
        grupo_id = request.args.get('grupo_id')
        usuario_id = request.args.get('usuario_id')
        pregunta_index = request.args.get('pregunta_index')

        progresos = controlador.obtener_progreso_grupal(grupo_id, usuario_id, pregunta_index)

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


@app.route("/api/progreso_grupal/<int:progreso_id>", methods=["GET"])
def api_obtener_progreso_grupal_por_id(progreso_id):
    """GET: Obtiene un progreso grupal específico"""
    try:
        progreso = controlador.obtener_progreso_id(progreso_id)

        if not progreso:
            return jsonify({
                "success": False,
                "message": "Progreso no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "data": progreso
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener progreso: {str(e)}"
        }), 500


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

        nuevo_id = controlador.registrar_progreso_upsert(
            grupo_id=data.get('grupo_id'),
            usuario_id=data.get('usuario_id'),
            pregunta_index=data.get('pregunta_index', 0),
            respondio=data.get('respondio', 1)
        )

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


@app.route("/api/progreso_grupal/<int:progreso_id>", methods=["PUT"])
def api_actualizar_progreso_grupal(progreso_id):
    """POST/PUT: Actualiza el progreso grupal"""
    try:
        data = request.get_json()

        exito = controlador.actualizar_progreso_manual(
            progreso_id=progreso_id,
            pregunta_index=data.get('pregunta_index'),
            respondio=data.get('respondio')
        )

        if not exito:
            return jsonify({
                "success": False,
                "message": "Progreso no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Progreso actualizado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar progreso: {str(e)}"
        }), 500


@app.route("/api/progreso_grupal/<int:progreso_id>", methods=["DELETE"])
def api_eliminar_progreso_grupal(progreso_id):
    """POST/DELETE: Elimina un progreso grupal"""
    try:
        exito = controlador.eliminar_progreso(progreso_id)

        if not exito:
            return jsonify({
                "success": False,
                "message": "Progreso no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Progreso eliminado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar progreso: {str(e)}"
        }), 500


# ========================================
# TABLA: respuestas_individuales (RUTAS)
# ========================================

@app.route("/api/respuestas_individuales", methods=["GET"])
def api_obtener_respuestas_individuales():
    """GET: Lista respuestas individuales"""
    try:
        historial_id = request.args.get('historial_id')
        pregunta_id = request.args.get('pregunta_id')

        respuestas = controlador.obtener_respuestas_individuales(historial_id, pregunta_id)

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


@app.route("/api/respuestas_individuales/<int:respuesta_id>", methods=["GET"])
def api_obtener_respuesta_individual_por_id(respuesta_id):
    """GET: Obtiene una respuesta individual específica"""
    try:
        respuesta = controlador.obtener_respuesta_individual_id(respuesta_id)

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

        nuevo_id = controlador.registrar_respuesta_individual(
            historial_id=data.get('historial_id'),
            pregunta_id=data.get('pregunta_id'),
            respuesta_estudiante=data.get('respuesta_estudiante'),
            es_correcta=data.get('es_correcta', 0),
            puntos=data.get('puntos', 0),
            tiempo=data.get('tiempo_respuesta', 0)
        )

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


@app.route("/api/respuestas_individuales/<int:respuesta_id>", methods=["PUT"])
def api_actualizar_respuesta_individual(respuesta_id):
    """POST/PUT: Actualiza una respuesta individual"""
    try:
        data = request.get_json()

        exito = controlador.actualizar_respuesta_individual(
            respuesta_id=respuesta_id,
            respuesta_estudiante=data.get('respuesta_estudiante'),
            es_correcta=data.get('es_correcta'),
            puntos=data.get('puntos'),
            tiempo=data.get('tiempo_respuesta')
        )

        if not exito:
            return jsonify({
                "success": False,
                "message": "Respuesta no encontrada"
            }), 404

        return jsonify({
            "success": True,
            "message": "Respuesta actualizada exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar respuesta: {str(e)}"
        }), 500


@app.route("/api/respuestas_individuales/<int:respuesta_id>", methods=["DELETE"])
def api_eliminar_respuesta_individual(respuesta_id):
    """POST/DELETE: Elimina una respuesta individual"""
    try:
        exito = controlador.eliminar_respuesta_individual(respuesta_id)

        if not exito:
            return jsonify({
                "success": False,
                "message": "Respuesta no encontrada"
            }), 404

        return jsonify({
            "success": True,
            "message": "Respuesta eliminada exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar respuesta: {str(e)}"
        }), 500


# ========================================
# TABLA: reconocimiento_facial (RUTAS)
# ========================================

@app.route("/api/reconocimiento_facial", methods=["GET"])
@token_requerido
def api_obtener_reconocimiento_facial(usuario_id, rol):
    """GET: Obtiene todos los registros de reconocimiento facial"""
    try:
        registros = controlador.obtener_todos_reconocimientos()
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


@app.route("/api/reconocimiento_facial/<int:reconocimiento_id>", methods=["GET"])
@token_requerido
def api_obtener_reconocimiento_facial_por_id(usuario_id, rol, reconocimiento_id):
    """GET: Obtiene un registro de reconocimiento facial específico"""
    try:
        registro = controlador.obtener_reconocimiento_id(reconocimiento_id)

        if not registro:
            return jsonify({
                "success": False,
                "message": "Registro no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "data": registro
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al obtener registro: {str(e)}"
        }), 500


@app.route("/api/reconocimiento_facial", methods=["POST"])
@token_requerido
def api_registrar_reconocimiento_facial(usuario_id, rol):

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

        # Llamada al controlador que maneja la lógica Insert/Update
        resultado = controlador.guardar_o_actualizar_embedding(
            usuario_id=data.get('usuario_id'),
            embedding_list=data.get('embedding')
        )

        return jsonify({
            "success": True,
            "message": resultado["mensaje"],
            "data": {"id": resultado["id"]}
        }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al registrar reconocimiento facial: {str(e)}"
        }), 500


@app.route("/api/reconocimiento_facial/<int:reconocimiento_id>", methods=["PUT"])
@token_requerido
def api_actualizar_reconocimiento_facial(usuario_id, rol, reconocimiento_id):

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

        # Controlador que encapsula verificación de permisos y update
        resultado = controlador.actualizar_embedding_directo(
            reconocimiento_id=reconocimiento_id,
            embedding_list=data.get('embedding'),
            usuario_solicitante=usuario_id,
            rol_solicitante=rol
        )

        if resultado["status"] != 200:
            return jsonify({
                "success": False,
                "message": resultado["message"]
            }), resultado["status"]

        return jsonify({
            "success": True,
            "message": resultado["message"]
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al actualizar reconocimiento facial: {str(e)}"
        }), 500


@app.route("/api/reconocimiento_facial/<int:reconocimiento_id>", methods=["DELETE"])
@token_requerido
@rol_requerido(['profesor'])
def api_eliminar_reconocimiento_facial(usuario_id, rol, reconocimiento_id):

    try:
        exito = controlador.eliminar_reconocimiento(reconocimiento_id)

        if not exito:
            return jsonify({
                "success": False,
                "message": "Registro no encontrado"
            }), 404

        return jsonify({
            "success": True,
            "message": "Reconocimiento facial eliminado exitosamente"
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error al eliminar reconocimiento facial: {str(e)}"
        }), 500

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