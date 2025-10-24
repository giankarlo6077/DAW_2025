from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mail import Mail, Message
from bd import obtener_conexion
import random
import string
import re
import secrets
from datetime import datetime, timedelta
from io import BytesIO
import json
import pandas as pd
import google.oauth2.credentials
import google_drive_helper
from flask import send_file
import traceback


from io import BytesIO
import json

app = Flask(__name__)

# --- CONFIGURACIÓN DE LA APLICACIÓN ---
app.secret_key = 'una-clave-secreta-muy-larga-y-dificil-de-adivinar'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Configuración de correo
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'cevar4@gmail.com'
app.config['MAIL_PASSWORD'] = 'rgzl jhyh ceaa snxi' # Considera usar variables de entorno
app.config['MAIL_DEFAULT_SENDER'] = 'cevar4@gmail.com'
app.config['MAIL_DEBUG'] = True

mail = Mail(app)

# --- IMPORTS DE GOOGLE (MOVIDOS A SUS FUNCIONES) ---
# Se movieron para evitar que la app falle al iniciar si no están instalados
import os
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
CLIENT_SECRETS_FILE = os.path.join(BASE_DIR, 'credentials.json')
SCOPES = ['https://www.googleapis.com/auth/drive.file']


# --- FUNCIONES DE AYUDA ---

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
        correo, password = request.form["correo"], request.form["password"]
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute("SELECT * FROM usuarios WHERE correo = %s", (correo,))
                usuario = cursor.fetchone()
        finally:
            if conexion and conexion.open: conexion.close()
        if not usuario or usuario["password"] != password:
            flash("❌ Correo o contraseña incorrectos", "error")
            return redirect(url_for("login"))
        if not usuario["verificado"]:
            flash("❌ Debes verificar tu cuenta.", "error")
            session.update(temp_usuario_id=usuario['id'], temp_correo=usuario['correo'], temp_nombre=usuario['nombre'])
            return redirect(url_for("verificar_cuenta"))

        session.permanent = True
        session.update(usuario=usuario["nombre"], correo=usuario["correo"], rol=usuario["rol"], user_id=usuario["id"])

        return redirect(url_for("dashboard_profesor") if usuario["rol"] == "profesor" else url_for("dashboard_estudiante"))
    return render_template("iniciosesion.html")

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

# --- RUTAS DE ESTUDIANTE Y GRUPOS ---
@app.route("/dashboard_estudiante")
def dashboard_estudiante():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    grupo_info, miembros, cuestionarios_recientes = None, [], []
    user_id = session.get("user_id")

    # Obtener datos del grupo actual (si existe)
    try:
        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
            usuario_data = cursor.fetchone()
            if usuario_data and usuario_data.get('grupo_id'):
                grupo_id = usuario_data.get('grupo_id')
                cursor.execute("SELECT * FROM grupos WHERE id = %s", (grupo_id,))
                grupo_info = cursor.fetchone()
                cursor.execute("SELECT id, nombre FROM usuarios WHERE grupo_id = %s", (grupo_id,))
                miembros = cursor.fetchall()
    finally:
        if 'conexion' in locals() and conexion.open:
            conexion.close()

    # Obtener el historial personal
    try:
        conexion_historial = obtener_conexion()
        with conexion_historial.cursor() as cursor:
            # Esta consulta lee el TÍTULO que guardamos, ya no necesita la tabla 'cuestionarios'
            cursor.execute("""
                SELECT h.titulo_cuestionario, h.puntuacion_final, h.fecha_partida, h.nombre_grupo
                FROM historial_partidas h
                JOIN participantes_partida p ON h.id = p.partida_id
                WHERE p.usuario_id = %s
                ORDER BY h.fecha_partida DESC
                LIMIT 5
            """, (user_id,))
            cuestionarios_recientes = cursor.fetchall()
    finally:
        if 'conexion_historial' in locals() and conexion_historial.open:
            conexion_historial.close()

    return render_template("dashboard_estudiante.html",
                           nombre=session["usuario"],
                           grupo=grupo_info,
                           miembros=miembros,
                           user_id=user_id,
                           cuestionarios_recientes=cuestionarios_recientes)

@app.route("/crear_grupo", methods=["POST"])
def crear_grupo():
    if "usuario" not in session or session.get("rol") != "estudiante": return redirect(url_for("login"))
    nombre_grupo, user_id = request.form.get("nombre_grupo"), session["user_id"]
    if not nombre_grupo:
        flash("❌ Debes darle un nombre a tu grupo.", "error")
        return redirect(url_for("dashboard_estudiante"))
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
            if cursor.fetchone().get('grupo_id'):
                flash("❌ Ya perteneces a un grupo.", "error")
                return redirect(url_for("dashboard_estudiante"))
            codigo_grupo = generar_codigo_grupo()
            cursor.execute("INSERT INTO grupos (nombre_grupo, codigo_grupo, lider_id) VALUES (%s, %s, %s)", (nombre_grupo, codigo_grupo, user_id))
            conexion.commit()
            nuevo_grupo_id = cursor.lastrowid
            cursor.execute("UPDATE usuarios SET grupo_id = %s WHERE id = %s", (nuevo_grupo_id, user_id))
            conexion.commit()
            flash(f"✅ ¡Grupo '{nombre_grupo}' creado con éxito!", "success")
    except Exception as e:
        flash("❌ Ocurrió un error al crear el grupo.", "error")
        print(f"Error en /crear_grupo: {e}")
    finally:
        if conexion and conexion.open: conexion.close()
    return redirect(url_for("dashboard_estudiante"))

@app.route("/unirse_grupo", methods=["POST"])
def unirse_grupo():
    if "usuario" not in session or session.get("rol") != "estudiante": return redirect(url_for("login"))
    codigo_grupo, user_id = request.form.get("codigo_grupo"), session["user_id"]
    if not codigo_grupo:
        flash("❌ Debes ingresar un código de grupo.", "error")
        return redirect(url_for("dashboard_estudiante"))
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT grupo_id FROM usuarios WHERE id = %s", (user_id,))
            if cursor.fetchone().get('grupo_id'):
                flash("❌ Ya perteneces a un grupo.", "error")
                return redirect(url_for("dashboard_estudiante"))
            cursor.execute("SELECT id FROM grupos WHERE codigo_grupo = %s", (codigo_grupo,))
            if not (grupo := cursor.fetchone()):
                flash("❌ No se encontró ningún grupo con ese código.", "error")
                return redirect(url_for("dashboard_estudiante"))
            cursor.execute("UPDATE usuarios SET grupo_id = %s WHERE id = %s", (grupo['id'], user_id))
            conexion.commit()
            flash("✅ Te has unido al grupo exitosamente.", "success")
    except Exception as e:
        flash("❌ Ocurrió un error al unirte al grupo.", "error")
        print(f"Error en /unirse_grupo: {e}")
    finally:
        if conexion and conexion.open: conexion.close()
    return redirect(url_for("dashboard_estudiante"))

@app.route("/salir_grupo")
def salir_grupo():
    if "usuario" not in session or session.get("rol") != "estudiante": return redirect(url_for("login"))
    user_id = session["user_id"]
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT g.id, g.lider_id FROM grupos g JOIN usuarios u ON g.id = u.grupo_id WHERE u.id = %s", (user_id,))
            if not (grupo := cursor.fetchone()):
                flash("❌ No perteneces a ningún grupo.", "error")
                return redirect(url_for("dashboard_estudiante"))
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
        if conexion and conexion.open: conexion.close()
    return redirect(url_for("dashboard_estudiante"))

@app.route("/juego_grupo", methods=["POST"])
def juego_grupo():
    """Inicia un juego grupal - VALIDANDO QUE SEA MODO GRUPAL"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return redirect(url_for("login"))

    pin = request.form.get("pin")
    user_id = session["user_id"]

    if not pin:
        flash("❌ Debes ingresar un código PIN.", "error")
        return redirect(url_for("dashboard_estudiante"))

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Verificar que el usuario está en un grupo
            cursor.execute("""
                SELECT g.id, g.lider_id, g.nombre_grupo
                FROM grupos g
                JOIN usuarios u ON g.id = u.grupo_id
                WHERE u.id = %s
            """, (user_id,))
            grupo = cursor.fetchone()

            if not grupo:
                flash("❌ Debes estar en un grupo para jugar en modo grupal.", "error")
                return redirect(url_for('dashboard_estudiante'))

            if grupo['lider_id'] != user_id:
                flash("❌ Solo el líder del grupo puede iniciar una partida.", "error")
                return redirect(url_for('dashboard_estudiante'))

            # VALIDACIÓN CRÍTICA: Verificar que el cuestionario sea GRUPAL
            cursor.execute("SELECT id, titulo, modo_juego FROM cuestionarios WHERE codigo_pin = %s", (pin,))
            cuestionario = cursor.fetchone()

            if not cuestionario:
                flash(f"❌ No se encontró ningún cuestionario con el PIN '{pin}'.", "error")
                return redirect(url_for('dashboard_estudiante'))

            # NUEVA VALIDACIÓN
            if cuestionario['modo_juego'] != 'grupal':
                flash(f"❌ El cuestionario '{cuestionario['titulo']}' está configurado para juego INDIVIDUAL. No se puede jugar en grupo.", "error")
                return redirect(url_for('dashboard_estudiante'))

            # Actualizar el grupo con el PIN activo
            cursor.execute("""
                UPDATE grupos
                SET active_pin = %s,
                    game_state = 'waiting',
                    current_question_index = 0,
                    current_score = 0
                WHERE id = %s
            """, (pin, grupo['id']))
            conexion.commit()

            print(f"✅ Juego grupal validado - Grupo: {grupo['id']}, PIN: {pin}, Modo: {cuestionario['modo_juego']}")

            return redirect(url_for('sala_espera_grupo', grupo_id=grupo['id']))

    except Exception as e:
        flash("❌ Error al iniciar el juego grupal.", "error")
        print(f"❌ Error en /juego_grupo: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('dashboard_estudiante'))
    finally:
        if conexion and conexion.open:
            conexion.close()

@app.route("/sala_profesor/<codigo_pin>")
def sala_profesor(codigo_pin):
    """Sala donde el profesor ve los grupos esperando y puede iniciar la partida"""
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

            # Obtener grupos que están esperando para jugar este cuestionario
            cursor.execute("""
                SELECT g.id, g.nombre_grupo, g.game_state, g.lider_id,
                       COUNT(u.id) as num_miembros,
                       GROUP_CONCAT(u.nombre SEPARATOR ', ') as miembros
                FROM grupos g
                LEFT JOIN usuarios u ON g.id = u.grupo_id
                WHERE g.active_pin = %s
                GROUP BY g.id
            """, (codigo_pin,))
            grupos_esperando = cursor.fetchall()

            return render_template("sala_profesor.html",
                                   cuestionario=cuestionario,
                                   grupos_esperando=grupos_esperando)
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
    if "usuario" not in session: return redirect(url_for('login'))

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM grupos WHERE id = %s", (grupo_id,))
            grupo = cursor.fetchone()
            cursor.execute("SELECT id, nombre FROM usuarios WHERE grupo_id = %s", (grupo_id,))
            miembros = cursor.fetchall()

            if not grupo:
                return redirect(url_for('dashboard_estudiante'))

            return render_template('sala_espera_grupo.html', grupo=grupo, miembros=miembros, user_id=session['user_id'])
    finally:
        if conexion and conexion.open: conexion.close()

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
                return jsonify(None)

            return jsonify(estado)
    except Exception as e:
        print(f"Error en api_estado_grupo: {e}")
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
                SELECT g.current_question_index, g.current_score, g.game_state, c.id as cuestionario_id
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
                    return jsonify({
                        "tiene_respuesta": True,
                        "respuesta_correcta": pregunta['respuesta_correcta'],
                        "nuevo_score": juego['current_score']
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
                    game_state = %s
                WHERE id = %s
            """, (nuevo_index, nuevo_estado, grupo_id))

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
    if "usuario" not in session or session.get("rol") != "estudiante": return redirect(url_for("login"))
    pin = request.form.get("pin")
    if not pin:
        flash("❌ Debes ingresar un código PIN.", "error")
        return redirect(url_for("dashboard_estudiante"))
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("SELECT * FROM cuestionarios WHERE codigo_pin = %s", (pin,))
            if not (cuestionario := cursor.fetchone()):
                flash(f"❌ No se encontró ningún cuestionario con el PIN '{pin}'.", "error")
                return redirect(url_for("dashboard_estudiante"))

            # NUEVA VALIDACIÓN: No permitir visualizar un cuestionario grupal aquí
            if cuestionario['modo_juego'] == 'grupal':
                flash(f"❌ El PIN '{pin}' es para un juego GRUPAL. Únete a un grupo para jugarlo.", "error")
                return redirect(url_for("dashboard_estudiante"))

            cursor.execute("SELECT * FROM preguntas WHERE cuestionario_id = %s ORDER BY orden", (cuestionario['id'],))
            preguntas = cursor.fetchall()
    finally:
        if conexion and conexion.open: conexion.close()
    return render_template("visualizar_cuestionario.html", cuestionario=cuestionario, preguntas=preguntas)


@app.route("/configurar_google_drive")
def configurar_google_drive():
    """Página de configuración de Google Drive"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    # CORRECCIÓN DE ERROR DE SINTAXIS
    return render_template("configurar_drive.html")

@app.route("/google_auth")
def google_auth():
    """Inicia el flujo de autenticación con Google"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        from google_auth_oauthlib.flow import Flow

        # Crear el flujo de OAuth
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True)
        )

        # Generar URL de autorización
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )

        # Guardar el state en la sesión
        session['state'] = state

        return redirect(authorization_url)

    except FileNotFoundError:
        flash("❌ Error: No se encontró el archivo credentials.json. Asegúrate de haberlo configurado correctamente.", "error")
        return redirect(url_for('configurar_google_drive'))
    except Exception as e:
        flash(f"❌ Error al conectar con Google: {str(e)}", "error")
        print(f"Error en google_auth: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('dashboard_profesor'))


@app.route("/oauth2callback")
def oauth2callback():
    """Callback de Google OAuth - guarda las credenciales en la BD"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        from google_auth_oauthlib.flow import Flow

        # Verificar el state para prevenir CSRF
        state = session.get('state')
        if not state:
            flash("❌ Error de autenticación: Estado inválido", "error")
            return redirect(url_for('dashboard_profesor'))

        # Crear el flujo de OAuth con el mismo redirect_uri
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=state,
            redirect_uri=url_for('oauth2callback', _external=True)
        )

        # Intercambiar el código de autorización por credenciales
        flow.fetch_token(authorization_response=request.url)

        # Obtener las credenciales
        credentials = flow.credentials

        # Guardar las credenciales en la base de datos
        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                cursor.execute(
                    "UPDATE usuarios SET google_creds_json = %s WHERE id = %s",
                    (credentials.to_json(), session['user_id'])
                )
                conexion.commit()

            flash("✅ Google Drive conectado exitosamente", "success")
            print(f"✅ Credenciales guardadas para usuario {session['user_id']}")

        finally:
            if conexion and conexion.open:
                conexion.close()

        # Redirigir de vuelta a la configuración
        return redirect(url_for('configurar_google_drive'))

    except Exception as e:
        flash(f"❌ Error al completar la autenticación: {str(e)}", "error")
        print(f"Error en oauth2callback: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('dashboard_profesor'))

# CORRECCIÓN DE ERROR DE RUTA DUPLICADA:
@app.route("/exportar_resultados/<int:cuestionario_id>")
def exportar_resultados(cuestionario_id):
    """Página de opciones de exportación"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    conexion = obtener_conexion()
    is_drive_connected = False
    try:
        with conexion.cursor() as cursor:
            # Verificar que el cuestionario pertenece al profesor
            cursor.execute("""
                SELECT titulo, num_preguntas FROM cuestionarios
                WHERE id = %s AND profesor_id = %s
            """, (cuestionario_id, session["user_id"]))

            cuestionario = cursor.fetchone()
            if not cuestionario:
                flash("❌ Cuestionario no encontrado", "error")
                return redirect(url_for("dashboard_profesor"))

            # Contar resultados disponibles
            cursor.execute("""
                SELECT COUNT(*) as total FROM historial_partidas
                WHERE cuestionario_id = %s
            """, (cuestionario_id,))
            total_resultados = cursor.fetchone()['total']

            # Verificar si el profesor tiene credenciales de Google
            cursor.execute("SELECT google_creds_json FROM usuarios WHERE id = %s", (session['user_id'],))
            usuario = cursor.fetchone()
            if usuario and usuario['google_creds_json']:
                is_drive_connected = True

    finally:
        if conexion and conexion.open:
            conexion.close()

    return render_template("exportar_opciones.html",
                           cuestionario=cuestionario,
                           cuestionario_id=cuestionario_id,
                           total_resultados=total_resultados,
                           is_drive_connected=is_drive_connected) # Pasar esta variable al HTML

@app.route("/descargar_excel/<int:cuestionario_id>")
def descargar_excel(cuestionario_id):
    """Descarga directa del Excel"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        # --- CORRECCIÓN: Imports movidos aquí ---
        import pandas as pd
        import openpyxl
        from flask import send_file
        # --- FIN CORRECCIÓN ---

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # Verificar que el cuestionario pertenece al profesor
                cursor.execute("""
                    SELECT titulo FROM cuestionarios
                    WHERE id = %s AND profesor_id = %s
                """, (cuestionario_id, session["user_id"]))

                cuestionario = cursor.fetchone()
                if not cuestionario:
                    flash("❌ Cuestionario no encontrado", "error")
                    return redirect(url_for("dashboard_profesor"))

                # Obtener resultados de las partidas
                cursor.execute("""
                    SELECT
                        h.id as partida_id,
                        h.nombre_grupo,
                        h.puntuacion_final,
                        h.num_preguntas_total,
                        h.num_miembros,
                        h.fecha_partida,
                        GROUP_CONCAT(p.nombre_usuario SEPARATOR ', ') as participantes
                    FROM historial_partidas h
                    LEFT JOIN participantes_partida p ON h.id = p.partida_id
                    WHERE h.cuestionario_id = %s
                    GROUP BY h.id
                    ORDER BY h.fecha_partida DESC
                """, (cuestionario_id,))

                resultados = cursor.fetchall()

                if not resultados:
                    flash("⚠️ No hay resultados para exportar", "warning")
                    return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

                # Crear DataFrame
                df = pd.DataFrame(resultados)

                # Renombrar columnas
                df.columns = ['ID Partida', 'Grupo', 'Puntuación', 'Total Preguntas',
                               'Miembros', 'Fecha', 'Participantes']

                # Calcular porcentaje y estadísticas
                df['Porcentaje (%)'] = (df['Puntuación'] / (df['Total Preguntas'] * 100) * 100).round(2)
                df['Preguntas Correctas'] = (df['Puntuación'] / 100).astype(int)
                df['Preguntas Incorrectas'] = df['Total Preguntas'] - df['Preguntas Correctas']

                # Crear archivo Excel en memoria con múltiples hojas
                output = BytesIO()
                with pd.ExcelWriter(output, engine='openpyxl') as writer:
                    # Hoja 1: Resultados detallados
                    df.to_excel(writer, sheet_name='Resultados Detallados', index=False)

                    # Hoja 2: Estadísticas generales
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
                                    # --- CORRECCIÓN DE BUG ---
                                    # Convertir a string ANTES de medir la longitud
                                    if len(str(cell.value)) > max_length:
                                        max_length = len(str(cell.value))
                                    # --- FIN CORRECCIÓN ---
                                except:
                                    pass
                            adjusted_width = min(max_length + 2, 50)
                            worksheet.column_dimensions[column_cells[0].column_letter].width = adjusted_width

                output.seek(0)

                # Nombre del archivo
                filename = f"Resultados_{cuestionario['titulo'].replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

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

@app.route("/exportar_google_drive/<int:cuestionario_id>")
def exportar_google_drive(cuestionario_id):
    """Exporta los resultados a Google Drive"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    user_id = session['user_id']
    conexion = None # Inicializa conexion a None

    try:
        # --- Imports necesarios SOLO para esta función ---
        from google.oauth2.credentials import Credentials
        # --- Fin imports locales ---

        conexion = obtener_conexion()
        with conexion.cursor() as cursor:
            # 1. Obtener credenciales de Google del usuario
            cursor.execute("SELECT google_creds_json FROM usuarios WHERE id = %s", (user_id,))
            usuario = cursor.fetchone()
            if not usuario or not usuario.get('google_creds_json'):
                flash("❌ No tienes conectada tu cuenta de Google Drive.", "error")
                return redirect(url_for('exportar_resultados', cuestionario_id=cuestionario_id))

            # Cargar las credenciales
            try:
                creds_info = json.loads(usuario['google_creds_json'])
                # IMPORTANTE: Asegúrate que SCOPES esté definido globalmente o aquí
                credentials = Credentials.from_authorized_user_info(creds_info, SCOPES)
            except Exception as cred_error:
                print(f"❌ Error al cargar credenciales: {cred_error}")
                flash("❌ Hubo un error al cargar tus credenciales de Google. Intenta reconectar tu cuenta.", "error")
                return redirect(url_for('configurar_google_drive')) # O a donde configures Drive

            # 2. Obtener datos del cuestionario y resultados (similar a descargar_excel)
            cursor.execute("SELECT titulo FROM cuestionarios WHERE id = %s AND profesor_id = %s",
                           (cuestionario_id, user_id))
            cuestionario = cursor.fetchone()
            if not cuestionario:
                flash("❌ Cuestionario no encontrado", "error")
                return redirect(url_for("dashboard_profesor"))

            cursor.execute("""
                SELECT h.*, GROUP_CONCAT(p.nombre_usuario SEPARATOR ', ') as participantes
                FROM historial_partidas h
                LEFT JOIN participantes_partida p ON h.id = p.partida_id
                WHERE h.cuestionario_id = %s
                GROUP BY h.id ORDER BY h.fecha_partida DESC
            """, (cuestionario_id,))
            resultados = cursor.fetchall()

            if not resultados:
                flash("⚠️ No hay resultados para exportar", "warning")
                return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

            # 3. Crear DataFrame y Excel en memoria (igual que en descargar_excel)
            df = pd.DataFrame(resultados)
            df.rename(columns={ # Renombrar columnas para claridad
                'id': 'ID Partida', 'nombre_grupo': 'Grupo', 'puntuacion_final': 'Puntuación',
                'num_preguntas_total': 'Total Preguntas', 'num_miembros': 'Miembros', 'fecha_partida': 'Fecha'
            }, inplace=True)
            df = df[['ID Partida', 'Grupo', 'Puntuación', 'Total Preguntas',
                     'Miembros', 'Fecha', 'participantes']] # Reordenar si es necesario
            df['Porcentaje (%)'] = (df['Puntuación'] / (df['Total Preguntas'] * 100) * 100).round(2)
            df['Preguntas Correctas'] = (df['Puntuación'] / 100).astype(int)
            df['Preguntas Incorrectas'] = df['Total Preguntas'] - df['Preguntas Correctas']

            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Resultados Detallados', index=False)
                # Aquí podrías añadir la hoja de estadísticas igual que en descargar_excel si quieres

                # Ajustar ancho de columnas (opcional pero recomendado)
                worksheet = writer.sheets['Resultados Detallados']
                for column in worksheet.columns:
                     max_length = 0
                     column_letter = column[0].column_letter
                     for cell in column:
                         try:
                             if len(str(cell.value)) > max_length:
                                 max_length = len(str(cell.value))
                         except:
                             pass
                     adjusted_width = min(max_length + 2, 50)
                     worksheet.column_dimensions[column_letter].width = adjusted_width

            output.seek(0)

            # 4. Preparar nombre de archivo
            filename = f"Resultados_{cuestionario['titulo'].replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

            # 5. Llamar a la función del helper para subir el archivo
            resultado_subida = google_drive_helper.upload_excel_to_drive(credentials, output, filename)

            # 6. Manejar el resultado de la subida
            if resultado_subida['success']:
                flash("✅ Archivo exportado a Google Drive exitosamente.", "success")
                # Pasar datos a la página de éxito
                return render_template('export_success.html',
                                       filename=resultado_subida['name'],
                                       drive_link=resultado_subida['web_link'],
                                       download_link=resultado_subida['download_link'])
            else:
                flash(f"❌ Error al subir a Google Drive: {resultado_subida['error']}", "error")
                # Si el error es por token inválido, sugerir reconectar
                if 'invalid_grant' in resultado_subida['error'].lower():
                    return redirect(url_for('configurar_google_drive'))
                else:
                     return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

    except ImportError:
        flash("❌ Error: Faltan librerías para exportar (pandas, openpyxl, google-api-python-client, etc.).", "error")
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))
    except Exception as e:
        flash(f"❌ Error inesperado al exportar a Drive: {str(e)}", "error")
        print(f"Error en exportar_google_drive: {e}")
        traceback.print_exc() # Imprime el error detallado en tus logs del servidor
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))
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
