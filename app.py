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
app.config['MAIL_PASSWORD'] = 'rgzl jhyh ceaa snxi'
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

    # === BLOQUE 2: Historial de partidas (CORREGIDO) ===
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

    # 2.2 Cargar historial INDIVIDUAL (CORREGIDO)
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
                        'fecha_partida': resultado['fecha_realizacion'],  # ✅ Campo correcto
                        'nombre_grupo': None,
                        'tipo': 'individual'
                    })

                print(f"   ✅ Partidas individuales: {len(partidas_individuales)}")

        except Exception as e:
            print(f"   ⚠️ No se pudo cargar historial individual: {e}")
            import traceback
            traceback.print_exc()
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

    # === RENDERIZAR ===
    print(f"\n✅ Dashboard cargado")
    print(f"   - Grupo: {'Sí' if grupo_info else 'No'}")
    print(f"   - Miembros: {len(miembros)}")
    print(f"   - Historial: {len(cuestionarios_recientes)}")
    print(f"{'='*70}\n")

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
    if "usuario" not in session or session.get("rol") != "profesor":
        return jsonify({"error": "No autorizado"}), 403

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Obtener estudiantes que están esperando para este cuestionario
            cursor.execute("""
                SELECT u.id, u.nombre, se.estado, se.fecha_ingreso
                FROM salas_espera se
                JOIN usuarios u ON se.usuario_id = u.id
                WHERE se.codigo_pin = %s
                ORDER BY se.fecha_ingreso ASC
            """, (codigo_pin,))

            estudiantes = cursor.fetchall()

            # Formatear timestamp
            for est in estudiantes:
                if est['fecha_ingreso']:
                    tiempo_transcurrido = datetime.now() - est['fecha_ingreso']
                    segundos = int(tiempo_transcurrido.total_seconds())
                    if segundos < 60:
                        est['timestamp'] = f'Hace {segundos}s'
                    elif segundos < 3600:
                        est['timestamp'] = f'Hace {segundos // 60}m'
                    else:
                        est['timestamp'] = est['fecha_ingreso'].strftime('%H:%M')

            return jsonify(estudiantes)
    except Exception as e:
        print(f"Error en api_estudiantes_esperando: {e}")
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

            # ✅ GENERAR ID DE SESIÓN ÚNICO
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
                "sesion_id": sesion_id
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

            # ✅ OBTENER SESION_ID DE LA SALA DE ESPERA
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

            # ✅ CREAR HISTORIAL INDIVIDUAL CON SESION_ID
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
                           nombre_estudiante=nombre_estudiante)


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
    return render_template("sala_espera_individual.html", cuestionario=cuestionario, preguntas=preguntas)


@app.route("/exportar_resultados/<int:cuestionario_id>")
def exportar_resultados(cuestionario_id):
    """Página de opciones de exportación"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    conexion = obtener_conexion()

    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                SELECT titulo, num_preguntas FROM cuestionarios
                WHERE id = %s AND profesor_id = %s
            """, (cuestionario_id, session["user_id"]))

            cuestionario = cursor.fetchone()
            if not cuestionario:
                flash("❌ Cuestionario no encontrado", "error")
                return redirect(url_for("dashboard_profesor"))

            cursor.execute("""
                SELECT COUNT(*) as total FROM historial_partidas
                WHERE cuestionario_id = %s
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


@app.route("/enviar_excel_correo/<int:cuestionario_id>", methods=["POST"])
def enviar_excel_correo(cuestionario_id):
    """Envía el archivo Excel por correo electrónico"""
    if "usuario" not in session or session.get("rol") != "profesor":
        return redirect(url_for("login"))

    try:
        import pandas as pd

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
                df.columns = ['ID Partida', 'Grupo', 'Puntuación', 'Total Preguntas', 'Miembros', 'Fecha', 'Participantes']
                df['Porcentaje (%)'] = (df['Puntuación'] / (df['Total Preguntas'] * 100) * 100).round(2)
                df['Preguntas Correctas'] = (df['Puntuación'] / 100).astype(int)
                df['Preguntas Incorrectas'] = df['Total Preguntas'] - df['Preguntas Correctas']

                # Crear archivo Excel en memoria
                output = BytesIO()
                with pd.ExcelWriter(output, engine='openpyxl') as writer:
                    df.to_excel(writer, sheet_name='Resultados Detallados', index=False)

                    stats_data = {
                        'Métrica': ['Total de Partidas', 'Total de Jugadores', 'Puntuación Promedio', 'Puntuación Máxima', 'Puntuación Mínima', 'Porcentaje Promedio', 'Grupos con +80%', 'Grupos con +60%'],
                        'Valor': [len(df), df['Miembros'].sum(), df['Puntuación'].mean().round(2), df['Puntuación'].max(), df['Puntuación'].min(), df['Porcentaje (%)'].mean().round(2), len(df[df['Porcentaje (%)'] >= 80]), len(df[df['Porcentaje (%)'] >= 60])]
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
                filename = "Resultados_" + cuestionario['titulo'].replace(' ', '_') + "_" + datetime.now().strftime('%Y%m%d_%H%M%S') + ".xlsx"

                # Preparar variables para el correo
                correo_destino = session.get('correo')
                nombre_profesor = session.get('usuario')
                titulo_cuestionario = cuestionario['titulo']
                total_partidas = len(df)
                total_jugadores = int(df['Miembros'].sum())
                fecha_generacion = datetime.now().strftime('%d/%m/%Y a las %H:%M')

                # Crear el mensaje
                msg = Message(
                    subject='Resultados del Cuestionario: ' + titulo_cuestionario,
                    recipients=[correo_destino]
                )

                # Construir HTML del correo sin f-strings
                html_body = '<html><body style="font-family: Arial, sans-serif; background-color: #f5f6fa; padding: 20px;">'
                html_body += '<div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 15px; box-shadow: 0 5px 20px rgba(0,0,0,0.1);">'
                html_body += '<div style="text-align: center; margin-bottom: 30px;"><div style="font-size: 48px; margin-bottom: 15px;">📊</div>'
                html_body += '<h2 style="color: #667eea; margin: 0;">Resultados de Cuestionario</h2></div>'
                html_body += '<p style="color: #333; font-size: 16px;">Hola <strong>' + nombre_profesor + '</strong>,</p>'
                html_body += '<p style="color: #666; line-height: 1.6;">Adjunto encontrarás el archivo Excel con los resultados detallados del cuestionario <strong>"' + titulo_cuestionario + '"</strong>.</p>'
                html_body += '<div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 20px; margin: 25px 0; border-radius: 8px;">'
                html_body += '<h3 style="color: #1976d2; margin-top: 0;">📄 Contenido del Archivo</h3><ul style="color: #0d47a1; line-height: 1.8;">'
                html_body += '<li><strong>Hoja 1:</strong> Resultados detallados de todas las partidas</li>'
                html_body += '<li><strong>Hoja 2:</strong> Estadísticas generales y promedios</li>'
                html_body += '<li><strong>Total de partidas:</strong> ' + str(total_partidas) + '</li>'
                html_body += '<li><strong>Total de jugadores:</strong> ' + str(total_jugadores) + '</li></ul></div>'
                html_body += '<div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0;">'
                html_body += '<p style="color: #856404; margin: 0; font-size: 14px;">💡 <strong>Consejo:</strong> Abre el archivo con Microsoft Excel, Google Sheets o LibreOffice Calc.</p></div>'
                html_body += '<div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0;">'
                html_body += '<p style="color: #999; font-size: 12px; margin: 0;">Sistema de Cuestionarios Interactivos<br>Generado el ' + fecha_generacion + '</p></div>'
                html_body += '</div></body></html>'

                msg.html = html_body

                # Adjuntar Excel
                msg.attach(filename, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', output.getvalue())

                # Enviar
                with app.app_context():
                    mail.send(msg)

                print("Correo enviado exitosamente a " + correo_destino)
                flash("✅ ¡Correo enviado exitosamente a " + correo_destino + "! Revisa tu bandeja de entrada.", "success")
                return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

        finally:
            if conexion and conexion.open:
                conexion.close()

    except ImportError:
        flash("❌ Error: Necesitas instalar pandas y openpyxl", "error")
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))
    except Exception as e:
        flash("❌ Error al enviar el correo: " + str(e), "error")
        print("Error en enviar_excel_correo: " + str(e))
        import traceback
        traceback.print_exc()
        return redirect(url_for("exportar_resultados", cuestionario_id=cuestionario_id))

@app.route("/guardar_respuesta_individual", methods=["POST"])
def guardar_respuesta_individual():
    """Guarda la respuesta de una pregunta individual y devuelve si fue correcta"""
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        data = request.get_json()
        pregunta_id = data.get('pregunta_id')
        respuesta = data.get('respuesta')
        tiempo_respuesta = data.get('tiempo_respuesta', 0)

        user_id = session["user_id"]
        historial_id = session.get('historial_individual_id')

        if not historial_id:
            return jsonify({"success": False, "message": "No hay sesión activa"}), 400

        conexion = obtener_conexion()
        try:
            with conexion.cursor() as cursor:
                # Obtener pregunta y tiempo límite del cuestionario
                cursor.execute("""
                    SELECT p.respuesta_correcta, c.tiempo_pregunta
                    FROM preguntas p
                    JOIN cuestionarios c ON p.cuestionario_id = c.id
                    WHERE p.id = %s
                """, (pregunta_id,))
                pregunta = cursor.fetchone()

                if not pregunta:
                    return jsonify({"success": False, "message": "Pregunta no encontrada"}), 404

                # Calcular puntos basados en velocidad de respuesta
                puntos_obtenidos = 0
                es_correcta = False

                if respuesta is not None:
                    es_correcta = (respuesta == pregunta['respuesta_correcta'])

                    if es_correcta:
                        tiempo_limite = pregunta['tiempo_pregunta']

                        # Sistema de puntos basado en velocidad:
                        # - Respuesta en primeros 25% del tiempo: 1000 puntos
                        # - Respuesta en primeros 50% del tiempo: 800 puntos
                        # - Respuesta en primeros 75% del tiempo: 600 puntos
                        # - Respuesta antes del límite: 400 puntos

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

                # Actualizar puntuación total
                if es_correcta:
                    cursor.execute("""
                        UPDATE historial_individual
                        SET puntuacion_final = puntuacion_final + %s
                        WHERE id = %s
                    """, (puntos_obtenidos, historial_id))

                conexion.commit()

                return jsonify({
                    "success": True,
                    "correcta": es_correcta,
                    "respuesta_correcta": pregunta['respuesta_correcta'],
                    "puntos": puntos_obtenidos
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

            # --- INICIO DE LA CORRECCIÓN ---
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
            print(f"✅ Respuestas cargadas: {len(respuestas_raw)}")

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

            # --- INICIO DE LA CORRECCIÓN 2 ---
            # 3. Determinar posición actual en el ranking
            posicion_actual = 0
            for i, participante in enumerate(ranking_completo, 1):
                if participante['id'] == historial_id:
                    posicion_actual = i
                    break
            print(f"   - Posición en ranking: {posicion_actual}")
            # --- FIN DE LA CORRECCIÓN 2 ---

            # 5. Calcular estadísticas
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

            # 6. Formatear fecha
            try:
                fecha_realizacion_str = historial['fecha_realizacion'].strftime('%d/%m/%Y a las %H:%M')
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

def inicializar_stats_estudiante(usuario_id):
    """Crea el registro de estadísticas para un nuevo estudiante"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                INSERT INTO estudiantes_stats (usuario_id)
                VALUES (%s)
                ON DUPLICATE KEY UPDATE usuario_id=usuario_id
            """, (usuario_id,))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def calcular_xp_necesaria(nivel):
    """Calcula XP necesaria para el siguiente nivel (escala progresiva)"""
    return 100 * nivel + (nivel - 1) * 50

def otorgar_xp(usuario_id, xp_ganada):
    """Otorga XP al estudiante y verifica si sube de nivel"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Obtener stats actuales
            cursor.execute("SELECT * FROM estudiantes_stats WHERE usuario_id = %s", (usuario_id,))
            stats = cursor.fetchone()

            if not stats:
                inicializar_stats_estudiante(usuario_id)
                cursor.execute("SELECT * FROM estudiantes_stats WHERE usuario_id = %s", (usuario_id,))
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
            cursor.execute("""
                UPDATE estudiantes_stats
                SET experiencia_actual = %s,
                    experiencia_total = %s,
                    nivel = %s
                WHERE usuario_id = %s
            """, (nuevo_xp_actual, nuevo_xp_total, nivel_actual, usuario_id))
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

def otorgar_monedas(usuario_id, monedas):
    """Otorga monedas al estudiante"""
    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            cursor.execute("""
                UPDATE estudiantes_stats
                SET monedas = monedas + %s
                WHERE usuario_id = %s
            """, (monedas, usuario_id))
            conexion.commit()
    finally:
        if conexion and conexion.open:
            conexion.close()

def verificar_y_desbloquear_insignias(usuario_id):
    """Verifica y desbloquea insignias que el estudiante haya ganado"""
    conexion = obtener_conexion()
    insignias_desbloqueadas = []

    try:
        with conexion.cursor() as cursor:
            # Obtener stats del estudiante
            cursor.execute("SELECT * FROM estudiantes_stats WHERE usuario_id = %s", (usuario_id,))
            stats = cursor.fetchone()

            if not stats:
                return []

            # Obtener insignias que aún no tiene
            cursor.execute("""
                SELECT i.* FROM insignias i
                WHERE i.id NOT IN (
                    SELECT insignia_id FROM estudiantes_insignias WHERE usuario_id = %s
                )
            """, (usuario_id,))
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
                    cursor.execute("""
                        INSERT INTO estudiantes_insignias (usuario_id, insignia_id)
                        VALUES (%s, %s)
                    """, (usuario_id, insignia['id']))

                    # Otorgar recompensas
                    if insignia['recompensa_xp'] > 0:
                        cursor.execute("""
                            UPDATE estudiantes_stats
                            SET experiencia_total = experiencia_total + %s,
                                experiencia_actual = experiencia_actual + %s
                            WHERE usuario_id = %s
                        """, (insignia['recompensa_xp'], insignia['recompensa_xp'], usuario_id))

                    if insignia['recompensa_monedas'] > 0:
                        cursor.execute("""
                            UPDATE estudiantes_stats
                            SET monedas = monedas + %s
                            WHERE usuario_id = %s
                        """, (insignia['recompensa_monedas'], usuario_id))

                    insignias_desbloqueadas.append(insignia)

            conexion.commit()

    finally:
        if conexion and conexion.open:
            conexion.close()

    return insignias_desbloqueadas

def actualizar_stats_despues_partida(usuario_id, puntuacion, correctas, incorrectas):
    """Actualiza las estadísticas del estudiante después de una partida"""
    from datetime import datetime, date

    conexion = obtener_conexion()
    try:
        with conexion.cursor() as cursor:
            # Inicializar stats si no existen
            cursor.execute("SELECT * FROM estudiantes_stats WHERE usuario_id = %s", (usuario_id,))
            stats = cursor.fetchone()

            if not stats:
                inicializar_stats_estudiante(usuario_id)
                cursor.execute("SELECT * FROM estudiantes_stats WHERE usuario_id = %s", (usuario_id,))
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
            cursor.execute("""
                UPDATE estudiantes_stats SET
                    total_partidas = total_partidas + 1,
                    total_preguntas_correctas = total_preguntas_correctas + %s,
                    total_preguntas_incorrectas = total_preguntas_incorrectas + %s,
                    mejor_puntaje = %s,
                    racha_actual = %s,
                    mejor_racha = %s,
                    ultima_partida = %s
                WHERE usuario_id = %s
            """, (correctas, incorrectas, mejor_puntaje, nueva_racha, mejor_racha, hoy, usuario_id))
            conexion.commit()

            # Calcular XP basada en rendimiento
            xp_base = 50  # XP base por completar
            xp_por_correcta = 10
            xp_bonus_perfecto = 100 if correctas > 0 and incorrectas == 0 else 0

            total_xp = xp_base + (correctas * xp_por_correcta) + xp_bonus_perfecto

            # Otorgar XP y monedas
            resultado_xp = otorgar_xp(usuario_id, total_xp)
            monedas_ganadas = 5 + (correctas * 2)
            otorgar_monedas(usuario_id, monedas_ganadas)

            # Verificar insignias
            insignias_nuevas = verificar_y_desbloquear_insignias(usuario_id)

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
            cursor.execute("SELECT * FROM estudiantes_stats WHERE usuario_id = %s", (user_id,))
            stats = cursor.fetchone()

            if not stats:
                inicializar_stats_estudiante(user_id)
                cursor.execute("SELECT * FROM estudiantes_stats WHERE usuario_id = %s", (user_id,))
                stats = cursor.fetchone()

            if not stats:
                flash("Error al cargar tu perfil. Por favor, contacta al administrador.", "error")
                return redirect(url_for("dashboard_estudiante"))

            # Obtener insignias desbloqueadas
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