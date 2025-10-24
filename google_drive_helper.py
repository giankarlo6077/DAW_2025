# google_drive_helper.py
# Archivo auxiliar para integración con Google Drive

import os
import io
# Los imports de 'credentials' y 'flow' ya no son necesarios aquí
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
# import pickle (Ya no se usa pickle)

# --- INICIO DE LA CORRECCIÓN ---
# Obtener la ruta absoluta del directorio donde se encuentra este script
# (p.ej., /home/kahootg4/DAW_2025)
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
# --- FIN DE LA CORRECCIÓN ---

def upload_excel_to_drive(credentials, file_data, filename):
    """
    Función simplificada para subir Excel a Drive
    
    Args:
        credentials (google.oauth2.credentials.Credentials): Las credenciales del usuario.
        file_data (BytesIO): Los datos del archivo Excel en memoria.
        filename (str): El nombre para el archivo en Google Drive.
    """
    try:
        # Construir el servicio de Drive usando las credenciales del usuario
        service = build('drive', 'v3', credentials=credentials)
        
        # Buscar o crear carpeta "Resultados_Cuestionarios"
        folder_name = "Resultados_Cuestionarios"
        
        results = service.files().list(
            q=f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false",
            fields='files(id, name)'
        ).execute()
        
        files = results.get('files', [])
        
        if files:
            folder_id = files[0]['id']
        else:
            # Crear carpeta
            file_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            folder = service.files().create(body=file_metadata, fields='id').execute()
            folder_id = folder.get('id')
        
        # Subir archivo a esa carpeta
        file_metadata = {
            'name': filename,
            'parents': [folder_id]
        }
        mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        media = MediaIoBaseUpload(file_data, mimetype=mimetype, resumable=True)
        
        file = service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, name, webViewLink, webContentLink'
        ).execute()
        
        # Hacer el archivo accesible (opcional, pero útil)
        service.permissions().create(
            fileId=file.get('id'),
            body={'type': 'anyone', 'role': 'reader'}
        ).execute()
        
        return {
            'success': True,
            'file_id': file.get('id'),
            'name': file.get('name'),
            'web_link': file.get('webViewLink'),
            'download_link': file.get('webContentLink')
        }
        
    except Exception as e:
        # Manejar errores comunes de token
        error_str = str(e)
        if 'invalid_grant' in error_str.lower():
            error_msg = "El token de Google ha expirado o ha sido revocado. Por favor, vuelve a conectar tu cuenta."
        elif 'file not found' in error_str.lower():
             error_msg = f"No se encontró el archivo de credenciales. Asegúrate que 'credentials.json' existe."
        else:
            error_msg = str(e)
            
        return {
            'success': False,
            'error': error_msg
        }

# ==============================================================
# CONFIGURACIÓN INICIAL (Ya no es necesario ejecutar este archivo)
# ==============================================================
"""
PASOS PARA CONFIGURAR GOOGLE DRIVE:

1. Crear proyecto en Google Cloud Console:
   - Ve a https://console.cloud.google.com/
   - Crea un nuevo proyecto o selecciona uno existente

2. Habilitar Google Drive API:
   - "APIs & Services" > "Library" > "Google Drive API" > "Enable"

3. Crear credenciales OAuth 2.0:
   - "APIs & Services" > "Credentials" > "Create Credentials" > "OAuth client ID"
   - Tipo de aplicación: "Aplicación web" (¡IMPORTANTE! Cambiar a "Web application")
   - Nombre: "Sistema Cuestionarios Web"
   
4. Configurar Orígenes y URIs de redirección:
   - En "Orígenes de JavaScript autorizados", añade tu URL:
     - Para local: http://127.0.0.1:8080
     - Para PythonAnywhere: https://kahootg4.pythonanywhere.com (O tu URL específica)
   - En "URIs de redirección autorizados", añade la URL de callback:
     - Para local: http://127.0.0.1:8080/oauth2callback
     - Para PythonAnywhere: https://kahootg4.pythonanywhere.com/oauth2callback (O tu URL específica)
   
5. Descargar JSON:
   - Descarga el JSON y renómbralo a "credentials.json"
   - Colócalo en la raíz de tu proyecto (junto a app.py)

6. Configurar pantalla de consentimiento:
   - "OAuth consent screen" > "External"
   - Añade el scope: ../auth/drive.file
   - Añade tu correo como "Usuario de prueba".

7. Conectar Cuenta:
   - Inicia sesión como profesor en tu app.
   - Ve a la página de exportar.
   - Haz clic en "Conectar con Google Drive" y sigue los pasos.
   
8. ¡YA NO SE NECESITA 'token.pickle'!
   - El nuevo flujo guarda las credenciales de CADA usuario en la base de datos.
"""

