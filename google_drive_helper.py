# google_drive_helper.py
# Archivo auxiliar para integración con Google Drive

import os
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

# Obtener la ruta absoluta del directorio donde se encuentra este script
BASE_DIR = os.path.dirname(os.path.realpath(__file__))

def upload_excel_to_drive(credentials, file_data, filename):
    """
    Función para subir archivo Excel a Google Drive

    Args:
        credentials: Credenciales OAuth2 del usuario
        file_data: BytesIO con los datos del archivo
        filename: Nombre del archivo a crear

    Returns:
        dict: Resultado de la operación con success, file_id, enlaces, etc.
    """
    try:
        # Construir el servicio de Drive
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
            print(f"✅ Carpeta encontrada: {folder_id}")
        else:
            # Crear carpeta
            file_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            folder = service.files().create(body=file_metadata, fields='id').execute()
            folder_id = folder.get('id')
            print(f"✅ Carpeta creada: {folder_id}")

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

        print(f"✅ Archivo subido: {file.get('name')} - ID: {file.get('id')}")

        # Hacer el archivo público (lectura para cualquiera con el enlace)
        try:
            service.permissions().create(
                fileId=file.get('id'),
                body={'type': 'anyone', 'role': 'reader'}
            ).execute()
            print(f"✅ Permisos configurados para: {file.get('id')}")
        except Exception as perm_error:
            print(f"⚠️ Advertencia al configurar permisos: {perm_error}")

        return {
            'success': True,
            'file_id': file.get('id'),
            'name': file.get('name'),
            'web_link': file.get('webViewLink'),
            'download_link': file.get('webContentLink')
        }

    except Exception as e:
        # Manejar errores comunes
        error_str = str(e).lower()

        if 'invalid_grant' in error_str:
            error_msg = "El token de Google ha expirado o ha sido revocado. Por favor, vuelve a conectar tu cuenta."
        elif 'credentials' in error_str:
            error_msg = "Las credenciales de Google no son válidas. Por favor, reconéctate."
        elif 'quota' in error_str:
            error_msg = "Se ha excedido la cuota de Google Drive. Intenta más tarde."
        else:
            error_msg = f"Error al subir archivo: {str(e)}"

        print(f"❌ Error en upload_excel_to_drive: {error_msg}")
        import traceback
        traceback.print_exc()

        return {
            'success': False,
            'error': error_msg
        }
