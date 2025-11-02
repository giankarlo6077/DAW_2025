import pymysql
import pymysql.cursors

def obtener_conexion():
    return pymysql.connect(
        host='kahootg4.mysql.pythonanywhere-services.com',
        user='kahootg4',
        password='Grupo1234',
        db='kahootg4$pf',
        cursorclass=pymysql.cursors.DictCursor,
        charset='utf8mb4'
    )