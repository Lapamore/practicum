import grpc
from concurrent import futures
import os
import sys
import hashlib
import psycopg2 # Оставил импорт, т.к. он используется в db.py
from datetime import timezone
# --- Определение корня проекта и добавление в sys.path ---
# server.py находится в PRACTICUM/user_service/
# Корень проекта PRACTICUM/ на один уровень выше
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from user_service import user_pb2
from user_service import user_pb2_grpc
from user_service import db # db.py теперь не будет иметь psycopg2 импорта напрямую
from common_utils import get_cert_path_from_root, get_ca_chain_path_from_root, get_jwt_key_path_from_root


SERVICE_NAME = "user_service"
PORT = "50051"
# Путь к публичному ключу JWT (если этот сервис будет проверять токены, сейчас он их выдает)
# JWT_PUBLIC_KEY_PATH = get_jwt_key_path_from_root(PROJECT_ROOT, SERVICE_NAME, "public")
# Путь к приватному ключу JWT (для подписи токенов)
JWT_PRIVATE_KEY_PATH = get_jwt_key_path_from_root(PROJECT_ROOT, SERVICE_NAME, "private")
JWT_ALGORITHM = "RS256"
JWT_ISSUER = "user.service.local"
JWT_AUDIENCE = ["transaction.service.local", "report.service.local"]


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class UserServiceServicer(user_pb2_grpc.UserServiceServicer):
    def __init__(self):
        db.init_db() # Инициализация БД при старте сервиса
        try:
            with open(JWT_PRIVATE_KEY_PATH, 'rb') as f:
                self.jwt_private_key = f.read()
        except FileNotFoundError:
            print(f"CRITICAL: JWT private key not found at {JWT_PRIVATE_KEY_PATH}")
            sys.exit(1)


    def RegisterUser(self, request, context):
        conn = db.get_conn()
        cur = conn.cursor()
        user_id = ""
        status = "error: unknown"
        try:
            cur.execute("INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s) RETURNING id", (
                request.email, request.username, hash_password(request.password)))
            row = cur.fetchone()
            conn.commit()
            user_id = str(row['id'])
            status = "registered"
        except psycopg2.Error as e: # psycopg2.Error импортируется из db.py теперь
            status = f"error: db {e.pgcode} - {e.pgerror}"
            print(f"Error registering user: {status}")
            # context.abort(grpc.StatusCode.ALREADY_EXISTS, "User with this email or username already exists.")
        except Exception as e:
            status = f"error: {str(e)}"
            print(f"Unexpected error registering user: {status}")
        finally:
            if cur: cur.close()
            if conn: conn.close()
        return user_pb2.RegisterUserResponse(user_id=user_id, status=status)

    def AuthenticateUser(self, request, context):
        conn = db.get_conn()
        cur = conn.cursor()
        user_id = ""
        token = ""
        status = "error: unknown"
        try:
            cur.execute("SELECT id, password_hash, username FROM users WHERE email=%s", (request.email,))
            row = cur.fetchone()
            if row and row['password_hash'] == hash_password(request.password):
                user_id_str = str(row['id'])
                username = row.get('username', '')

                # Генерация JWT
                from datetime import datetime, timedelta
                import uuid # Для jti

                payload = {
                    'iss': JWT_ISSUER,
                    'sub': user_id_str, # Subject (user_id)
                    'aud': JWT_AUDIENCE, # Audience
                    'exp': datetime.now(timezone.utc) + timedelta(minutes=60),
                    'iat': datetime.now(timezone.utc),
                    'jti': str(uuid.uuid4()), # JWT ID
                    'username': username # Дополнительная информация
                }
                import jwt # Импортируем здесь, чтобы не было циклической зависимости на старте
                token = jwt.encode(payload, self.jwt_private_key, algorithm=JWT_ALGORITHM)
                user_id = user_id_str
                status = "authenticated"
            else:
                status = "invalid credentials"
        except psycopg2.Error as e:
            status = f"error: db {e.pgcode} - {e.pgerror}"
            print(f"Error authenticating user: {status}")
        except Exception as e:
            status = f"error: {str(e)}"
            print(f"Unexpected error authenticating user: {status}")
        finally:
            if cur: cur.close()
            if conn: conn.close()
        return user_pb2.AuthenticateUserResponse(user_id=user_id, token=token, status=status)

    def GetUserProfile(self, request, context):
        # JWT проверка должна быть здесь, если GetUserProfile требует аутентификации
        # Для примера, пока оставим без явной JWT проверки, но в реальном приложении она нужна
        conn = db.get_conn()
        cur = conn.cursor()
        response = user_pb2.GetUserProfileResponse()
        try:
            # request.user_id должен быть строкой из proto
            cur.execute("SELECT id, email, username, created_at FROM users WHERE id=%s", (int(request.user_id),))
            row = cur.fetchone()
            if row:
                response.user_id=str(row['id'])
                response.email=row['email']
                response.username=row['username']
                response.created_at=str(row['created_at'])
            else:
                # context.abort(grpc.StatusCode.NOT_FOUND, "User not found")
                print(f"User profile not found for ID: {request.user_id}")
        except (psycopg2.Error, ValueError) as e: # ValueError если user_id не число
            error_msg = f"db error: {e.pgcode} - {e.pgerror}" if hasattr(e, 'pgcode') else f"error: {str(e)}"
            print(f"Error getting user profile: {error_msg}")
            # context.abort(grpc.StatusCode.INTERNAL, error_msg)
        except Exception as e:
            print(f"Unexpected error getting user profile: {str(e)}")
            # context.abort(grpc.StatusCode.INTERNAL, f"Error: {str(e)}")
        finally:
            if cur: cur.close()
            if conn: conn.close()
        return response

def serve():
    server_key_path = get_cert_path_from_root(PROJECT_ROOT, SERVICE_NAME, 'server.key')
    server_pem_path = get_cert_path_from_root(PROJECT_ROOT, SERVICE_NAME, 'server.pem')
    ca_chain_pem_path = get_ca_chain_path_from_root(PROJECT_ROOT)

    try:
        with open(server_key_path, 'rb') as f:
            private_key = f.read()
        with open(server_pem_path, 'rb') as f:
            certificate_chain = f.read()
        with open(ca_chain_pem_path, 'rb') as f:
            root_certificates = f.read()
    except FileNotFoundError as e:
        print(f"CRITICAL: Certificate file not found - {e}")
        sys.exit(1)

    server_credentials = grpc.ssl_server_credentials(
        private_key_certificate_chain_pairs=[(private_key, certificate_chain)],
        root_certificates=root_certificates,
        require_client_auth=True
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    user_pb2_grpc.add_UserServiceServicer_to_server(UserServiceServicer(), server)
    
    server.add_secure_port(f'[::]:{PORT}', server_credentials)
    print(f"gRPC сервер {SERVICE_NAME.replace('_', ' ').title()} (mTLS) запущен на порту {PORT}")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()