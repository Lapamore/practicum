import grpc
from concurrent import futures
import os
import sys
import psycopg2 # Оставил импорт для db.py

# --- Определение корня проекта и добавление в sys.path ---
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from transaction_service import transaction_pb2
from transaction_service import transaction_pb2_grpc
from transaction_service import db # db.py
from common_utils import get_cert_path_from_root, get_ca_chain_path_from_root, get_jwt_key_path_from_root

# Для JWT валидации
import jwt
from functools import wraps

SERVICE_NAME = "transaction_service"
PORT = "50052"

# JWT Валидация
# Публичный ключ user_service для проверки JWT
USER_SERVICE_FOR_JWT_VALIDATION = "user_service"
JWT_PUBLIC_KEY_PATH = get_jwt_key_path_from_root(PROJECT_ROOT, USER_SERVICE_FOR_JWT_VALIDATION, "public")
JWT_ALGORITHMS = ["RS256"]
JWT_EXPECTED_ISSUER = "user.service.local"
# Вот эта строка важна:
JWT_EXPECTED_AUDIENCE_FOR_THIS_SERVICE = "transaction.service.local" # Ожидаемая аудитория для ЭТОГО сервиса


# --- Декоратор для JWT валидации ---
def validate_jwt(func):
    @wraps(func)
    def wrapper(self, request, context):
        metadata = dict(context.invocation_metadata())
        auth_header = metadata.get('authorization', None)

        if not auth_header or not auth_header.lower().startswith('bearer '):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Authorization token is missing or invalid format.")
            return

        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(
                token,
                self.jwt_public_key,
                algorithms=JWT_ALGORITHMS,
                audience=JWT_EXPECTED_AUDIENCE_FOR_THIS_SERVICE,
                issuer=JWT_EXPECTED_ISSUER
            )
            context.user_id_from_token = payload.get('sub') # Сохраняем user_id из токена
            if not context.user_id_from_token:
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Token is missing user subject (sub).")
                return

        except jwt.ExpiredSignatureError:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Token has expired.")
            return
        except jwt.InvalidAudienceError:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid token audience.")
            return
        except jwt.InvalidIssuerError:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid token issuer.")
            return
        except jwt.PyJWTError as e:
            print(f"JWT validation error: {e}")
            context.abort(grpc.StatusCode.UNAUTHENTICATED, f"Invalid token.")
            return
        
        # Авторизация: проверяем, что user_id в запросе совпадает с user_id из токена
        # Предполагаем, что все запросы к этому сервису содержат поле user_id
        if hasattr(request, 'user_id') and request.user_id != context.user_id_from_token:
            context.abort(grpc.StatusCode.PERMISSION_DENIED,
                          "User ID in request does not match user ID in token.")
            return

        return func(self, request, context)
    return wrapper


class TransactionServiceServicer(transaction_pb2_grpc.TransactionServiceServicer):
    def __init__(self):
        db.init_db() # Инициализация БД
        try:
            with open(JWT_PUBLIC_KEY_PATH, 'rb') as f:
                self.jwt_public_key = f.read()
        except FileNotFoundError:
            print(f"CRITICAL: JWT public key for validation not found at {JWT_PUBLIC_KEY_PATH}")
            sys.exit(1)

    @validate_jwt
    def AddTransaction(self, request, context):
        conn = db.get_conn()
        cur = conn.cursor()
        transaction_id = ""
        status = "error: unknown"
        try:
            cur.execute("""
                INSERT INTO transactions (user_id, amount, category, tx_type, date, description)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, (request.user_id, request.amount, request.category, request.tx_type, request.date, request.description))
            row = cur.fetchone()
            conn.commit()
            transaction_id = str(row['id'])
            status = "added"
        except psycopg2.Error as e:
            status = f"error: db {e.pgcode} - {e.pgerror}"
            print(f"Error adding transaction: {status}")
        except Exception as e:
            status = f"error: {str(e)}"
            print(f"Unexpected error adding transaction: {status}")
        finally:
            if cur: cur.close()
            if conn: conn.close()
        return transaction_pb2.AddTransactionResponse(transaction_id=transaction_id, status=status)

    @validate_jwt
    def GetTransactions(self, request, context):
        conn = db.get_conn()
        cur = conn.cursor()
        transactions_list = []
        try:
            cur.execute("""
                SELECT id, user_id, amount, category, tx_type, date, description
                FROM transactions
                WHERE user_id=%s AND date BETWEEN %s AND %s
                ORDER BY date
            """, (request.user_id, request.start_date, request.end_date))
            rows = cur.fetchall()
            for row in rows:
                transactions_list.append(transaction_pb2.Transaction(
                    id=str(row['id']),
                    user_id=str(row['user_id']),
                    amount=row['amount'],
                    category=row['category'],
                    tx_type=row['tx_type'],
                    date=str(row['date']), # Убедиться, что дата конвертируется в строку корректно
                    description=row['description'] or ""
                ))
        except psycopg2.Error as e:
            print(f"Error getting transactions: db {e.pgcode} - {e.pgerror}")
        except Exception as e:
            print(f"Unexpected error getting transactions: {str(e)}")
        finally:
            if cur: cur.close()
            if conn: conn.close()
        return transaction_pb2.GetTransactionsResponse(transactions=transactions_list)

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
    transaction_pb2_grpc.add_TransactionServiceServicer_to_server(TransactionServiceServicer(), server)
    
    server.add_secure_port(f'[::]:{PORT}', server_credentials)
    print(f"gRPC сервер {SERVICE_NAME.replace('_', ' ').title()} (mTLS & JWT) запущен на порту {PORT}")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()