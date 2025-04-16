import grpc
from concurrent import futures
from user_service import user_pb2
from user_service import user_pb2_grpc
from user_service import db
import hashlib
import psycopg2

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class UserServiceServicer(user_pb2_grpc.UserServiceServicer):
    def RegisterUser(self, request, context):
        db.init_db()
        conn = db.get_conn()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s) RETURNING id, created_at", (
                request.email, request.username, hash_password(request.password)))
            row = cur.fetchone()
            conn.commit()
            user_id = str(row['id'])
            status = "registered"
        except psycopg2.Error as e:
            user_id = ""
            status = f"error: {e.pgerror}"
        finally:
            cur.close()
            conn.close()
        return user_pb2.RegisterUserResponse(user_id=user_id, status=status)

    def AuthenticateUser(self, request, context):
        db.init_db()
        conn = db.get_conn()
        cur = conn.cursor()
        try:
            cur.execute("SELECT id, password_hash FROM users WHERE email=%s", (request.email,))
            row = cur.fetchone()
            if row and row['password_hash'] == hash_password(request.password):
                user_id = str(row['id'])
                token = "token123"  # Для простоты, можно реализовать JWT
                status = "authenticated"
            else:
                user_id = ""
                token = ""
                status = "invalid credentials"
        except Exception as e:
            user_id = ""
            token = ""
            status = f"error: {str(e)}"
        finally:
            cur.close()
            conn.close()
        return user_pb2.AuthenticateUserResponse(user_id=user_id, token=token, status=status)

    def GetUserProfile(self, request, context):
        db.init_db()
        conn = db.get_conn()
        cur = conn.cursor()
        try:
            cur.execute("SELECT id, email, username, created_at FROM users WHERE id=%s", (request.user_id,))
            row = cur.fetchone()
            if row:
                return user_pb2.GetUserProfileResponse(
                    user_id=str(row['id']),
                    email=row['email'],
                    username=row['username'],
                    created_at=str(row['created_at'])
                )
            else:
                return user_pb2.GetUserProfileResponse(user_id="", email="", username="", created_at="")
        except Exception as e:
            return user_pb2.GetUserProfileResponse(user_id="", email="", username="", created_at="")
        finally:
            cur.close()
            conn.close()

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    user_pb2_grpc.add_UserServiceServicer_to_server(UserServiceServicer(), server)
    server.add_insecure_port('[::]:50051')
    print("gRPC сервер UserService запущен на порту 50051")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
