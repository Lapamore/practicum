import grpc
from concurrent import futures
from transaction_service import transaction_pb2
from transaction_service import transaction_pb2_grpc
from transaction_service import db
import psycopg2

class TransactionServiceServicer(transaction_pb2_grpc.TransactionServiceServicer):
    def AddTransaction(self, request, context):
        db.init_db()
        conn = db.get_conn()
        cur = conn.cursor()
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
            transaction_id = ""
            status = f"error: {e.pgerror}"
        finally:
            cur.close()
            conn.close()
        return transaction_pb2.AddTransactionResponse(transaction_id=transaction_id, status=status)

    def GetTransactions(self, request, context):
        db.init_db()
        conn = db.get_conn()
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT id, user_id, amount, category, tx_type, date, description
                FROM transactions
                WHERE user_id=%s AND date BETWEEN %s AND %s
                ORDER BY date
            """, (request.user_id, request.start_date, request.end_date))
            rows = cur.fetchall()
            transactions = [
                transaction_pb2.Transaction(
                    id=str(row['id']),
                    user_id=str(row['user_id']),
                    amount=row['amount'],
                    category=row['category'],
                    tx_type=row['tx_type'],
                    date=str(row['date']),
                    description=row['description'] or ""
                ) for row in rows
            ]
        except Exception as e:
            transactions = []
        finally:
            cur.close()
            conn.close()
        return transaction_pb2.GetTransactionsResponse(transactions=transactions)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    transaction_pb2_grpc.add_TransactionServiceServicer_to_server(TransactionServiceServicer(), server)
    server.add_insecure_port('[::]:50052')
    print("gRPC сервер TransactionService запущен на порту 50052")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
