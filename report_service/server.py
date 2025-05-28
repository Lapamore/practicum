import grpc
from concurrent import futures
import os
import sys
import csv
import json
from datetime import datetime, timedelta

# --- Определение корня проекта и добавление в sys.path ---
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from report_service import report_pb2
from report_service import report_pb2_grpc
# from report_service import db # report_service больше не ходит в свою БД за транзакциями
from common_utils import get_cert_path_from_root, get_ca_chain_path_from_root, get_jwt_key_path_from_root

# Для JWT валидации
import jwt
from functools import wraps

# Для вызова transaction_service
from transaction_service import transaction_pb2 as ts_pb2
from transaction_service import transaction_pb2_grpc as ts_pb2_grpc


SERVICE_NAME = "report_service"
PORT = "50053"

# JWT Валидация
USER_SERVICE_FOR_JWT_VALIDATION = "user_service"
JWT_PUBLIC_KEY_PATH = get_jwt_key_path_from_root(PROJECT_ROOT, USER_SERVICE_FOR_JWT_VALIDATION, "public")
JWT_ALGORITHMS = ["RS256"]
JWT_EXPECTED_ISSUER = "user.service.local"
JWT_EXPECTED_AUDIENCE_FOR_THIS_SERVICE = "report.service.local"

# --- Декоратор для JWT валидации (аналогичен transaction_service) ---
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
                audience=JWT_EXPECTED_AUDIENCE_FOR_THIS_SERVICE, # Передаем ОДНУ строку
                issuer=JWT_EXPECTED_ISSUER
            )
            context.user_id_from_token = payload.get('sub')
            context.auth_token_for_forwarding = token # Сохраняем токен для проброса
            if not context.user_id_from_token:
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Token is missing user subject (sub).")
                return
        # ... (обработка ошибок jwt как в transaction_service) ...
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
        
        if hasattr(request, 'user_id') and request.user_id != context.user_id_from_token:
            context.abort(grpc.StatusCode.PERMISSION_DENIED,
                          "User ID in request does not match user ID in token.")
            return
        return func(self, request, context)
    return wrapper


def get_month_date_range_strs(year, month):
    start_date = datetime(year, month, 1)
    if month == 12:
        end_date_obj = datetime(year + 1, 1, 1) - timedelta(days=1) # Конец месяца включительно
    else:
        end_date_obj = datetime(year, month + 1, 1) - timedelta(days=1) # Конец месяца включительно
    return start_date.strftime('%Y-%m-%d'), end_date_obj.strftime('%Y-%m-%d')


class ReportServiceServicer(report_pb2_grpc.ReportServiceServicer):
    def __init__(self):
        # Загрузка публичного ключа для валидации JWT
        try:
            with open(JWT_PUBLIC_KEY_PATH, 'rb') as f:
                self.jwt_public_key = f.read()
        except FileNotFoundError:
            print(f"CRITICAL: JWT public key for validation not found at {JWT_PUBLIC_KEY_PATH}")
            sys.exit(1)

        # Настройка mTLS клиента для вызова TransactionService
        client_key_path = get_cert_path_from_root(PROJECT_ROOT, SERVICE_NAME, 'client.key') # Ключ этого сервиса как клиента
        client_pem_path = get_cert_path_from_root(PROJECT_ROOT, SERVICE_NAME, 'client.pem') # Сертификат этого сервиса как клиента
        ca_chain_path = get_ca_chain_path_from_root(PROJECT_ROOT) # Общая CA цепочка

        try:
            with open(client_key_path, 'rb') as f: client_key = f.read()
            with open(client_pem_path, 'rb') as f: client_pem = f.read()
            with open(ca_chain_path, 'rb') as f: ca_chain_for_ts = f.read()
        except FileNotFoundError as e:
            print(f"CRITICAL: ReportService client certs for TransactionService not found - {e}")
            self.transaction_stub = None
            return

        ts_creds = grpc.ssl_channel_credentials(
            root_certificates=ca_chain_for_ts,
            private_key=client_key,
            certificate_chain=client_pem
        )
        ts_channel_target = 'localhost:50052'
        ts_server_cn = 'transaction.service.local'
        ts_channel_options = [('grpc.ssl_target_name_override', ts_server_cn)]
        
        ts_channel = grpc.secure_channel(ts_channel_target, ts_creds, options=ts_channel_options)
        self.transaction_stub = ts_pb2_grpc.TransactionServiceStub(ts_channel)
        print("ReportService initialized mTLS client for TransactionService.")


    @validate_jwt
    def GenerateMonthlyReport(self, request, context):
        if not self.transaction_stub:
            context.abort(grpc.StatusCode.INTERNAL, "TransactionService client not initialized.")
            return report_pb2.GenerateMonthlyReportResponse()

        start_date_str, end_date_str = get_month_date_range_strs(request.year, request.month)
        
        # Проброс JWT токена
        metadata_for_ts = [('authorization', f'Bearer {context.auth_token_for_forwarding}')]

        try:
            ts_req = ts_pb2.GetTransactionsRequest(
                user_id=request.user_id,
                start_date=start_date_str,
                end_date=end_date_str
            )
            print(f"[{SERVICE_NAME}] Вызов TransactionService.GetTransactions. user_id={request.user_id}. Проброс JWT (начало): {context.auth_token_for_forwarding[:20]}...")
            ts_response = self.transaction_stub.GetTransactions(ts_req, metadata=metadata_for_ts)
            print(f"[{SERVICE_NAME}] Ответ от TransactionService получен. Количество транзакций: {len(ts_response.transactions)}")
            
            # Обработка ответа от transaction_service
            categories = {}
            total_income = 0.0
            total_expense = 0.0
            for tx in ts_response.transactions:
                cat = tx.category
                if cat not in categories:
                    categories[cat] = {'income': 0.0, 'expense': 0.0}
                if tx.tx_type == 'income':
                    categories[cat]['income'] += tx.amount
                    total_income += tx.amount
                else: # expense
                    categories[cat]['expense'] += tx.amount
                    total_expense += tx.amount
            
            cat_summaries = [
                report_pb2.CategorySummary(category=cat, income=val['income'], expense=val['expense'])
                for cat, val in categories.items()
            ]
            balance = total_income - total_expense
            report = report_pb2.MonthlyReport(
                user_id=request.user_id,
                year=request.year,
                month=request.month,
                total_income=total_income,
                total_expense=total_expense,
                balance=balance,
                categories=cat_summaries
            )
            return report_pb2.GenerateMonthlyReportResponse(report=report)

        except grpc.RpcError as e:
            print(f"Error calling TransactionService: {e.code()} - {e.details()}")
            context.abort(e.code(), f"Failed to retrieve transactions: {e.details()}")
            return report_pb2.GenerateMonthlyReportResponse()
        except Exception as e:
            print(f"Unexpected error in GenerateMonthlyReport: {e}")
            context.abort(grpc.StatusCode.INTERNAL, "Error generating report.")
            return report_pb2.GenerateMonthlyReportResponse()

    @validate_jwt
    def ExportReport(self, request, context):
        if not self.transaction_stub:
            context.abort(grpc.StatusCode.INTERNAL, "TransactionService client not initialized.")
            return report_pb2.ExportReportResponse(status="error: internal setup")

        start_date_str, end_date_str = get_month_date_range_strs(request.year, request.month)
        metadata_for_ts = [('authorization', f'Bearer {context.auth_token_for_forwarding}')]

        try:
            ts_req = ts_pb2.GetTransactionsRequest(
                user_id=request.user_id,
                start_date=start_date_str,
                end_date=end_date_str
            )
            ts_response = self.transaction_stub.GetTransactions(ts_req, metadata=metadata_for_ts)

            # Логика формирования данных для экспорта (аналогично GenerateMonthlyReport)
            categories = {}
            total_income = 0.0
            total_expense = 0.0
            for tx in ts_response.transactions:
                cat = tx.category
                if cat not in categories: categories[cat] = {'income': 0.0, 'expense': 0.0}
                if tx.tx_type == 'income':
                    categories[cat]['income'] += tx.amount
                    total_income += tx.amount
                else:
                    categories[cat]['expense'] += tx.amount
                    total_expense += tx.amount
            
            cat_summaries_list_of_dicts = [
                {'category': cat, 'income': val['income'], 'expense': val['expense']}
                for cat, val in categories.items()
            ]
            balance = total_income - total_expense
            report_data = {
                'user_id': request.user_id, 'year': request.year, 'month': request.month,
                'total_income': total_income, 'total_expense': total_expense, 'balance': balance,
                'categories': cat_summaries_list_of_dicts
            }

            # Экспорт в файл
            file_dir = os.path.join(PROJECT_ROOT, 'report_service', 'exports') # Убедись, что путь корректен
            os.makedirs(file_dir, exist_ok=True)
            filename = f"report_{request.user_id}_{request.year}_{request.month}.{request.format}"
            file_path = os.path.join(file_dir, filename)

            if request.format == 'json':
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, ensure_ascii=False, indent=2)
            elif request.format == 'csv':
                # CSV для категорий, основные итоги можно добавить как-то иначе или не включать в CSV
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    if cat_summaries_list_of_dicts:
                        writer = csv.DictWriter(f, fieldnames=cat_summaries_list_of_dicts[0].keys())
                        writer.writeheader()
                        writer.writerows(cat_summaries_list_of_dicts)
                    else:
                        f.write("No category data for this period.\n")
                    f.write(f"\nTotal Income,{total_income}\n")
                    f.write(f"Total Expense,{total_expense}\n")
                    f.write(f"Balance,{balance}\n")
            else:
                return report_pb2.ExportReportResponse(file_url="", status="unsupported format")
            
            print(f"Report exported to: {file_path}")
            return report_pb2.ExportReportResponse(file_url=file_path, status="exported")

        except grpc.RpcError as e:
            print(f"Error calling TransactionService for export: {e.code()} - {e.details()}")
            context.abort(e.code(), f"Failed to retrieve transactions for export: {e.details()}")
            return report_pb2.ExportReportResponse(status=f"error: RpcError {e.code()}")
        except Exception as e:
            print(f"Unexpected error in ExportReport: {e}")
            context.abort(grpc.StatusCode.INTERNAL, "Error exporting report.")
            return report_pb2.ExportReportResponse(status=f"error: {str(e)}")


def serve():
    server_key_path = get_cert_path_from_root(PROJECT_ROOT, SERVICE_NAME, 'server.key')
    server_pem_path = get_cert_path_from_root(PROJECT_ROOT, SERVICE_NAME, 'server.pem')
    ca_chain_pem_path = get_ca_chain_path_from_root(PROJECT_ROOT)

    try:
        with open(server_key_path, 'rb') as f: private_key = f.read()
        with open(server_pem_path, 'rb') as f: certificate_chain = f.read()
        with open(ca_chain_pem_path, 'rb') as f: root_certificates = f.read()
    except FileNotFoundError as e:
        print(f"CRITICAL: Certificate file not found - {e}")
        sys.exit(1)

    server_credentials = grpc.ssl_server_credentials(
        private_key_certificate_chain_pairs=[(private_key, certificate_chain)],
        root_certificates=root_certificates,
        require_client_auth=True
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    report_pb2_grpc.add_ReportServiceServicer_to_server(ReportServiceServicer(), server)
    
    server.add_secure_port(f'[::]:{PORT}', server_credentials)
    print(f"gRPC сервер {SERVICE_NAME.replace('_', ' ').title()} (mTLS & JWT) запущен на порту {PORT}")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()