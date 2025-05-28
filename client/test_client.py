import sys
import os
import grpc
import uuid
import random
from datetime import datetime, timedelta

# --- Определение корня проекта и добавление в sys.path ---
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import user_service.user_pb2 as user_pb2
import user_service.user_pb2_grpc as user_pb2_grpc
import transaction_service.transaction_pb2 as transaction_pb2
import transaction_service.transaction_pb2_grpc as transaction_pb2_grpc
import report_service.report_pb2 as report_pb2
import report_service.report_pb2_grpc as report_pb2_grpc
import pytest
from common_utils import get_cert_path_from_root, get_ca_chain_path_from_root

CLIENT_NAME_FOR_CERTS = "test_client"

# --- Настройка SSL/TLS для клиента ---
try:
    client_key_path = get_cert_path_from_root(PROJECT_ROOT, CLIENT_NAME_FOR_CERTS, 'client.key')
    client_pem_path = get_cert_path_from_root(PROJECT_ROOT, CLIENT_NAME_FOR_CERTS, 'client.pem')
    ca_chain_pem_path = get_ca_chain_path_from_root(PROJECT_ROOT)

    with open(client_key_path, 'rb') as f: client_private_key = f.read()
    with open(client_pem_path, 'rb') as f: client_certificate_chain = f.read()
    with open(ca_chain_pem_path, 'rb') as f: root_ca_cert = f.read()
except FileNotFoundError as e:
    print(f"CRITICAL: Client certificate file not found - {e}")
    sys.exit(1)

client_credentials = grpc.ssl_channel_credentials(
    root_certificates=root_ca_cert,
    private_key=client_private_key,
    certificate_chain=client_certificate_chain
)

# --- Создание защищенных каналов ---
user_channel_target = os.getenv('USER_SERVICE_HOST', 'localhost') + ':50051'
user_server_cn = 'user.service.local'
user_channel_options = [('grpc.ssl_target_name_override', user_server_cn)]
user_channel = grpc.secure_channel(user_channel_target, client_credentials, options=user_channel_options)
user_stub = user_pb2_grpc.UserServiceStub(user_channel)

transaction_channel_target = os.getenv('TRANSACTION_SERVICE_HOST', 'localhost') + ':50052'
transaction_server_cn = 'transaction.service.local'
transaction_channel_options = [('grpc.ssl_target_name_override', transaction_server_cn)]
transaction_channel = grpc.secure_channel(transaction_channel_target, client_credentials, options=transaction_channel_options)
transaction_stub = transaction_pb2_grpc.TransactionServiceStub(transaction_channel)

report_channel_target = os.getenv('REPORT_SERVICE_HOST', 'localhost') + ':50053'
report_server_cn = 'report.service.local'
report_channel_options = [('grpc.ssl_target_name_override', report_server_cn)]
report_channel = grpc.secure_channel(report_channel_target, client_credentials, options=report_channel_options)
report_stub = report_pb2_grpc.ReportServiceStub(report_channel)


@pytest.fixture(scope="module")
def authenticated_user_info():
    unique_email = f"test_auth_{uuid.uuid4().hex[:8]}@a.com"
    unique_username = f"alice_auth_{uuid.uuid4().hex[:8]}"
    
    print(f"\n[Fixture] Registering user: {unique_email}")
    resp_reg = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=unique_email, username=unique_username, password='123'))
    print(f"[Fixture] Registration response: {resp_reg.status}, ID: {resp_reg.user_id}")
    assert resp_reg.user_id and resp_reg.status == "registered", f"User registration failed for fixture! Status: {resp_reg.status}"
    user_id = resp_reg.user_id
    
    print(f"[Fixture] Authenticating user: {unique_email}")
    auth_resp = user_stub.AuthenticateUser(user_pb2.AuthenticateUserRequest(email=unique_email, password='123'))
    print(f"[Fixture] Authentication response: {auth_resp.status}, Token: {'present' if auth_resp.token else 'absent'}")
    assert auth_resp.status == "authenticated" and auth_resp.token, f"User authentication failed! Status: {auth_resp.status}"
    
    print(f"[Fixture] Getting profile for user ID: {user_id}")
    profile = user_stub.GetUserProfile(user_pb2.GetUserProfileRequest(user_id=user_id))
    print(f"[Fixture] Profile response: User ID: {profile.user_id}, Email: {profile.email}")
    assert profile.user_id == user_id, "Failed to get user profile for fixture"
    
    return {"user_id": user_id, "token": auth_resp.token, "email": unique_email}

def test_user_service_duplicate_email():
    email = f"test_dupe_{uuid.uuid4().hex[:8]}@a.com"
    username1 = f"alice_dupe1_{uuid.uuid4().hex[:8]}"
    username2 = f"alice_dupe2_{uuid.uuid4().hex[:8]}"
    resp1 = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=email, username=username1, password='123'))
    assert resp1.status == "registered"
    resp2 = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=email, username=username2, password='123'))
    print(f"Duplicate email registration response: {resp2.status}")
    assert resp2.status != "registered"

def test_user_service_wrong_password():
    email = f"test_wrongpass_{uuid.uuid4().hex[:8]}@a.com"
    username = f"wrongpass_{uuid.uuid4().hex[:8]}"
    reg_resp = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=email, username=username, password='correctpassword'))
    assert reg_resp.status == "registered"
    auth_resp = user_stub.AuthenticateUser(user_pb2.AuthenticateUserRequest(email=email, password='wrongpassword'))
    print(f"Wrong password auth response: {auth_resp.status}")
    assert auth_resp.status == "invalid credentials"

def test_transaction_service(authenticated_user_info):
    user_id = authenticated_user_info["user_id"]
    token = authenticated_user_info["token"]
    metadata = [('authorization', f'Bearer {token}')]

    print('\n--- Тестирование сервиса транзакций (mTLS & JWT) ---')
    income_amount = round(random.uniform(500, 5000), 2)
    income_category = random.choice(['salary', 'bonus', 'gift'])
    income_date_obj = (datetime(2024, 4, 1) + timedelta(days=random.randint(0, 10)))
    income_date = income_date_obj.strftime('%Y-%m-%d')
    income_desc = random.choice(['Зарплата', 'Премия', 'Подарок'])
    
    resp1 = transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(
        user_id=user_id, amount=income_amount, category=income_category, tx_type='income', date=income_date, description=income_desc),
        metadata=metadata
    )
    print(f'Добавление дохода: {resp1.status}, ID: {resp1.transaction_id}')
    assert resp1.status == "added"
    
    expense_amount = round(random.uniform(100, 1500), 2)
    expense_category = random.choice(['food', 'rent', 'entertainment'])
    expense_date_obj = (income_date_obj + timedelta(days=random.randint(1, 10))) # Расход после дохода
    expense_date = expense_date_obj.strftime('%Y-%m-%d')
    expense_desc = random.choice(['Продукты', 'Аренда', 'Развлечения'])
    
    resp2 = transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(
        user_id=user_id, amount=expense_amount, category=expense_category, tx_type='expense', date=expense_date, description=expense_desc),
        metadata=metadata
    )
    print(f'Добавление расхода: {resp2.status}, ID: {resp2.transaction_id}')
    assert resp2.status == "added"
    
    # Запрос транзакций за период, включающий добавленные
    start_query_date = datetime(2024, 4, 1).strftime('%Y-%m-%d')
    end_query_date = (expense_date_obj + timedelta(days=5)).strftime('%Y-%m-%d') # Чтобы точно включить

    resp3 = transaction_stub.GetTransactions(transaction_pb2.GetTransactionsRequest(
        user_id=user_id, start_date=start_query_date, end_date=end_query_date),
        metadata=metadata
    )
    print(f'Получение транзакций ({len(resp3.transactions)} шт.): первая дата {resp3.transactions[0].date if resp3.transactions else "N/A"}')
    assert len(resp3.transactions) >= 2

def test_transaction_empty_for_new_user():
    email = f"test_empty_tx_{uuid.uuid4().hex[:8]}@a.com"
    username = f"empty_tx_user_{uuid.uuid4().hex[:8]}"
    reg_resp = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=email, username=username, password='123'))
    user_id = reg_resp.user_id
    assert user_id and reg_resp.status == "registered"
    
    auth_resp = user_stub.AuthenticateUser(user_pb2.AuthenticateUserRequest(email=email, password='123'))
    token = auth_resp.token
    metadata = [('authorization', f'Bearer {token}')]

    resp_tx = transaction_stub.GetTransactions(transaction_pb2.GetTransactionsRequest(
        user_id=user_id, start_date='2024-01-01', end_date='2024-12-31'),
        metadata=metadata
    )
    print(f'Транзакции для нового пользователя: {len(resp_tx.transactions)} шт.')
    assert len(resp_tx.transactions) == 0

def test_report_service(authenticated_user_info):
    user_id = authenticated_user_info["user_id"]
    token = authenticated_user_info["token"]
    metadata = [('authorization', f'Bearer {token}')]

    print('\n--- Тестирование сервиса отчетов (mTLS & JWT) ---')
    
    # Добавим несколько транзакций для этого пользователя, чтобы отчет был не пустой
    transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(user_id=user_id, amount=1000, category="salary", tx_type="income", date="2024-04-05", description="ЗП Апрель"), metadata=metadata)
    transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(user_id=user_id, amount=150, category="food", tx_type="expense", date="2024-04-07", description="Продукты"), metadata=metadata)


    resp_gen = report_stub.GenerateMonthlyReport(report_pb2.GenerateMonthlyReportRequest(user_id=user_id, year=2024, month=4),
        metadata=metadata
    )
    print(f'Генерация месячного отчета: User ID {resp_gen.report.user_id}, Income {resp_gen.report.total_income}, Expense {resp_gen.report.total_expense}')
    assert resp_gen.report.user_id == user_id
    assert resp_gen.report.total_income > 0 # Ожидаем, что доход будет, так как добавили транзакцию

    resp_export_json = report_stub.ExportReport(report_pb2.ExportReportRequest(user_id=user_id, year=2024, month=4, format='json'),
        metadata=metadata
    )
    print(f'Экспорт отчета (json): {resp_export_json.status}, URL: {resp_export_json.file_url}')
    assert resp_export_json.status == "exported"
    assert ".json" in resp_export_json.file_url

    resp_export_xml = report_stub.ExportReport(report_pb2.ExportReportRequest(user_id=user_id, year=2024, month=4, format='xml'),
        metadata=metadata
    )
    print(f'Экспорт отчета (xml): {resp_export_xml.status}')
    assert resp_export_xml.status == "unsupported format"

# Тесты на неавторизованный доступ (без JWT или с неверным user_id в токене)
def test_transaction_unauthorized_no_jwt(authenticated_user_info):
    user_id = authenticated_user_info["user_id"]
    try:
        transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(
            user_id=user_id, amount=10, category="test", tx_type="income", date="2024-01-01")
            # БЕЗ metadata
        )
        pytest.fail("Should have raised RpcError for missing JWT")
    except grpc.RpcError as e:
        print(f"No JWT test: RpcError status={e.code()}, details='{e.details()}'")
        assert e.code() == grpc.StatusCode.UNAUTHENTICATED

def test_transaction_unauthorized_wrong_user(authenticated_user_info):
    user_id_owner = authenticated_user_info["user_id"]
    token_owner = authenticated_user_info["token"]
    metadata_owner = [('authorization', f'Bearer {token_owner}')]

    # Создаем "другого" пользователя просто для user_id
    other_user_email = f"other_{uuid.uuid4().hex[:8]}@a.com"
    other_user_name = f"other_user_{uuid.uuid4().hex[:8]}"
    reg_resp_other = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=other_user_email, username=other_user_name, password="password"))
    other_user_id = reg_resp_other.user_id
    assert other_user_id and reg_resp_other.status == "registered"

    try:
        # Пытаемся добавить транзакцию для other_user_id, используя токен user_id_owner
        transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(
            user_id=other_user_id, amount=20, category="hack", tx_type="expense", date="2024-01-02"),
            metadata=metadata_owner # Токен от user_id_owner
        )
        pytest.fail("Should have raised RpcError for mismatched user ID")
    except grpc.RpcError as e:
        print(f"Mismatched user ID test: RpcError status={e.code()}, details='{e.details()}'")
        assert e.code() == grpc.StatusCode.PERMISSION_DENIED