import sys
import os
import grpc
import uuid
import random
from datetime import datetime, timedelta, timezone # Добавил timezone для datetime.now(timezone.utc)

# --- Определение корня проекта и добавление в sys.path ---
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ... (импорты pb2 и pb2_grpc) ...
import user_service.user_pb2 as user_pb2
import user_service.user_pb2_grpc as user_pb2_grpc
import transaction_service.transaction_pb2 as transaction_pb2
import transaction_service.transaction_pb2_grpc as transaction_pb2_grpc
import report_service.report_pb2 as report_pb2
import report_service.report_pb2_grpc as report_pb2_grpc
import pytest
from common_utils import get_cert_path_from_root, get_ca_chain_path_from_root

CLIENT_NAME_FOR_CERTS = "test_client"
print(f"[Клиент] Инициализация test_client.py. Корень проекта: {PROJECT_ROOT}")

# --- Настройка SSL/TLS для клиента ---
print(f"[Клиент] Загрузка mTLS сертификатов для клиента '{CLIENT_NAME_FOR_CERTS}'...")
try:
    client_key_path = get_cert_path_from_root(PROJECT_ROOT, CLIENT_NAME_FOR_CERTS, 'client.key')
    client_pem_path = get_cert_path_from_root(PROJECT_ROOT, CLIENT_NAME_FOR_CERTS, 'client.pem')
    ca_chain_pem_path = get_ca_chain_path_from_root(PROJECT_ROOT)

    print(f"  Client key: {client_key_path}")
    print(f"  Client pem: {client_pem_path}")
    print(f"  CA chain: {ca_chain_pem_path}")

    with open(client_key_path, 'rb') as f: client_private_key = f.read()
    with open(client_pem_path, 'rb') as f: client_certificate_chain = f.read()
    with open(ca_chain_pem_path, 'rb') as f: root_ca_cert = f.read()
    print(f"[Клиент] mTLS сертификаты успешно загружены.")
except FileNotFoundError as e:
    print(f"CRITICAL: Client certificate file not found - {e}")
    sys.exit(1)

client_credentials = grpc.ssl_channel_credentials(
    root_certificates=root_ca_cert,
    private_key=client_private_key,
    certificate_chain=client_certificate_chain
)
print(f"[Клиент] grpc.ssl_channel_credentials созданы.")

# --- Создание защищенных каналов ---
print("[Клиент] Создание защищенных mTLS каналов к сервисам...")
user_channel_target = os.getenv('USER_SERVICE_HOST', 'localhost') + ':50051'
user_server_cn = 'user.service.local'
user_channel_options = [('grpc.ssl_target_name_override', user_server_cn)]
user_channel = grpc.secure_channel(user_channel_target, client_credentials, options=user_channel_options)
user_stub = user_pb2_grpc.UserServiceStub(user_channel)
print(f"  Канал к UserService ({user_server_cn}@{user_channel_target}) создан.")

transaction_channel_target = os.getenv('TRANSACTION_SERVICE_HOST', 'localhost') + ':50052'
transaction_server_cn = 'transaction.service.local'
transaction_channel_options = [('grpc.ssl_target_name_override', transaction_server_cn)]
transaction_channel = grpc.secure_channel(transaction_channel_target, client_credentials, options=transaction_channel_options)
transaction_stub = transaction_pb2_grpc.TransactionServiceStub(transaction_channel)
print(f"  Канал к TransactionService ({transaction_server_cn}@{transaction_channel_target}) создан.")


report_channel_target = os.getenv('REPORT_SERVICE_HOST', 'localhost') + ':50053'
report_server_cn = 'report.service.local'
report_channel_options = [('grpc.ssl_target_name_override', report_server_cn)]
report_channel = grpc.secure_channel(report_channel_target, client_credentials, options=report_channel_options)
report_stub = report_pb2_grpc.ReportServiceStub(report_channel)
print(f"  Канал к ReportService ({report_server_cn}@{report_channel_target}) создан.")


@pytest.fixture(scope="module")
def authenticated_user_info():
    print(f"\n{'='*10} [Фикстура authenticated_user_info НАЧАЛО] {'='*10}")
    unique_email = f"test_auth_{uuid.uuid4().hex[:8]}@a.com"
    unique_username = f"alice_auth_{uuid.uuid4().hex[:8]}"
    
    print(f"  [Фикстура] Регистрация пользователя: {unique_email}, {unique_username}")
    resp_reg = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=unique_email, username=unique_username, password='123'))
    print(f"  [Фикстура] Ответ регистрации: status={resp_reg.status}, user_id={resp_reg.user_id}")
    assert resp_reg.user_id and resp_reg.status == "registered", f"User registration failed for fixture! Status: {resp_reg.status}"
    user_id = resp_reg.user_id
    
    print(f"  [Фикстура] Аутентификация пользователя: {unique_email}")
    auth_resp = user_stub.AuthenticateUser(user_pb2.AuthenticateUserRequest(email=unique_email, password='123'))
    token_display = auth_resp.token[:20] + "..." if auth_resp.token else "None" # Не выводим весь токен
    print(f"  [Фикстура] Ответ аутентификации: status={auth_resp.status}, user_id={auth_resp.user_id}, token (начало)={token_display}")
    assert auth_resp.status == "authenticated" and auth_resp.token, f"User authentication failed! Status: {auth_resp.status}"
    
    print(f"  [Фикстура] Запрос профиля пользователя ID: {user_id}")
    # Для GetUserProfile тоже нужен JWT, если он защищен
    # Пока предполагаем, что GetUserProfile в user_service не требует JWT или JWT не проверяется строго для этого вызова
    # Если требует, нужно передать metadata=[('authorization', f'Bearer {auth_resp.token}')]
    profile = user_stub.GetUserProfile(user_pb2.GetUserProfileRequest(user_id=user_id))
    print(f"  [Фикстура] Ответ профиля: user_id={profile.user_id}, email={profile.email}")
    assert profile.user_id == user_id, "Failed to get user profile for fixture"
    
    print(f"{'='*10} [Фикстура authenticated_user_info КОНЕЦ] {'='*10}")
    return {"user_id": user_id, "token": auth_resp.token, "email": unique_email}

def test_user_service_duplicate_email():
    print(f"\n{'='*10} [Тест test_user_service_duplicate_email НАЧАЛО] {'='*10}")
    email = f"test_dupe_{uuid.uuid4().hex[:8]}@a.com"
    username1 = f"alice_dupe1_{uuid.uuid4().hex[:8]}"
    username2 = f"alice_dupe2_{uuid.uuid4().hex[:8]}"
    print(f"  Регистрация первого пользователя с email: {email}")
    resp1 = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=email, username=username1, password='123'))
    print(f"  Ответ: {resp1.status}")
    assert resp1.status == "registered"
    print(f"  Попытка регистрации второго пользователя с тем же email: {email}")
    resp2 = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=email, username=username2, password='123'))
    print(f"  Ответ (ожидается ошибка): {resp2.status}")
    assert resp2.status != "registered" # Используем более общее условие
    print(f"{'='*10} [Тест test_user_service_duplicate_email КОНЕЦ] {'='*10}")


def test_user_service_wrong_password():
    print(f"\n{'='*10} [Тест test_user_service_wrong_password НАЧАЛО] {'='*10}")
    email = f"test_wrongpass_{uuid.uuid4().hex[:8]}@a.com"
    username = f"wrongpass_{uuid.uuid4().hex[:8]}"
    print(f"  Регистрация пользователя для теста с неверным паролем: {email}")
    reg_resp = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=email, username=username, password='correctpassword'))
    print(f"  Ответ регистрации: {reg_resp.status}")
    assert reg_resp.status == "registered"
    print(f"  Попытка аутентификации с неверным паролем для: {email}")
    auth_resp = user_stub.AuthenticateUser(user_pb2.AuthenticateUserRequest(email=email, password='wrongpassword'))
    print(f"  Ответ (ожидается 'invalid credentials'): {auth_resp.status}")
    assert auth_resp.status == "invalid credentials"
    print(f"{'='*10} [Тест test_user_service_wrong_password КОНЕЦ] {'='*10}")

def test_transaction_service(authenticated_user_info):
    print(f"\n{'='*10} [Тест test_transaction_service НАЧАЛО] {'='*10}")
    user_id = authenticated_user_info["user_id"]
    token = authenticated_user_info["token"]
    metadata = [('authorization', f'Bearer {token}')]
    print(f"  Используется user_id: {user_id}, token (начало): {token[:20]}...")

    print("  Добавление дохода...")
    # ... (параметры дохода) ...
    resp1 = transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(
        user_id=user_id, amount=100, category='salary', tx_type='income', date='2024-05-01', description='Test income'),
        metadata=metadata
    )
    print(f"  Ответ добавления дохода: {resp1.status}, ID: {resp1.transaction_id}")
    assert resp1.status == "added"
    
    print("  Добавление расхода...")
    # ... (параметры расхода) ...
    resp2 = transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(
        user_id=user_id, amount=20, category='food', tx_type='expense', date='2024-05-02', description='Test expense'),
        metadata=metadata
    )
    print(f"  Ответ добавления расхода: {resp2.status}, ID: {resp2.transaction_id}")
    assert resp2.status == "added"
    
    print("  Запрос транзакций...")
    resp3 = transaction_stub.GetTransactions(transaction_pb2.GetTransactionsRequest(
        user_id=user_id, start_date='2024-05-01', end_date='2024-05-30'),
        metadata=metadata
    )
    print(f"  Получено транзакций: {len(resp3.transactions)}")
    assert len(resp3.transactions) >= 2
    print(f"{'='*10} [Тест test_transaction_service КОНЕЦ] {'='*10}")


def test_transaction_empty_for_new_user():
    print(f"\n{'='*10} [Тест test_transaction_empty_for_new_user НАЧАЛО] {'='*10}")
    # ... (создание нового пользователя, получение токена) ...
    email = f"test_empty_tx_{uuid.uuid4().hex[:8]}@a.com"
    username = f"empty_tx_user_{uuid.uuid4().hex[:8]}"
    print(f"  Регистрация нового пользователя: {email}")
    reg_resp = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=email, username=username, password='123'))
    user_id = reg_resp.user_id
    assert user_id and reg_resp.status == "registered"
    print(f"  Аутентификация нового пользователя: {email}")
    auth_resp = user_stub.AuthenticateUser(user_pb2.AuthenticateUserRequest(email=email, password='123'))
    token = auth_resp.token
    metadata = [('authorization', f'Bearer {token}')]
    print(f"  Используется user_id: {user_id}, token (начало): {token[:20]}...")

    print("  Запрос транзакций для нового пользователя (ожидается 0)...")
    resp_tx = transaction_stub.GetTransactions(transaction_pb2.GetTransactionsRequest(
        user_id=user_id, start_date='2024-01-01', end_date='2024-12-31'),
        metadata=metadata
    )
    print(f"  Получено транзакций: {len(resp_tx.transactions)}")
    assert len(resp_tx.transactions) == 0
    print(f"{'='*10} [Тест test_transaction_empty_for_new_user КОНЕЦ] {'='*10}")


def test_report_service(authenticated_user_info):
    print(f"\n{'='*10} [Тест test_report_service НАЧАЛО] {'='*10}")
    user_id = authenticated_user_info["user_id"]
    token = authenticated_user_info["token"]
    metadata = [('authorization', f'Bearer {token}')]
    print(f"  Используется user_id: {user_id}, token (начало): {token[:20]}...")
    
    print("  Добавление транзакций для отчета...")
    transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(user_id=user_id, amount=1000, category="salary", tx_type="income", date="2024-04-05", description="ЗП Апрель"), metadata=metadata)
    transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(user_id=user_id, amount=150, category="food", tx_type="expense", date="2024-04-07", description="Продукты"), metadata=metadata)

    print("  Генерация месячного отчета (Апрель 2024)...")
    resp_gen = report_stub.GenerateMonthlyReport(report_pb2.GenerateMonthlyReportRequest(user_id=user_id, year=2024, month=4),
        metadata=metadata
    )
    print(f"  Ответ генерации отчета: User ID {resp_gen.report.user_id}, Income {resp_gen.report.total_income}, Expense {resp_gen.report.total_expense}")
    assert resp_gen.report.user_id == user_id
    assert resp_gen.report.total_income >= 1000 # Сумма может быть больше, если тест запускался много раз на тех же данных
    
    print("  Экспорт отчета в JSON...")
    resp_export_json = report_stub.ExportReport(report_pb2.ExportReportRequest(user_id=user_id, year=2024, month=4, format='json'),
        metadata=metadata
    )
    print(f"  Ответ экспорта JSON: {resp_export_json.status}, URL: {resp_export_json.file_url}")
    assert resp_export_json.status == "exported"
    assert ".json" in resp_export_json.file_url

    print("  Экспорт отчета в XML (ожидается ошибка формата)...")
    resp_export_xml = report_stub.ExportReport(report_pb2.ExportReportRequest(user_id=user_id, year=2024, month=4, format='xml'),
        metadata=metadata
    )
    print(f"  Ответ экспорта XML: {resp_export_xml.status}")
    assert resp_export_xml.status == "unsupported format"
    print(f"{'='*10} [Тест test_report_service КОНЕЦ] {'='*10}")


def test_transaction_unauthorized_no_jwt(authenticated_user_info):
    print(f"\n{'='*10} [Тест test_transaction_unauthorized_no_jwt НАЧАЛО] {'='*10}")
    user_id = authenticated_user_info["user_id"]
    print(f"  Попытка добавить транзакцию для user_id: {user_id} БЕЗ JWT токена...")
    try:
        transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(
            user_id=user_id, amount=10, category="test_no_jwt", tx_type="income", date="2024-01-01")
        )
        pytest.fail("Ожидалась ошибка RpcError из-за отсутствия JWT")
    except grpc.RpcError as e:
        print(f"  Получена ожидаемая ошибка RpcError: status={e.code()}, details='{e.details()}'")
        assert e.code() == grpc.StatusCode.UNAUTHENTICATED
    print(f"{'='*10} [Тест test_transaction_unauthorized_no_jwt КОНЕЦ] {'='*10}")


def test_transaction_unauthorized_wrong_user(authenticated_user_info):
    print(f"\n{'='*10} [Тест test_transaction_unauthorized_wrong_user НАЧАЛО] {'='*10}")
    user_id_owner = authenticated_user_info["user_id"]
    token_owner = authenticated_user_info["token"]
    metadata_owner = [('authorization', f'Bearer {token_owner}')]
    print(f"  Токен принадлежит user_id: {user_id_owner}")

    print("  Регистрация 'другого' пользователя...")
    other_user_email = f"other_{uuid.uuid4().hex[:8]}@a.com"
    other_user_name = f"other_user_{uuid.uuid4().hex[:8]}"
    reg_resp_other = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=other_user_email, username=other_user_name, password="password"))
    other_user_id = reg_resp_other.user_id
    assert other_user_id and reg_resp_other.status == "registered"
    print(f"  'Другой' пользователь зарегистрирован с ID: {other_user_id}")

    print(f"  Попытка добавить транзакцию для 'другого' user_id ({other_user_id}) используя токен владельца ({user_id_owner})...")
    try:
        transaction_stub.AddTransaction(transaction_pb2.AddTransactionRequest(
            user_id=other_user_id, amount=20, category="hack_attempt", tx_type="expense", date="2024-01-02"),
            metadata=metadata_owner
        )
        pytest.fail("Ожидалась ошибка RpcError из-за несоответствия user_id")
    except grpc.RpcError as e:
        print(f"  Получена ожидаемая ошибка RpcError: status={e.code()}, details='{e.details()}'")
        assert e.code() == grpc.StatusCode.PERMISSION_DENIED
    print(f"{'='*10} [Тест test_transaction_unauthorized_wrong_user КОНЕЦ] {'='*10}")