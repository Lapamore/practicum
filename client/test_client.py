import sys
import os
import grpc
import uuid
import random
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import user_service.user_pb2 as user_pb2
import user_service.user_pb2_grpc as user_pb2_grpc
import transaction_service.transaction_pb2 as transaction_pb2
import transaction_service.transaction_pb2_grpc as transaction_pb2_grpc
import report_service.report_pb2 as report_pb2
import report_service.report_pb2_grpc as report_pb2_grpc
import pytest

@pytest.fixture(scope="module")
def user_id():
    channel = grpc.insecure_channel('localhost:50051')
    stub = user_pb2_grpc.UserServiceStub(channel)
    unique_email = f"test_{uuid.uuid4().hex[:8]}@a.com"
    unique_username = f"alice_{uuid.uuid4().hex[:8]}"
    resp = stub.RegisterUser(user_pb2.RegisterUserRequest(email=unique_email, username=unique_username, password='123'))
    print('Регистрация пользователя:', resp)
    user_id = resp.user_id
    assert user_id, "User registration failed!"
    auth = stub.AuthenticateUser(user_pb2.AuthenticateUserRequest(email=unique_email, password='123'))
    print('Аутентификация пользователя:', auth)
    assert auth.status == "authenticated"
    profile = stub.GetUserProfile(user_pb2.GetUserProfileRequest(user_id=user_id))
    print('Профиль пользователя:', profile)
    return user_id

def test_user_service_duplicate_email():
    """Проверка ошибки при повторной регистрации пользователя с тем же email."""
    channel = grpc.insecure_channel('localhost:50051')
    stub = user_pb2_grpc.UserServiceStub(channel)
    email = f"test_dupe_{uuid.uuid4().hex[:8]}@a.com"
    username1 = f"alice_dupe1_{uuid.uuid4().hex[:8]}"
    username2 = f"alice_dupe2_{uuid.uuid4().hex[:8]}"
    # Первая регистрация
    resp1 = stub.RegisterUser(user_pb2.RegisterUserRequest(email=email, username=username1, password='123'))
    assert resp1.status == "registered"
    # Повторная регистрация с тем же email
    resp2 = stub.RegisterUser(user_pb2.RegisterUserRequest(email=email, username=username2, password='123'))
    print('Повторная регистрация пользователя:', resp2)
    assert resp2.status != "registered"

def test_user_service_wrong_password(user_id):
    """Проверка ошибки аутентификации с неверным паролем."""
    channel = grpc.insecure_channel('localhost:50051')
    stub = user_pb2_grpc.UserServiceStub(channel)
    resp = stub.AuthenticateUser(user_pb2.AuthenticateUserRequest(email=f"test_{uuid.uuid4().hex[:8]}@a.com", password='wrong'))
    print('Аутентификация с неверным паролем:', resp)
    assert resp.status != "authenticated"

def test_transaction_service(user_id):
    channel = grpc.insecure_channel('localhost:50052')
    stub = transaction_pb2_grpc.TransactionServiceStub(channel)
    print('--- Тестирование сервиса транзакций ---')
    user_id = str(user_id)
    # Случайные параметры для дохода
    income_amount = round(random.uniform(500, 5000), 2)
    income_category = random.choice(['salary', 'bonus', 'gift'])
    income_date = (datetime(2024, 4, 1) + timedelta(days=random.randint(0, 10))).strftime('%Y-%m-%d')
    income_desc = random.choice(['Зарплата', 'Премия', 'Подарок'])
    # Добавляем доход
    resp1 = stub.AddTransaction(transaction_pb2.AddTransactionRequest(
        user_id=user_id, amount=income_amount, category=income_category, tx_type='income', date=income_date, description=income_desc))
    print(f'Добавление дохода: сумма={income_amount}, категория={income_category}, дата={income_date}, описание={income_desc} ->', resp1)
    assert resp1.status == "added"
    # Случайные параметры для расхода
    expense_amount = round(random.uniform(100, 1500), 2)
    expense_category = random.choice(['food', 'rent', 'entertainment'])
    expense_date = (datetime(2024, 4, 11) + timedelta(days=random.randint(0, 10))).strftime('%Y-%m-%d')
    expense_desc = random.choice(['Продукты', 'Аренда', 'Развлечения'])
    # Добавляем расход
    resp2 = stub.AddTransaction(transaction_pb2.AddTransactionRequest(
        user_id=user_id, amount=expense_amount, category=expense_category, tx_type='expense', date=expense_date, description=expense_desc))
    print(f'Добавление расхода: сумма={expense_amount}, категория={expense_category}, дата={expense_date}, описание={expense_desc} ->', resp2)
    assert resp2.status == "added"
    # Получаем все транзакции за месяц
    resp3 = stub.GetTransactions(transaction_pb2.GetTransactionsRequest(
        user_id=user_id, start_date='2024-04-01', end_date='2024-04-30'))
    print('Получение транзакций за месяц:', resp3)
    assert len(resp3.transactions) >= 2

def test_transaction_empty_for_new_user():
    """Проверка, что у нового пользователя нет транзакций."""
    channel = grpc.insecure_channel('localhost:50052')
    stub = transaction_pb2_grpc.TransactionServiceStub(channel)
    # Создаём нового пользователя
    channel_user = grpc.insecure_channel('localhost:50051')
    user_stub = user_pb2_grpc.UserServiceStub(channel_user)
    email = f"test_empty_{uuid.uuid4().hex[:8]}@a.com"
    username = f"empty_{uuid.uuid4().hex[:8]}"
    resp = user_stub.RegisterUser(user_pb2.RegisterUserRequest(email=email, username=username, password='123'))
    user_id = resp.user_id
    assert user_id
    resp_tx = stub.GetTransactions(transaction_pb2.GetTransactionsRequest(
        user_id=user_id, start_date='2024-04-01', end_date='2024-04-30'))
    print('Получение транзакций для нового пользователя:', resp_tx)
    assert len(resp_tx.transactions) == 0

def test_report_service(user_id):
    channel = grpc.insecure_channel('localhost:50053')
    stub = report_pb2_grpc.ReportServiceStub(channel)
    print('--- Тестирование сервиса отчетов ---')
    user_id = str(user_id)
    # Генерируем отчёт за месяц
    resp = stub.GenerateMonthlyReport(report_pb2.GenerateMonthlyReportRequest(user_id=user_id, year=2024, month=4))
    print('Генерация месячного отчета:', resp)
    assert resp.report.user_id == user_id
    # Экспортируем отчёт
    resp2 = stub.ExportReport(report_pb2.ExportReportRequest(user_id=user_id, year=2024, month=4, format='json'))
    print('Экспорт отчета (json):', resp2)
    assert resp2.status == "exported"
    # Проверяем экспорт в неподдерживаемом формате
    resp3 = stub.ExportReport(report_pb2.ExportReportRequest(user_id=user_id, year=2024, month=4, format='xml'))
    print('Экспорт отчета (xml):', resp3)
    assert resp3.status == "unsupported format"
