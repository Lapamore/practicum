# Микросервисное приложение: Финансовый учёт

## Описание
Три микросервиса для учёта пользователей, транзакций и формирования отчётов. Основной протокол взаимодействия — gRPC, альтернативный — MessagePack.

## Сервисы
- user_service — регистрация, авторизация, профиль
- transaction_service — учёт доходов/расходов
- report_service — отчёты по активности

## Запуск
1. Установите зависимости:
   ```
   pip install -r requirements.txt
   ```
2. Сгенерируйте gRPC-код из proto-файлов:
   ```
   python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. user_service/user.proto
   python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. transaction_service/transaction.proto
   python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. report_service/report.proto
   ```

## Альтернативный протокол
Для передачи отчётов между сервисами используется MessagePack.

## Клиент
CLI или REST API для взаимодействия с сервисами.

---

## Инструкция по запуску с нуля

### 1. Клонируйте проект и перейдите в папку:
```bash
cd "папка_проекта"
```

### 2. Установите зависимости:
```bash
pip install -r requirements.txt
```

### 3. Сгенерируйте gRPC-код из proto-файлов (один раз после изменений .proto):
```bash
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. user_service/user.proto
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. transaction_service/transaction.proto
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. report_service/report.proto
```

### 4. Настройте базу данных (если требуется)
- Проверьте параметры подключения в файле `db.py` или аналогичном.
- Убедитесь, что PostgreSQL/MySQL сервер запущен и создана нужная БД.

### 5. Запустите все микросервисы (каждый в отдельном окне/терминале):

**User Service (порт 50051):**
```bash
python -m user_service.server
```

**Transaction Service (порт 50052):**
```bash
python -m transaction_service.server
```

**Report Service (порт 50053):**
```bash
python -m report_service.server
```

### 6. Проверьте, что все сервисы работают (нет ошибок в консоли)

### 7. Запустите автотесты:
```bash
pytest client/test_client.py -s
```

---

**Примечания:**
- Все сервисы должны быть запущены одновременно.
- Для Windows используйте обычный `python`, для Linux/macOS может быть `python3`.
- Если появятся ошибки соединения — убедитесь, что все сервисы слушают свои порты и нет конфликтов.
- Для повторного запуска сервисов — сначала закройте старые процессы (Ctrl+C или через диспетчер задач/`taskkill`).
- Все логи тестов выводятся на русском языке.

---

### Удачного запуска и тестирования!
