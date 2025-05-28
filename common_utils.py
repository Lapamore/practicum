import os

# Функции, которые будут использоваться КЛИЕНТОМ (test_client.py) и СЕРВЕРАМИ
# Они принимают project_root_path как аргумент, который определяется в вызывающем скрипте.

def get_cert_path_from_root(project_root_path, subfolder, filename):
    """Возвращает путь к файлу сертификата от заданного корня проекта."""
    return os.path.join(project_root_path, "certs", subfolder, filename)

def get_ca_chain_path_from_root(project_root_path):
    """Возвращает путь к файлу цепочки CA от заданного корня проекта."""
    return os.path.join(project_root_path, "certs", "ca_chain.pem")

def get_jwt_key_path_from_root(project_root_path, service_name, key_type="private"):
    """Возвращает путь к JWT ключу (private или public) от заданного корня проекта."""
    filename = f"jwt_{key_type}.pem"
    return os.path.join(project_root_path, "certs", service_name, filename)

# Пример того, как можно было бы получить корень проекта, если бы этот файл
# всегда запускался или импортировался из определенного места.
# Но мы будем определять PROJECT_ROOT в каждом скрипте, который использует эти утилиты.
# def get_project_root_example():
#     # Если common_utils.py в корне PRACTICUM/
#     return os.path.dirname(os.path.abspath(__file__))