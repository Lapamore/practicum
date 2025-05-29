import psycopg2 # psycopg2 здесь
from psycopg2.extras import RealDictCursor
import os

DB_CONFIG = {
    'dbname': os.getenv('POSTGRES_DB', 'lab5'), # Измени на имя своей БД
    'user': os.getenv('POSTGRES_USER', 'postgres'),
    'password': os.getenv('POSTGRES_PASSWORD', 'SOSAL?'), # Измени на свой пароль
    'host': os.getenv('POSTGRES_HOST', 'localhost'),
    'port': os.getenv('POSTGRES_PORT', '5432'),
}

def get_conn():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY,
            user_id TEXT NOT NULL, -- Изменим на TEXT, т.к. из JWT приходит строка
            amount DOUBLE PRECISION NOT NULL,
            category VARCHAR(255) NOT NULL,
            tx_type VARCHAR(20) NOT NULL, -- 'income' or 'expense'
            date DATE NOT NULL,
            description TEXT
        );
        ''')
        conn.commit()
    except psycopg2.Error as e:
        print(f"Error initializing transactions table: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()
