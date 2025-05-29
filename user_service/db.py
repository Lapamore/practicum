import psycopg2
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
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        ''')
        conn.commit()
        print("--- Таблица users инициализирована (или уже существует) ---")
    except psycopg2.Error as e:
        print(f"Error initializing users table: {e}")
        conn.rollback()
    finally:
        if cur: cur.close()
        if conn: conn.close()
