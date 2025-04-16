import psycopg2
from psycopg2.extras import RealDictCursor
import os

DB_CONFIG = {
    'dbname': os.getenv('POSTGRES_DB', 'report_db'),
    'user': os.getenv('POSTGRES_USER', 'postgres'),
    'password': os.getenv('POSTGRES_PASSWORD', 'ufhybnehf23'),
    'host': os.getenv('POSTGRES_HOST', 'localhost'),
    'port': os.getenv('POSTGRES_PORT', '5432'),
}

def get_conn():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        amount DOUBLE PRECISION NOT NULL,
        category VARCHAR(255) NOT NULL,
        type VARCHAR(20) NOT NULL,
        date DATE NOT NULL,
        description TEXT
    );
    ''')
    conn.commit()
    cur.close()
    conn.close()
