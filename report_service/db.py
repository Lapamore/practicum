import psycopg2
from psycopg2.extras import RealDictCursor
import os

DB_CONFIG = {
    'dbname': os.getenv('POSTGRES_DB', 'YOUR_DB'),
    'user': os.getenv('POSTGRES_USER', 'postgres'),
    'password': os.getenv('POSTGRES_PASSWORD', 'YOUR_PASSWORD'),
    'host': os.getenv('POSTGRES_HOST', 'localhost'),
    'port': os.getenv('POSTGRES_PORT', '5432'),
}

def get_conn():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
