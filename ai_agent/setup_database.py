import pandas as pd
from sqlalchemy import create_engine, text
import os
from dotenv import load_dotenv

print("--- Starting Robust Database Setup Process for MySQL ---")

# --- 1. Load Configuration from .env file ---
load_dotenv()

DB_TYPE = os.getenv("DB_TYPE")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

# Configuration for the script
ALERTS_TABLE = "alerts"
FEEDBACK_TABLE = "feedback"
CSV_FILE = r'C:\Users\samee\OneDrive\Desktop\ai_agent\NSL_KDD_Test.csv'

def create_db_engine():
    """Creates a SQLAlchemy engine based on the .env configuration."""
    try:
        if DB_TYPE == "postgresql":
            uri = f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        elif DB_TYPE == "mysql":
            # This is the correct connection string format for MySQL
            uri = f"mysql+mysqlconnector://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        else:
            raise ValueError(f"Unsupported DB_TYPE: {DB_TYPE}")
        
        engine = create_engine(uri)
        # Test the connection
        with engine.connect() as connection:
            print(f"Successfully connected to {DB_TYPE} database '{DB_NAME}' on {DB_HOST}.")
        return engine
    except Exception as e:
        print(f"FATAL ERROR: Could not connect to the database. Please check your .env file settings.")
        print(f"Error details: {e}")
        return None

def drop_tables_if_exist(engine):
    """Drops the tables to ensure a clean slate."""
    print("\nDropping old tables (if they exist)...")
    with engine.connect() as connection:
        with connection.begin():
            # Temporarily disable foreign key checks for safe dropping
            connection.execute(text("SET FOREIGN_KEY_CHECKS = 0;"))
            connection.execute(text(f"DROP TABLE IF EXISTS {FEEDBACK_TABLE};"))
            connection.execute(text(f"DROP TABLE IF EXISTS {ALERTS_TABLE};"))
            connection.execute(text("SET FOREIGN_KEY_CHECKS = 1;"))
    print("Old tables dropped successfully.")

def create_tables(engine):
    """Create the necessary tables with an explicit schema for MySQL."""
    print("Defining and creating new database schema for MySQL...")

    # --- THIS IS THE KEY CHANGE FOR MYSQL ---
    # MySQL uses 'INT PRIMARY KEY AUTO_INCREMENT' instead of 'SERIAL PRIMARY KEY'
    pk_type = "INT PRIMARY KEY AUTO_INCREMENT"

    sql_create_alerts_table = f"""
    CREATE TABLE {ALERTS_TABLE} (
        id {pk_type}, duration REAL, protocol_type TEXT, service TEXT, flag TEXT, src_bytes REAL, dst_bytes REAL,
        land INTEGER, wrong_fragment REAL, urgent REAL, hot REAL, num_failed_logins REAL, logged_in REAL,
        num_compromised REAL, root_shell REAL, su_attempted REAL, num_root REAL, num_file_creations REAL,
        num_shells REAL, num_access_files REAL, num_outbound_cmds REAL, is_host_login REAL, is_guest_login REAL,
        count REAL, srv_count REAL, serror_rate REAL, srv_serror_rate REAL, rerror_rate REAL, srv_rerror_rate REAL,
        same_srv_rate REAL, diff_srv_rate REAL, srv_diff_host_rate REAL, dst_host_count REAL, dst_host_srv_count REAL,
        dst_host_same_srv_rate REAL, dst_host_diff_srv_rate REAL, dst_host_same_src_port_rate REAL,
        dst_host_srv_diff_host_rate REAL, dst_host_serror_rate REAL, dst_host_srv_serror_rate REAL,
        dst_host_rerror_rate REAL, dst_host_srv_rerror_rate REAL, class TEXT, difficulty REAL
    );"""

    sql_create_feedback_table = f"""
    CREATE TABLE {FEEDBACK_TABLE} (
        id {pk_type}, timestamp TEXT NOT NULL, event_id INTEGER,
        feedback TEXT, service TEXT, protocol TEXT
    );"""

    with engine.connect() as connection:
        with connection.begin():
            connection.execute(text(sql_create_alerts_table))
            connection.execute(text(sql_create_feedback_table))
    print("Schema created successfully.")

def ingest_csv_data(engine, csv_file, table_name):
    """Load data from CSV and insert it into the specified table."""
    print(f"\nIngesting data from {csv_file}...")
    try:
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
            'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'class', 'difficulty'
        ]
        df = pd.read_csv(csv_file, header=None, names=columns)
        
        df.to_sql(table_name, engine, if_exists='append', index=False, chunksize=1000)
        print(f"Successfully ingested {len(df)} records into '{table_name}'.")

    except Exception as e:
        print(f"An error occurred during CSV ingestion: {e}")
        exit()

def main():
    """Main function to orchestrate the database setup."""
    engine = create_db_engine()
    if engine:
        drop_tables_if_exist(engine)
        create_tables(engine)
        ingest_csv_data(engine, CSV_FILE, ALERTS_TABLE)
        print("\n✅ Database setup is complete! Your app can now connect to your MySQL database.")

if __name__ == '__main__':
    main()