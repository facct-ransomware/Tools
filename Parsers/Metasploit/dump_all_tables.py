import psycopg2
import pandas as pd
import os

def export_tables_to_csv(dbname, user, password, host, port, output_dir):
    conn = psycopg2.connect(
        dbname=dbname,
        user=user,
        password=password,
        host=host,
        port=port
    )
    

    cursor = conn.cursor()

    cursor.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_type = 'BASE TABLE';
    """)
    
    tables = cursor.fetchall()

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for table_name in tables:
        table_name = table_name[0]
        df = pd.read_sql_query(f'SELECT * FROM {table_name}', conn)
        df.to_csv(os.path.join(output_dir, f'{table_name}.csv'), index=False)
        print(f"Exported {table_name} to {output_dir}/{table_name}.csv")

    cursor.close()
    conn.close()

if __name__ == '__main__':
    dbname = 'dbname'
    user = 'user'
    password = 'password'
    host = 'host'
    port = 'port'

    output_dir = 'db_out'

    export_tables_to_csv(dbname, user, password, host, port, output_dir)