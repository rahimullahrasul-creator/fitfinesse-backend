import os
import subprocess

# Get database URL from environment or paste it here
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://user:pass@host/dbname')

# Export to file
subprocess.run(['pg_dump', DATABASE_URL, '-f', 'fitfinesse_backup.sql'])

print("✅ Database exported to fitfinesse_backup.sql")

python export_db.py
