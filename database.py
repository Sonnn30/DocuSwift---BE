from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from dotenv import load_dotenv
import os
# Load file .env
load_dotenv()

# Ambil nilai dari .env
db_url = os.getenv("DATABASE_URL")
engine = create_engine(db_url)

# auto commit itu buat menyimpan perubahan secara permanen di database
# auto flush itu mengirim perintah ke database tapi tidak disimpan secara permanen
# engine = ini variabel untuk koneksi ke database
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

