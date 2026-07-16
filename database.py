from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

db_url = "postgresql://postgres:W1l$0n30@localhost:5432/DocuSwift"
engine = create_engine(db_url)

# auto commit itu buat menyimpan perubahan secara permanen di database
# auto flush itu mengirim perintah ke database tapi tidak disimpan secara permanen
# engine = ini variabel untuk koneksi ke database
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

