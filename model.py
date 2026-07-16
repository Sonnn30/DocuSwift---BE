from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer, Enum, ForeignKey, DateTime
from pgvector.sqlalchemy import Vector

# ini fungsinya agar sql alchemy bisa mengidentifikasi class ini adalah table
Base = declarative_base()


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String)
    hashed_password = Column(String)

class RefreshToken(Base):
    __tablename__ = "refresh_token"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey(User.id))
    refresh_token = Column(String)
    expire_at = Column(DateTime)
    created_at = Column(DateTime)

class AccessToken(Base):
    __tablename__ = "access_token"
    id = Column(Integer, primary_key=True, index=True)
    refresh_id = Column(Integer, ForeignKey(RefreshToken.id))
    access_token = Column(String)
    expire_at = Column(DateTime)
    created_at = Column(DateTime)

class VerifyCode(Base):
    __tablename__ = "verify_code"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey(User.id))
    code = Column(Integer)
    status = Column(String)
    expire_at = Column(DateTime)
    created_at = Column(DateTime)

class ChatbotInformation(Base):
    __tablename__ = "chatbot_information"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey(User.id))
    name = Column(String)
    prompt = Column(String)
    model = Column(Enum("qwen/qwen3.6-27b", "llama-3.1-8b-instant", name="category_enum"))

class Document(Base):
    __tablename__ = "document"
    id = Column(Integer, primary_key=True, index=True)
    chatbot_id = Column(Integer, ForeignKey(ChatbotInformation.id))
    filename = Column(String)
    file_type = Column(String)
    file_url = Column(String)
    upload_at = Column(DateTime)

class VectorData(Base):
    __tablename__ = "vector_data"
    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey(Document.id))
    chunk_text = Column(String)
    embeded_chunk = Column(Vector(384))
    page_number = Column(Integer)
    chunk_index = Column(Integer)