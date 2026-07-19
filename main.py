from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from dotenv import load_dotenv
# ini biar bisa baca .env
load_dotenv()

from fastapi.middleware.cors import CORSMiddleware
from database import SessionLocal, engine
import model
import os
from sqlalchemy.orm import Session
from schema import ChatbotCreate, UploadDocument, UserLogin, UserSignUp, CheckEmail, RefreshTokenRequest, UpdateChatbotInformation, InputMessages, Judul, VerifCode
from model import Document, User
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Union, Any, Optional
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer
import cloudinary
import cloudinary.uploader
from service import indexing, embedding_msg
from langchain_groq import ChatGroq
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import PromptTemplate
from fastapi.responses import StreamingResponse
from urllib.parse import urlparse
import random
import resend


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    # ini untuk allow port ini bisa akses endpoint
    allow_origins=["http://localhost:5173"],
    allow_methods = ["*"] ,
    allow_headers=["*"]
)


# ini untuk perintah agar sql alchemy membuat table di db
model.Base.metadata.create_all(bind=engine)

# merupakan dependency yang membuat, menyediakan, dan menutup session database untuk setiap request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 5
ALGORITHM = "HS256" 
JWT_SECRET_KEY = os.environ['JWT_SECRET_KEY']
JWT_REFRESH_SECRET_KEY = os.environ['JWT_REFRESH_SECRET_KEY']

# berfungsi untuk ambil data token yang dikirim FE
# tokenUrl fungsinya hanya untuk buat dokumentasi di swagger ui agar ada dokumentasi authorize
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

def validate_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credential_except = HTTPException(
        status_code=401,
        detail="Token invalid or expired",
        # ini cuman buat tambahan info aja
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credential_except
        
    except JWTError:
        raise credential_except
    

    user = db.query(model.User).filter(model.User.email == email).first()
    if user is None:
        raise credential_except
    
    return user


cloudinary.config(
    cloud_name= os.environ['CLOUDINARY_CLOUD_NAME'],
    api_key= os.environ['CLOUDINARY_API_KEY'],
    api_secret= os.environ['CLOUDINARY_API_SECRET']
)

@app.post("/api/refresh-token")
def refresh_token(payload: RefreshTokenRequest, db: Session = Depends(get_db)):
    credential_except = HTTPException(
        status_code=401,
        detail="Refresh token invalid or expired"
    )

    try:
        payload_data = jwt.decode(payload.refresh_token, JWT_REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload_data.get("sub")
        if email is None:
            raise credential_except
        
    except JWTError:
        raise credential_except
    
    user = db.query(model.User).filter(model.User.email == email).first()
    if user is None:
        raise credential_except

    refresh_record = db.query(model.RefreshToken).filter(model.RefreshToken.refresh_token == payload.refresh_token, model.RefreshToken.user_id == user.id).first()
    if refresh_record is None:
        raise credential_except
    
    new_access_token = create_access_token(user.email)


    return {
        "access_token": new_access_token
    }


@app.get("/api/get-all")
def get_all_chatbot(db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    db = db.query(model.ChatbotInformation).all()
    return db

@app.get("/api/get-chatbot/{chatbot_id}")
def get_chatbot_byid(chatbot_id: int, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    db = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.id == chatbot_id).first()
    if db:
        return db
    else:
        return {"message": "Chatbot Not Found"}
    
@app.get("/api/get-all-user-chatbot/{user_id}")
def get_all_user_chatbot(user_id: int, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    user_data = db.query(model.User).filter(model.User.id == user_id).first()
    if not user_data:
        raise HTTPException(
            status_code=400,
            detail="User not found."
        )
    
    chatbot_data = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.user_id == user_id).all()

    return chatbot_data

password_context = CryptContext(schemes=['bcrypt'], deprecated="auto")

def create_refresh_token(subject: Union[str, Any], expire_date: Optional[timedelta] = None):
    if expire_date is not None:
        expire = datetime.utcnow() + expire_date
    else:
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {"exp": expire, "sub": str(subject)}
    encode_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return encode_jwt


def create_access_token(subject: Union[str, Any], expire_date: Optional[timedelta] = None):
    if expire_date is not None:
        expire = datetime.utcnow() + expire_date
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {"exp": expire, "sub": str(subject)}
    encode_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    
    return encode_jwt


@app.post("/api/login")
def login(user: UserLogin, db: Session = Depends(get_db)):

    if not user.email:
        raise HTTPException(status_code=400, detail="Please enter email.")
    if not user.password:
        raise HTTPException(status_code=400, detail="Please enter password.")
    
    exist = db.query(model.User).filter(model.User.email == user.email).first()
    if not exist:
        raise HTTPException(status_code=400, detail="User not found, Please Sign Up")
    
    hashed_database = exist.hashed_password
    if not password_context.verify(user.password, hashed_database):
        raise HTTPException(status_code=400, detail="Invalid Password")

    # generate token
    refresh_token = create_refresh_token(user.email)
    expire_at = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_info = model.RefreshToken(
        user_id=exist.id,
        refresh_token=refresh_token,
        expire_at=expire_at,
        created_at=datetime.utcnow()
    )
    db.add(refresh_info)
    db.commit()
    db.refresh(refresh_info)

    access_token = create_access_token(user.email)
    expire_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_info = model.AccessToken(
        refresh_id=refresh_info.id,
        access_token=access_token,
        expire_at=expire_at,
        created_at=datetime.utcnow()
    )
    db.add(access_info)
    db.commit()

    return {
        "message": "berhasil login",
        "access_token": access_token,
        "refresh_token": refresh_token
    }


@app.post("/api/sign-up")
def sign_up(user: UserSignUp, db: Session = Depends(get_db)):
    if not user.name:
        raise HTTPException(status_code=400, detail="Please enter name.")
    
    if not user.email:
        raise HTTPException(status_code=400, detail="Please enter email.")
    
    if not user.password:
        raise HTTPException(status_code=400, detail="Please enter password.")
    
    if not user.confirmed_password:
        raise HTTPException(status_code=400, detail="Please enter confirmed password.")
    
    if user.password != user.confirmed_password:
        raise HTTPException(
            status_code=400,
            detail="password and confirmed password not same, please check again"
        )

    existing = db.query(model.User).filter(model.User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")
    
    hashed_password = password_context.hash(user.password)
    new_user = model.User(name=user.name, email=user.email, hashed_password=hashed_password)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    refresh_token = create_refresh_token(user.email)
    expire_at = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_info = model.RefreshToken(user_id=new_user.id, refresh_token=refresh_token, expire_at=expire_at,created_at=datetime.utcnow())

    db.add(refresh_info)
    db.commit()
    db.refresh(refresh_info)

    access_token =  create_access_token(user.email)
    expire_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_info = model.AccessToken(refresh_id=refresh_info.id, access_token=access_token, expire_at=expire_at, created_at=datetime.utcnow())

    db.add(access_info)
    db.commit()
    db.refresh(access_info)


    return {"message": "berhasil sign up", "access_token": access_token, "refresh_token": refresh_token}


@app.post("/api/logout")
def logout(payload: RefreshTokenRequest,db: Session = Depends(get_db)):
    refresh_token = db.query(model.RefreshToken).filter(model.RefreshToken.refresh_token == payload.refresh_token).first()

    if refresh_token:
        db.query(model.AccessToken).filter(model.AccessToken.refresh_id == refresh_token.id).delete()
        db.delete(refresh_token)
        db.commit()

    return {"message": "logout success"}


@app.post("/api/is-email-valid")
def check_email(email: CheckEmail, db: Session = Depends(get_db)):
    email = db.query(model.User).filter(model.User.email == email.email).first()

    if not email:
        raise HTTPException(
            status_code=400,
            detail="User email not found"
        )
    
    return {"message": "email ditemukan!"}

resend_api_key = os.environ["SEND_EMAIL_API_KEY"]

@app.post("/api/send-verify-code")
def verify_code(payload: VerifCode, db: Session = Depends(get_db)):
    TOTAL_DIGITS = 6
    CODE_DURATION = 3 # menit
    arr = []

    for i in range(TOTAL_DIGITS):
        x = random.randint(1, 9)
        arr.append(x)

    random_num = int("".join(map(str, arr)))

    email = db.query(model.User).filter(model.User.email == payload.email).first()

    created_at = datetime.utcnow()

    expire = created_at + timedelta(minutes=CODE_DURATION)

    new_verif_code = model.VerifyCode(
        user_id = email.id,
        code = random_num,
        status = "Active",
        expire_at = expire,
        created_at = created_at
    )

    db.add(new_verif_code)
    db.commit()


    return


@app.post("/api/createBot")
def create_bot(chatbot: ChatbotCreate, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    if chatbot.name.strip() == "" or not chatbot.name:
        raise HTTPException(
            status_code=400,
            detail="Name is required."
        )
    
    if chatbot.prompt.strip() == "" or not chatbot.prompt:
        raise HTTPException(
            status_code=400,
            detail="Prompt is required."
        )
    
    existing = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.name == chatbot.name, model.ChatbotInformation.user_id == validate.id).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail="Chatbot Name already used."
        )
    
    new_chatbot = model.ChatbotInformation(
        user_id = validate.id,
        name = chatbot.name,
        prompt = chatbot.prompt,
        model = chatbot.model
    )
    db.add(new_chatbot)
    db.commit()
    db.refresh(new_chatbot)
    
    return {"message": "Data successfully entered.", "id": new_chatbot.id}


@app.get("/api/get-user-by-id")
def get_user(validate: model.User = Depends(validate_token)):

    return {
        "name": validate.name,
        "email": validate.email
    }

@app.put("/api/chatbot-update/{chatbot_id}")
def update_chatbot(chatbot_id: int,  chatbot_update: UpdateChatbotInformation, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    chatbot = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.id == chatbot_id, model.ChatbotInformation.user_id == validate.id).first()
    if not chatbot:
        raise HTTPException(
            status_code=400,
            detail="Chatbot not found"
        )
    
    chatbot.name = chatbot_update.name
    chatbot.prompt = chatbot_update.prompt
    chatbot.model = chatbot_update.model

    db.commit()
    db.refresh(chatbot)

    return chatbot
    
@app.delete("/api/chatbot-delete/{chatbot_id}")
def delete_chatbot(chatbot_id: int,db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    chatbot = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.id == chatbot_id, model.ChatbotInformation.user_id == validate.id).first()
    if not chatbot:
        raise HTTPException(
            status_code=400,
            detail="Chatbot not found"
        )
    
    chat_id = [c.id for c in db.query(model.Chat.id).filter(model.Chat.chatbot_id == chatbot.id).all()]
    document_id = [d.id for d in db.query(model.Document.id).filter(model.Document.chatbot_id == chatbot.id).all()]

    if document_id:
        db.query(model.VectorData).filter(model.VectorData.document_id.in_(document_id)).delete(synchronize_session=False)

    if chat_id:
        db.query(model.Messages).filter(model.Messages.chat_id.in_(chat_id)).delete(synchronize_session=False)

    db.query(model.Document).filter(model.Document.chatbot_id == chatbot_id).delete(synchronize_session=False)

    db.query(model.Chat).filter(model.Chat.chatbot_id == chatbot_id).delete(synchronize_session=False)

    db.delete(chatbot)
    db.commit()

    return {"message": "Delete Successfully"}



@app.get("/api/is-upload-document/{id}")
def is_upload(id: int, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    document = db.query(model.Document).filter(model.Document.chatbot_id == id)
    return {
        "chatbot_id": id,
        "is_upload": document is not None
    }

ALLOWED_EXTENSIONS = {".pdf", ".docx", ".pptx", ".xlsx"}

@app.post("/api/chatbot/{chatbot_id}/upload-document")
async def upload_document(chatbot_id: int, file: UploadFile = File(...), db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="File not uploaded"
        )
    
    file_ext = "." + file.filename.rsplit(".", 1)[1] if "." in file.filename else ""
    if file_ext.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400, 
            detail=f"File type not supported. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    
    chatbot = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.id == chatbot_id, model.ChatbotInformation.user_id == validate.id).first()

    if not chatbot:
        raise HTTPException(
            status_code=400,
            detail="Chatbot not found"
        )
    
    try:
        result = cloudinary.uploader.upload(
            file.file,
            resource_type="raw",
            folder=f"chatbot_{chatbot_id}",
            public_id=file.filename,
            flags="attachment:false"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Upload failed: {str(e)}"
        )
    

    new_doc = model.Document(
        chatbot_id=chatbot_id,
        filename= file.filename.rsplit(".", 1)[0],
        file_type=file.filename.rsplit(".", 1)[1],
        file_url= result["secure_url"],
        upload_at=datetime.utcnow()
    )

    db.add(new_doc)
    db.commit()
    db.refresh(new_doc)

    indexed = await indexing(result['secure_url'], file.filename.rsplit(".", 1)[1])

    for chunk_index, item in enumerate(indexed):
        new_vector_data = model.VectorData(
            document_id = new_doc.id,
            chunk_text = item['chunk'],
            embeded_chunk = item['vector'],
            page_number = item['metadata'].get('page') or item['metadata'].get('sheet') or item['metadata'].get('slide'),
            chunk_index = chunk_index

        )
        db.add(new_vector_data)

    db.commit()



    return {
        "message": "Success Upload file",
        "url": result['secure_url'],
        "filename": file.filename.rsplit(".", 1)[0],
        "filetype": file.filename.rsplit(".", 1)[1]
    }




@app.get("/api/get-document/{chatbot_id}")
def get_document(chatbot_id: int, page: int = 1, limit: int = 10, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    chatbot = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.id == chatbot_id, model.ChatbotInformation.user_id == validate.id).first()
    if not chatbot:
        raise HTTPException(
            status_code=400,
            detail="Chatbot not found"
        )
    
    offset = (page - 1) * limit

    query = db.query(model.Document).filter(model.Document.chatbot_id == chatbot.id)

    total = query.count()
    docs = query.offset(offset).limit(limit).all()

    return {
        "data": docs,
        "total_pages": -(-total // limit),
        "current_page": page
    }

@app.get("/api/get-document-by-id/{doc_id}")
def get_doc_by_id(doc_id: int,db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    docs = db.query(model.Document).filter(model.Document.id == doc_id, model.ChatbotInformation.user_id == validate.id).first()
    if not docs:
        raise HTTPException(
            status_code=400,
            detail="Document not found"
        )
    
    return {"docs_url": docs.file_url}


@app.delete("/api/document-delete-by-id/{doc_id}")
def delete_docs(doc_id: int, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    docs = db.query(model.Document).filter(model.Document.id == doc_id).first()
    if not docs:
        raise HTTPException(
            status_code=400,
            detail="Document Not Found"
        )

    if docs.file_url:
        try:
            path = urlparse(docs.file_url).path
            public_id_with_ext = path.split("/upload/")[-1]

            parts = public_id_with_ext.split("/")
            if parts[0].startswith("v") and parts[0][1:].isdigit():
                parts = parts[1:]

            public_id = "/".join(parts)  # dengan ekstensi

            result = cloudinary.uploader.destroy(public_id, resource_type="raw", invalidate=True)

            if result.get("result") != "ok":
                raise HTTPException(
                    status_code=500,
                    detail=f"Gagal menghapus file dari Cloudinary"
                )

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Gagal menghapus file dari Cloudinary: {str(e)}"
            )

    db.delete(docs)
    db.commit()

    return {"message": "Document Deleted"}

@app.get("/api/get-chatbot-by-user_id")
def get_chatbot(db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    chatbot = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.user_id == validate.id).all()

    return chatbot

@app.get("/api/get-chatbot-by-id/{chatbot_id}")
def get_chatbot_by_id(chatbot_id: int ,db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    chatbot = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.id == chatbot_id, model.ChatbotInformation.user_id == validate.id).first()
    return chatbot


@app.post("/api/chat/{chatbot_id}")
def new_chat(chatbot_id: int, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    chatbot = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.id == chatbot_id).first()

    if not chatbot:
        raise HTTPException(
            status_code=400,
            detail="chatbot not found"
        )

    if chatbot.user_id != validate.id:
        raise HTTPException(
            status_code=403,
            detail="Invalid chatbot"
        )
    
    existing_chat = db.query(model.Chat).filter(model.Chat.chatbot_id == chatbot_id).first()
    if existing_chat:
        raise HTTPException(status_code=400, detail="Chat already exists for this chatbot")
    
    new_chat = model.Chat(
        chatbot_id = chatbot_id,
        created_at = datetime.utcnow()
    )

    db.add(new_chat)
    db.commit()
    db.refresh(new_chat)

    return {
        "message": "new chat created",
        "chat_id": new_chat.id,
        "created_at": new_chat.created_at
        
    }

@app.post("/api/message/{chatbot_id}")
def send_message(chatbot_id: int, message: InputMessages, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    chatbot = db.query(model.ChatbotInformation).filter(
        model.ChatbotInformation.id == chatbot_id,
        model.ChatbotInformation.user_id == validate.id
    ).first()

    if not chatbot:
        raise HTTPException(status_code=404, detail="Chatbot not found or access denied")

    chat = db.query(model.Chat).filter(model.Chat.chatbot_id == chatbot_id).first()

    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found for this chatbot")

    msg = message.message
    if message.sender == "user":
        embeded_msg = embedding_msg(msg)
    else:
        embeded_msg = None

    new_message = model.Messages(
        chat_id=chat.id,
        message=msg,
        embeded_message=embeded_msg,
        sender=message.sender,
        created_at=datetime.utcnow()
    )

    db.add(new_message)
    db.commit()
    db.refresh(new_message)
    
    # retrival
    # 1. ambil semua dokumen yang di select
    # 2. ambil pertanyaan yang sudah di embed
    # 3. hitung cosine similaritynya
    # 4. ambil 5 paling mirip (makin kecil makin mirip)

    message = db.query(model.Messages).filter(model.Messages.id == new_message.id).first()
    if not message:
        raise HTTPException(
            status_code=400,
            detail="Message not found"
        )
    
    if message.sender == "bot":
        chat = db.query(model.Chat).filter(model.Chat.id == message.chat_id).first()
        docs = db.query(model.Document).filter(model.Document.chatbot_id == chat.chatbot_id).first()

        if not docs:
            bot_message = model.Messages(
                chat_id = chat.id,
                message = "Please upload document",
                embeded_message = None,
                sender = "bot",
                created_at = datetime.utcnow()
            )

            db.add(bot_message)
            db.commit()
            db.refresh(bot_message)
            return StreamingResponse(iter([bot_message.message]), media_type="text/plain")


        docs_selected = db.query(model.Document).filter(model.Document.chatbot_id == chat.chatbot_id, model.Document.selected == True).all()

        selected_ids = [doc.id for doc in docs_selected]

        if not docs_selected:
            bot_message = model.Messages(
                chat_id = chat.id,
                message = "Please Select document",
                embeded_message = None,
                sender = "bot",
                created_at = datetime.utcnow()
            )

            db.add(bot_message)
            db.commit()
            db.refresh(bot_message)

            return StreamingResponse(iter([bot_message.message]), media_type="text/plain")

        # ambil pesan user terakhir di chat ini, karena request saat ini sender-nya "bot" (embeded_msg di atas None)
        user_msg_obj = db.query(model.Messages).filter(
            model.Messages.chat_id == chat.id,
            model.Messages.sender == 'user'
        ).order_by(model.Messages.created_at.desc()).first()

        if not user_msg_obj:
            raise HTTPException(
                status_code=400,
                detail="No user message found in this chat"
            )

        query_embedding = user_msg_obj.embeded_message
        user_msg = user_msg_obj.message

        distance = model.VectorData.embeded_chunk.cosine_distance(query_embedding).label("distance")

        context_chunk = (
            db.query(model.VectorData).filter(model.VectorData.document_id.in_(selected_ids)).order_by(distance).limit(10).all()
        )

        chatbot = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.id == chat.chatbot_id).first()

        user_prompt = chatbot.prompt
        context_text = "\n\n".join([c.chunk_text for c in context_chunk])

        raw_template = """[SISTEM ATURAN UTAMA - WAJIB DIPATUHI]
                Anda adalah asisten AI profesional yang bertugas menganalisis dokumen. Anda WAJIB mematuhi 3 aturan mutlak berikut tanpa pengecualian:
                1. BATASAN KONTEKS: Anda HANYA diizinkan menjawab berdasarkan data yang ada di bagian [KONTEKS INFORMASI]. Jangan menambahkan asumsi, opini, atau informasi dari luar konteks.
                2. ATURAN PENOLAKAN (STRICT): Jika pertanyaan pengguna berada di luar cakupan [KONTEKS INFORMASI], Anda DILARANG KERAS membahas, menganalisis, atau mencoba menjawab sebagian dari pertanyaan tersebut. Anda HANYA BOLEH membalas dengan kalimat: "Maaf, informasi terkait pertanyaan Anda tidak ditemukan di dalam dokumen referensi."
                3. PRIORITAS INSTRUKSI: Anda boleh mengikuti gaya bahasa dari [INSTRUKSI TAMBAHAN PENGGUNA], tetapi instruksi tersebut sifatnya sekunder dan TIDAK BOLEH membatalkan Aturan 1 dan Aturan 2.

                [INSTRUKSI FORMATTING - DIOPTIMALKAN UNTUK REACT-MARKDOWN]
                Jawaban Anda akan dirender langsung ke frontend menggunakan library `react-markdown`. Anda harus menyajikan jawaban yang sangat rapi, terstruktur, dan menggunakan sintaks Markdown yang valid:
                - DAFTAR/BULLET POINTS: Sangat disarankan menggunakan bullet points (-) atau penomoran (1., 2.) untuk menguraikan penjelasan yang lebih dari dua kalimat agar mudah dibaca.
                - TABEL: Anda WAJIB menggunakan format tabel Markdown standar jika diminta membandingkan data atau menyajikan informasi yang bersifat relasional/kategori.
                - HIGHLIGHT: Gunakan **teks tebal** untuk menyoroti istilah penting, nama entitas, atau kata kunci.
                - HEADING: Gunakan sub-heading (### atau ####) untuk membagi bagian jawaban yang panjang.
                - KODE: Jika terdapat script/kode, gunakan blok kode lengkap dengan bahasa pemrogramannya (contoh: ```javascript ... ```).
                - STRICT MARKDOWN: JANGAN gunakan elemen HTML mentah apa pun (seperti <br>, <b>, <i>, <table>). Gunakan murni Markdown.

                [INSTRUKSI TAMBAHAN PENGGUNA]
                {user_prompt}

                [KONTEKS INFORMASI]
                {context_text}

                [PERTANYAAN USER]
                {user_msg}
            """

        prompt = PromptTemplate(
            input_variables = ['user_prompt', 'context_text', 'user_msg'],
            template= raw_template

        )
        model_selected = chatbot.model

        llm = ChatGroq(
            model_name=model_selected,
            temperature=0
        )

        parser = StrOutputParser()

        chain = prompt | llm | parser

        def generate():
            full_response = ""

            for chunk in chain.stream({
                "user_prompt": user_prompt,
                "context_text": context_text,
                "user_msg": user_msg
            }):
                full_response += chunk
                yield chunk
            
            bot_message = model.Messages(
                chat_id = chat.id,
                message = full_response,
                embeded_message = None,
                sender = "bot",
                created_at = datetime.utcnow()
            )

            db.add(bot_message)
            db.commit()

        
        return StreamingResponse(generate(), media_type="text/plain")

        # result = [
        #     {
        #         "docs_id": c.document_id,
        #         "chunk_text": c.chunk_text,
        #         "page_number": c.page_number
        #     }
        #     for c in context_chunk
        # ]
    

    return {
        "id": new_message.id,
        "message": new_message.message,
        "sender": new_message.sender,
        "created_at": new_message.created_at
    }


@app.get("/api/get-message/{chatbot_id}")
def get_chat(chatbot_id: int , db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    chatbot = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.id == chatbot_id).first()

    if not chatbot:
        raise HTTPException(
            status_code=404,
            detail="Chatbot not found"
        )


    is_user = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.user_id == validate.id).first()

    if not is_user:
        raise HTTPException(
            status_code=404,
            detail="access denied"
        )
    
    chat = db.query(model.Chat).filter(model.Chat.chatbot_id == chatbot_id).first()
    if not chat:
        raise HTTPException(
            status_code=404,
            detail="Chat not found or not access denied"
        )
    
    message = db.query(model.Messages).filter(model.Messages.chat_id == chat.id).order_by(model.Messages.created_at.asc()).all()

    return [
        {
            "id": m.id,
            "message": m.message,
            "sender": m.sender,
            "created_at": m.created_at

        }
        for m in message
    ]



@app.post("/api/is-document-selected/{doc_id}")
def select_document(doc_id: int, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):

    document = db.query(model.Document).join(model.ChatbotInformation, model.Document.chatbot_id == model.ChatbotInformation.id).filter(model.Document.id == doc_id, model.ChatbotInformation.user_id == validate.id).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found or access denied"
        )

    document.selected =  not document.selected
    db.commit()

    return {"message": "document selected", "selected": document.selected}

@app.post("/api/get-document-by-name/{chatbot_id}")
def get_docs(chatbot_id: int, payload: Judul, page: int = 1, limit: int = 10, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):

    cari = f"%{payload.judul}%"
    offset = (page - 1) * limit

    query = db.query(model.Document).filter(
        model.Document.chatbot_id == chatbot_id,
        model.Document.filename.ilike(cari)
    )

    total = query.count()
    docs = query.offset(offset).limit(limit).all()

    if not docs:
        return {
            "message": "docs not found",
            "data": [],
            "total_pages": 0,
            "current_page": page
        }

    return {
        "message": "docs found",
        "data": docs,
        "total_pages": -(-total // limit),  # ceiling division
        "current_page": page
    }

# API apakah sudah upload document atau belum done
# API untuk search dokumen berdasarkan judul done
# API untuk kirim verify code 6 digit
# update delete beneran di cloudinarynya done