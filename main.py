from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from database import SessionLocal, engine
import model
import os
from sqlalchemy.orm import Session
from schema import ChatbotCreate, UploadDocument, UserLogin, UserSignUp, CheckEmail, RefreshTokenRequest, UpdateChatbotInformation, InputMessages
from model import Document, User
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Union, Any, Optional
from jose import jwt, JWTError
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer
import cloudinary
import cloudinary.uploader
from service import indexing, embedding_msg

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

# ini biar bisa baca .env
load_dotenv()
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

@app.post("/api/verify-code/{user_id}")
def verify_code():
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
    
    db.query(model.Document).filter(model.Document.chatbot_id == chatbot_id).delete()
    
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
def get_document(chatbot_id: int, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    chatbot = db.query(model.ChatbotInformation).filter(model.ChatbotInformation.id == chatbot_id, model.ChatbotInformation.user_id == validate.id).first()
    if not chatbot:
        raise HTTPException(
            status_code=400,
            detail="Chatbot not found"
        )
    
    docs = db.query(model.Document).filter(model.Document.chatbot_id == chatbot.id).all()

    return docs

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
def delete_docs(doc_id: int ,db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    docs = db.query(model.Document).filter(model.Document.id == doc_id).first()
    if not docs:
        raise HTTPException(
            status_code=400,
            detail="Document Not Found"
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

@app.post("/api/message/{chat_id}")
def send_message(chat_id: int, message: InputMessages, db: Session = Depends(get_db), validate: model.User = Depends(validate_token)):
    chat = db.query(model.Chat).join(model.ChatbotInformation).filter(
        model.Chat.id == chat_id,
        model.ChatbotInformation.user_id == validate.id
    ).first()

    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found or access denied")
    
    # retrival
    # 1. ambil semua dokumen yang di select
    # 2. ambil pertanyaan yang sudah di embed
    # 3. hitung cosine similaritynya
    # 4. ambil 5 paling mirip (makin kecil makin mirip)

    
    msg = message.message
    if message.sender == "user":
        embeded_msg = embedding_msg(msg)
    else:
        embeded_msg = None


    new_message = model.Messages(
        chat_id=chat_id,
        message=msg,
        embeded_message = embeded_msg,
        sender=message.sender,
        created_at=datetime.utcnow()
    )

    db.add(new_message)
    db.commit()
    db.refresh(new_message)

    message = db.query(model.Messages).filter(model.Messages.id == new_message.id).first()
    if not message:
        raise HTTPException(
            status_code=400,
            detail="Message not found"
        )
    
    if message.sender == "bot":
        chat = db.query(model.Chat).filter(model.Chat.id == message.chat_id).first()

        docs_selected = db.query(model.Document).filter(model.Document.chatbot_id == chat.chatbot_id, model.Document.selected == True).all()

        selected_ids = [doc.id for doc in docs_selected]

        distance = model.VectorData.embeded_chunk.cosine_distance(embeded_msg).label("distance")

        context_chunk = (
            db.query(model.VectorData).filter(model.VectorData.document_id.in_(selected_ids)).order_by(distance).limit(10).all()
        )

        result = [
            {
                "docs_id": c.document_id,
                "chunk_text": c.chunk_text,
                "page_number": c.page_number
            }
            for c in context_chunk
        ]

        return result
    

    return {
        "id": new_message.id,
        "message": new_message.message,
        "sender": new_message.sender,
        "created_at": new_message.created_at
    }


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