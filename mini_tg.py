from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, Field, EmailStr
from database import SessionLocal
from models import User as DBUser, Chat as DBChat, ChatMember, Message as DBMessage
from security import hash_password, verify_password
from auth import create_access_token, get_current_user_id
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

api = FastAPI()

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=30, pattern=r"^[a-zA-Z0-9_]+$")
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: str
    password: str

class ChatCreate(BaseModel):
    user_id: str

class MessageCreate(BaseModel):
    text: str = Field(min_length=1, max_length=2000)

class MessageUpdate(BaseModel):
    text: str = Field(min_length=1, max_length=2000)

@api.post("/api/v1/auth/register", status_code=201)
def register(data: RegisterRequest):
    with SessionLocal() as session:
        existing_user = session.scalar(
            select(DBUser).where(
                (DBUser.email == data.email)
                | (DBUser.username == data.username)
            )
        )

        if existing_user:
            if existing_user.email == data.email:
                raise HTTPException(status_code=409,detail="Email already registered")
            raise HTTPException(status_code=409,detail="Username already taken")

        new_user = DBUser(username=data.username,email=data.email,password_hash=hash_password(data.password))

        session.add(new_user)

        try:
            session.commit()
            session.refresh(new_user)
        except IntegrityError:
            session.rollback()
            raise HTTPException(status_code=409,detail="Email or username already registered")

        return {
            "id": str(new_user.id),
            "username": new_user.username,
            "email": new_user.email,
        }

@api.post("/api/v1/auth/login")
def login(data: LoginRequest):
    with SessionLocal() as session:
        user = session.scalar(
            select(DBUser).where(DBUser.email == data.email)
        )

        if user is None or not verify_password(data.password, user.password_hash):
            raise HTTPException(status_code=401,detail="Invalid email or password")


        access_token = create_access_token(user.id)

        return {
            "message": "Login successful",
            "user_id": str(user.id),
            "access_token": access_token,
            "token_type": "bearer",
        }


@api.post("/api/v1/chats")
def create_chat(data: ChatCreate, current_user_id: int = Depends(get_current_user_id)):
    try:
        other_user_id = int(data.user_id)
    except ValueError:
        raise HTTPException(status_code=400,detail="User ID must be an integer")

    if current_user_id == other_user_id:
        raise HTTPException(status_code=400,detail="Cannot create chat with yourself")

    with SessionLocal() as session:
        owner = session.get(DBUser, current_user_id)
        other_user = session.get(DBUser, other_user_id)

        if owner is None:
            raise HTTPException(status_code=404, detail="Owner not found")

        if other_user is None:
            raise HTTPException(status_code=404, detail="User not found")

        existing_chat = session.scalar(select(DBChat).where(DBChat.type == "private", DBChat.id.in_(select(ChatMember.chat_id).where(ChatMember.user_id == current_user_id)), DBChat.id.in_(select(ChatMember.chat_id).where(ChatMember.user_id == other_user_id))).limit(1))

        if existing_chat is not None:
            member_ids = session.scalars(select(ChatMember.user_id).where(ChatMember.chat_id == existing_chat.id)).all()

            return {
                "id": str(existing_chat.id),
                "type": existing_chat.type,
                "owner_id": str(existing_chat.owner_id),
                "member_ids": [str(member_id) for member_id in member_ids],
                "message": "Chat already exists",
            }

        new_chat = DBChat(type="private",owner_id=current_user_id)
        session.add(new_chat)
        session.flush()

        session.add_all([
            ChatMember(chat_id=new_chat.id, user_id=current_user_id),
            ChatMember(chat_id=new_chat.id, user_id=other_user_id),
        ])

        session.commit()
        session.refresh(new_chat)

        return {
            "id": str(new_chat.id),
            "type": new_chat.type,
            "owner_id": str(new_chat.owner_id),
            "member_ids": [str(current_user_id), str(other_user_id)],
            "message": "Chat created",
        }

@api.post("/api/v1/chats/{chat_id}/messages")
def send_message(chat_id: str, data: MessageCreate, current_user_id: int = Depends(get_current_user_id)):
    try:
        current_chat_id = int(chat_id)
    except ValueError:
        raise HTTPException(status_code=400,detail="Chat ID must be an integer")
    
    if not data.text.strip():
        raise HTTPException(status_code=400,detail="Message cannot be empty")

    with SessionLocal() as session:
        chat = session.get(DBChat, current_chat_id)

        if chat is None:
            raise HTTPException(status_code=404,detail="Chat not found")

        membership = session.scalar(select(ChatMember).where(ChatMember.chat_id == current_chat_id,ChatMember.user_id == current_user_id))

        if membership is None:
            raise HTTPException(status_code=403,detail="Sender is not a member of this chat")

        new_message = DBMessage(chat_id=current_chat_id,sender_id=current_user_id,text=data.text.strip())

        session.add(new_message)
        session.commit()
        session.refresh(new_message)

        return {
            "id": str(new_message.id),
            "chat_id": str(new_message.chat_id),
            "sender_id": str(new_message.sender_id),
            "text": new_message.text,
        }

@api.get("/api/v1/auth/me")
def get_me(user_id: int = Depends(get_current_user_id)):
    with SessionLocal() as session:
        user = session.get(DBUser, user_id)

        if user is None:
            raise HTTPException(status_code=401,detail="User not found")

        return {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
        }

@api.get("/api/v1/users/{user_id}")
def get_user_by_id(user_id: int, current_user_id: int = Depends(get_current_user_id)):
    with SessionLocal() as session:
        user = session.get(DBUser, user_id)

        if user is None:
            raise HTTPException(status_code=404,detail="User not found")
        
        if user_id != current_user_id:
            raise HTTPException(status_code=403,detail="You can only view your own profile")
        return {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
        }

@api.get("/api/v1/chats")
def get_chat(current_user_id: int = Depends(get_current_user_id)):
    with SessionLocal() as session:
        current_user = session.get(DBUser, current_user_id)

        if current_user is None:
            raise HTTPException(status_code=404, detail="User not found")

        statement = (select(DBChat).join(ChatMember, ChatMember.chat_id == DBChat.id).where(ChatMember.user_id == current_user_id))

        user_chats = session.scalars(statement).all()
        result = []

        for chat in user_chats:
            member_ids = session.scalars(select(ChatMember.user_id).where(ChatMember.chat_id == chat.id)).all()

            result.append({
                "id": str(chat.id),
                "type": chat.type,
                "owner_id": str(chat.owner_id),
                "member_ids": [str(member_id) for member_id in member_ids],
            })

        return result

@api.get("/api/v1/chats/{chat_id}")
def get_chat(chat_id: str, current_user_id: int = Depends(get_current_user_id)):
    try:
        current_chat_id = int(chat_id)
    except ValueError:
        raise HTTPException(status_code=400,detail="Chat ID and user ID must be integers")

    with SessionLocal() as session:
        chat = session.get(DBChat, current_chat_id)

        if chat is None:
            raise HTTPException(status_code=404, detail="Chat not found")

        is_member = session.scalar(
            select(ChatMember).where(
                ChatMember.chat_id == current_chat_id,
                ChatMember.user_id == current_user_id,
            )
        )

        if is_member is None:
            raise HTTPException(status_code=403,detail="User is not a member of this chat")

        member_ids = session.scalars(select(ChatMember.user_id).where(ChatMember.chat_id == current_chat_id)).all()

        return {
            "id": str(chat.id),
            "type": chat.type,
            "owner_id": str(chat.owner_id),
            "member_ids": [str(member_id) for member_id in member_ids],
        }

@api.get("/api/v1/chats/{chat_id}/messages")
def get_messages(chat_id: str, limit: int = 50, current_user_id: int = Depends(get_current_user_id)):
    try:
        current_chat_id = int(chat_id)
    except ValueError:
        raise HTTPException(status_code=400,detail="Chat ID and user ID must be integers")

    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400,detail="Limit must be between 1 and 100")

    with SessionLocal() as session:
        chat = session.get(DBChat, current_chat_id)

        if chat is None:
            raise HTTPException(status_code=404,detail="Chat not found")

        membership = session.scalar(select(ChatMember).where(ChatMember.chat_id == current_chat_id,ChatMember.user_id == current_user_id))

        if membership is None:
            raise HTTPException(status_code=403,detail="You are not a member of this chat")

        statement = (
            select(DBMessage)
            .where(DBMessage.chat_id == current_chat_id)
            .order_by(DBMessage.id.desc())
            .limit(limit)
        )

        messages = session.scalars(statement).all()
        messages.reverse()

        return [
            {
                "id": str(message.id),
                "chat_id": str(message.chat_id),
                "sender_id": str(message.sender_id),
                "text": message.text,
            }
            for message in messages
        ]

@api.patch("/api/v1/messages/{message_id}")
def update_message(message_id: str, data: MessageUpdate, current_user_id: int = Depends(get_current_user_id),):
    try:
        current_message_id = int(message_id)
    except ValueError:
        raise HTTPException(status_code=400,detail="Message ID and user ID must be integers")

    if not data.text.strip():
        raise HTTPException(status_code=400,detail="Message cannot be empty")

    with SessionLocal() as session:
        message = session.get(DBMessage, current_message_id)

        if message is None:
            raise HTTPException(status_code=404,detail="Message not found")

        if message.sender_id != current_user_id:
            raise HTTPException(status_code=403,detail="You can only edit your own messages")

        membership = session.scalar(select(ChatMember).where(ChatMember.chat_id == message.chat_id,ChatMember.user_id == current_user_id))

        if membership is None:
            raise HTTPException(status_code=403,detail="You are not a member of this chat")

        message.text = data.text.strip()
        session.commit()
        session.refresh(message)

        return {
            "message": "Message updated",
            "id": str(message.id),
            "chat_id": str(message.chat_id),
            "sender_id": str(message.sender_id),
            "text": message.text,
        }

@api.delete("/api/v1/chats/{chat_id}")
def delete_chat(chat_id: str, current_user_id: int = Depends(get_current_user_id)):
    try:
        current_chat_id = int(chat_id)
    except ValueError:
        raise HTTPException(status_code=400,detail="Chat ID and user ID must be integers")

    with SessionLocal() as session:
        chat = session.get(DBChat, current_chat_id)

        if chat is None:
            raise HTTPException(status_code=404, detail="Chat not found")

        if chat.owner_id != current_user_id:
            raise HTTPException(status_code=403,detail="Only the chat owner can delete it")

        membership = session.scalar(select(ChatMember).where(ChatMember.chat_id == current_chat_id,ChatMember.user_id == current_user_id))
        
        if membership is None:
            raise HTTPException(status_code=403,detail="You are not a member of this chat")

        session.delete(chat)
        session.commit()

        return {
            "message": "Chat deleted",
            "chat_id": str(current_chat_id),
        }

@api.delete("/api/v1/messages/{message_id}")
def delete_message(message_id: str, current_user_id: int = Depends(get_current_user_id)):
    try:
        current_message_id = int(message_id)
    except ValueError:
        raise HTTPException(status_code=400,detail="Message ID and user ID must be integers")

    with SessionLocal() as session:
        message = session.get(DBMessage, current_message_id)

        if message is None:
            raise HTTPException(status_code=404,detail="Message not found")

        if message.sender_id != current_user_id:
            raise HTTPException(status_code=403,detail="You can only delete your own messages")

        membership = session.scalar(select(ChatMember).where(ChatMember.chat_id == message.chat_id,ChatMember.user_id == current_user_id))

        if membership is None:
            raise HTTPException(status_code=403,detail="You are not a member of this chat")

        session.delete(message)
        session.commit()

        return {
            "message": "Message deleted",
            "message_id": str(current_message_id),
        }