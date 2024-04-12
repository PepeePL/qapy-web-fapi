from datetime import timedelta, datetime, timezone
import os
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError, ExpiredSignatureError
from dotenv import load_dotenv

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

load_dotenv()
SECRET_KEY = os.environ['SECRET']
ALGORITHM = "HS256"

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/session')

class CreateUserRequest(BaseModel):
    username: str
    password: str
    permission: int
    
class Token(BaseModel):
    access_token: str
    token_type: str
    
class PatchUserRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    permission: Optional[int] = None
    
def check_permission(required_permission: int, user_permission: int):
    if user_permission < required_permission:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permission.')    
    

        
def auth_user(username: str, password: str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_pass):
        return False
    return user

def create_session(username:str, user_id: int, permission_level: int, expires_delta: timedelta):
    encode = {'id': user_id, 'sub': username, 'permission': permission_level}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)
    
def get_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp_time: int = payload.get('exp')
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        permission_level: int = payload.get('permission')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Couldn't validate user.")
        return {'username': username, 'id': user_id, 'permission': permission_level}
    except ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_410_GONE,
                                detail="The token has expired.")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Couldn't validate user.")        

user_dependency = Annotated[dict, Depends(get_user)]



@router.post('/', status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, user: user_dependency, create_user_request: CreateUserRequest):
    check_permission(99, user.get('permission'))
    
    create_user_model = Users(
        username=create_user_request.username,
        hashed_pass=bcrypt_context.hash(create_user_request.password),
        permission_level=create_user_request.permission
    )
    db.add(create_user_model)
    db.commit()
    
@router.delete('/{user_id}', status_code=status.HTTP_204_NO_CONTENT)
async def remove_user(user_id: int, db: db_dependency, user: user_dependency):
    target_user = db.query(Users).filter(Users.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found.')
    check_permission(80, user.get('permission'))
    check_permission(target_user.permission_level, user.get('permission'))
    
    db.delete(target_user)
    db.commit()

@router.patch('/{user_id}', status_code=status.HTTP_200_OK)
async def patch_user(user_id: int, db: db_dependency, user: user_dependency, patch_user_request: PatchUserRequest):
    target_user = db.query(Users).filter(Users.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found.')
    if user.get('permission') < 80 or user.get('permission') <= target_user.permission_level:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permission.')
    
    if patch_user_request.username:
        target_user.username = patch_user_request.username
    if patch_user_request.password:
        target_user.hashed_pass = bcrypt_context.hash(patch_user_request.password)
    if patch_user_request.permission is not None:
        if user.get('permission') <= patch_user_request.permission:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permission')
        target_user.permission_level = patch_user_request.permission
    db.commit()
    return target_user

        
@router.post("/session", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: db_dependency):
    user = auth_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Couldn't validate user.")
    session = create_session(user.username, user.id, user.permission_level, timedelta(hours=6))
    
    return {'access_token': session, 'token_type': 'bearer'}

@router.get("/permission", status_code=status.HTTP_200_OK)
async def check_user_permission(token: str, required_permission: int):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        permission_level: int = payload.get('permission')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Couldn't validate user.")
        
        check_permission(required_permission, permission_level)
        return {"detail": "Permission granted."}
    
    except ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_410_GONE,
                                detail="The token has expired.")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Couldn't validate user.") 
        
@router.get("/", status_code=status.HTTP_200_OK)
async def user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail='Auth Failed')
    return {'User': user}

@router.get('/users', status_code=status.HTTP_200_OK)
async def list_users(db: db_dependency):
    users = db.query(Users).all()
    user_list = [{"id": user.id, "username": user.username, "permission_level": user.permission_level} for user in users]
    return user_list