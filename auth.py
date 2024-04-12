from datetime import timedelta, datetime, timezone
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError, ExpiredSignatureError

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)



SECRET_KEY = "123nu1id1l234l567lp7dsdfs8daek232132kdas2137"
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
    
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
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
        
db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_user)]



@router.post('/', status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, user: user_dependency, create_user_request: CreateUserRequest):
    if user.get('permission') < 99:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permission')
    
    create_user_model = Users(
        username=create_user_request.username,
        hashed_pass=bcrypt_context.hash(create_user_request.password),
        permission_level=create_user_request.permission
    )
    db.add(create_user_model)
    db.commit()
    
@router.delete('/{user_id}', status_code=status.HTTP_204_NO_CONTENT)
async def remove_user(user_id: int, db: db_dependency, user: user_dependency):
    if user.get('permission') < 99:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permission')
    
    target_user = db.query(Users).filter(Users.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    
    db.delete(target_user)
    db.commit()
        
@router.post("/session", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: db_dependency):
    user = auth_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Couldn't validate user.")
    session = create_session(user.username, user.id, user.permission_level, timedelta(hours=6))
    
    return {'access_token': session, 'token_type': 'bearer'}
    

        
