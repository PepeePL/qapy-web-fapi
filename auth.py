from datetime import timedelta, datetime, timezone
import os
from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from starlette import status
from database import db_dependency
from models import Permission, User
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError, ExpiredSignatureError
from dotenv import load_dotenv

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

load_dotenv()
SECRET_KEY = os.environ['SECRET']
ALGORITHM = "HS256"
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/session')

class CreateUserRequest(BaseModel):
    username: str
    password: str
    permission_level: int
    permissions: List[int] = []
    is_admin: bool = False
    
class PatchUserRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    permission_level: Optional[int] = None
    permissions: Optional[List[int]] = None
    
class Token(BaseModel):
    access_token: str
    token_type: str
    
def auth_user(username: str, password: str, db: db_dependency):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_pass):
        return False
    return user

def create_session(username:str, user_id: int, permissions: list[str], permission_level: int, expires_delta: timedelta):
    encode = {'id': user_id, 'sub': username, 'permissions': permissions, 'permission_level': permission_level}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)
    
def get_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        permissions: List[int] = payload.get('permissions')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Couldn't validate user.")
        return {'username': username, 'id': user_id, 'permissions': permissions}
    except ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_410_GONE,
                                detail="The token has expired.")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Couldn't validate user.")        

user_dependency = Annotated[dict, Depends(get_user)]

@router.get('/users', status_code=status.HTTP_200_OK)
async def list_users(db: db_dependency, user: user_dependency):
    caller_user = db.query(User).filter(User.username == user.get('username')).first()
    if caller_user.no_permission_and_not_admin(4):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permission.")
    users = db.query(User).all()
    user_list = [{"id": user.id, "username": user.username, "permission_level": user.permission_level,
                  "permissions": user.permissions, "created_at": user.created_at,
                  "updated_at": user.updated_at, "is_admin": user.is_admin} for user in users]
    return user_list

@router.post('/users', status_code=status.HTTP_201_CREATED)
async def create_user(user: CreateUserRequest, db: db_dependency, cuser: user_dependency):
    db_existing_user = db.query(User).filter(User.username == user.username).first()
    if db_existing_user:
        raise HTTPException(status_code=400, detail="User with this username already exists")
    caller_user = db.query(User).filter(User.username == cuser.get('username')).first()
    if caller_user.no_permission_and_not_admin(1):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permission.")
    db_user = User(username=user.username, hashed_pass=bcrypt_context.hash(user.password),
                   permission_level=user.permission_level, is_admin=False,
                   created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc))
    if caller_user.is_admin:
        db_user.is_admin = user.is_admin
    request_permissions = db.query(Permission).filter(Permission.id.in_(user.permissions)).all()
    db_user.permissions.extend(request_permissions)

    db.add(db_user)
    db.commit()
    return db_user
    
@router.delete('/users/{user_id}', status_code=status.HTTP_204_NO_CONTENT)
async def remove_user(user_id: int, db: db_dependency, user: user_dependency):
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found.')
    caller_user = db.query(User).filter(User.username == user.get('username')).first()
    if not caller_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found.')
    
    if caller_user.is_admin:
        db.delete(target_user)
        db.commit()
        return
    
    if not caller_user.has_permission(3):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permission.')
    
    if target_user.permission_level >= caller_user.permission_level:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permission.')
    
    db.delete(target_user)
    db.commit()
    return

@router.patch('/users/{user_id}', status_code=status.HTTP_200_OK)
async def patch_user(user_id: int, db: db_dependency, user: user_dependency, changed_user_request: PatchUserRequest):
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found.')
    caller_user = db.query(User).filter(User.username == user.get('username')).first()
    if not caller_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found.')
    
    if caller_user.is_admin:
        if changed_user_request.username:
            target_user.username = changed_user_request.username
        
        if changed_user_request.password:
            target_user.hashed_pass = bcrypt_context.hash(changed_user_request.password)
        if changed_user_request.permission_level:
            target_user.permission_level = changed_user_request.permission_level
        if changed_user_request.permissions:
            target_user.permissions.clear()
            request_permissions = db.query(Permission).filter(Permission.id.in_(changed_user_request.permissions)).all()
            target_user.permissions.extend(request_permissions)
        target_user.updated_at = datetime.now(timezone.utc)
        db.commit()
        return target_user
    
    if not caller_user.has_permission(2):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permission.')
    
    if changed_user_request.username:
        target_user.username = changed_user_request.username
        
    if changed_user_request.password:
        target_user.hashed_pass = bcrypt_context.hash(changed_user_request.password)
        
    if changed_user_request.permission_level:
        if changed_user_request.permission_level >= caller_user.permission_level:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permission')
        target_user.permission_level = changed_user_request.permission_level
    
    if changed_user_request.permissions:
        caller_permissions = set(caller_user.permissions_as_list())
        target_permissions = set(target_user.permissions_as_list())
        changed_permissions = set(changed_user_request.permissions).difference(target_permissions)
        
        for permission in changed_user_request.permissions:
            # Check if caller added a permission they don't have
            if permission not in caller_permissions and permission in changed_permissions:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permission')
        for permission in target_permissions:
            # Check if caller revoked a permission they don't have
            if permission not in caller_permissions and permission not in changed_user_request.permissions:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not enough permission')
                
        target_user.permissions.clear()
        request_permissions = db.query(Permission).filter(Permission.id.in_(changed_user_request.permissions)).all()
        target_user.permissions.extend(request_permissions)
    target_user.updated_at = datetime.now(timezone.utc)
    db.commit()
    return target_user

@router.post("/session", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],#
                                 db: db_dependency):
    
    user = auth_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Couldn't validate user.")
    session = create_session(user.username, user.id, user.permissions_as_list(), user.permission_level, timedelta(hours=6))
    
    return {'access_token': session, 'token_type': 'bearer'}


# @router.get("/permission", status_code=status.HTTP_200_OK)
# async def check_user_permission(token: str, required_permission: int):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get('sub')
#         user_id: int = payload.get('id')
#         permission_level: int = payload.get('permission')
#         if username is None or user_id is None:
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
#                                 detail="Couldn't validate user.")
        
#         check_permission(required_permission, permission_level)
#         return {"detail": "Permission granted."}
    
#     except ExpiredSignatureError:
#             raise HTTPException(status_code=status.HTTP_410_GONE,
#                                 detail="The token has expired.")
#     except JWTError:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
#                                 detail="Couldn't validate user.") 
        
@router.get("/", status_code=status.HTTP_200_OK)
async def user(user: user_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail='Auth Failed')
    return {'User': user}
