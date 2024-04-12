from typing import Annotated
import models
from sqlalchemy.orm import Session
from database import engine, SessionLocal
from fastapi import FastAPI, status, Depends, HTTPException
import auth
from auth import get_user
from models import Users
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.include_router(auth.router)
models.Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_user)]

@app.get("/", status_code=status.HTTP_200_OK)
async def user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail='Auth Failed')
    return {'User': user}

@app.get('/users', status_code=status.HTTP_200_OK)
async def list_users(db: db_dependency):
    users = db.query(Users).all()
    user_list = [{"id": user.id, "username": user.username, "permission_level": user.permission_level} for user in users]
    return user_list