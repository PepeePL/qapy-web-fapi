from database import engine, SessionLocal
from typing import Annotated
from sqlalchemy.orm import Session
from fastapi import FastAPI, status, Depends, HTTPException
from fastapi.responses import RedirectResponse
import models
import auth
import short
from auth import get_user
from fastapi.middleware.cors import CORSMiddleware
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

app = FastAPI()

app.include_router(auth.router)
app.include_router(short.router)
models.Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

user_dependency = Annotated[dict, Depends(get_user)]

@app.get("/{short_code}", response_model=short.URLResponse)
async def redirect_to_long_url(short_code: str, db: db_dependency):
    url = db.query(models.URL).filter(models.URL.short_code == short_code).first()
    if not url:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="URL not found")
    return RedirectResponse(url=url.long_url)