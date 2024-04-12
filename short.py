import secrets
from pydantic import BaseModel
from auth import check_permission, get_user
from database import SessionLocal
from typing import Annotated, Optional
from sqlalchemy.orm import Session
from fastapi import APIRouter, status, Depends, HTTPException
from models import URL

router = APIRouter(
    prefix="/short",
    tags=["short"]
)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_user)]
class URLRequest(BaseModel):
    long_url: str
    custom_short_url: Optional[str] = None

class PatchURLRequest(BaseModel):
    long_url: Optional[str] = None
    custom_short_url: Optional[str] = None

# class URLPermissionRequest(BaseModel):
#     token: str

class URLResponse(BaseModel):
    short_url: str

@router.get("/urls/", status_code=status.HTTP_200_OK)
async def list_urls(db: db_dependency):
    urls = db.query(URL).all()
    url_list = [{"id": url.id, "short_url": url.short_code, "long_url": url.long_url} for url in urls]
    return url_list

@router.post("/shorten", response_model=URLResponse)
async def shorten_url(request: URLRequest, db: db_dependency, user: user_dependency):
    check_permission(30, user.get('permission'))

    short_code = request.custom_short_url or secrets.token_urlsafe(6)
    
    url = URL(short_code=short_code, long_url=request.long_url)
    db.add(url)
    db.commit()

    return {"short_url": f"http://localhost:8000/{short_code}"}

@router.patch("/url/{url_id}", status_code=status.HTTP_200_OK)
async def update_url(url_id: int, url_update: PatchURLRequest, db: db_dependency, user: user_dependency):
    check_permission(40, user.get('permission'))
    db_url = db.query(URL).filter(URL.id == url_id).first()
    if not db_url:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="URL not found")

    if url_update.long_url:
        db_url.long_url = url_update.long_url
    if url_update.custom_short_url:
        db_url.short_code = url_update.custom_short_url
    db.commit()

    return {"short_url": f"http://localhost:8000/{db_url.short_code}"}

@router.delete("/url/{url_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_url_record(url_id: int, db: db_dependency, user: user_dependency):
    check_permission(40, user.get('permission'))
    url = db.query(URL).get(url_id)
    if not url:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="URL not found")

    db.delete(url)
    db.commit()
