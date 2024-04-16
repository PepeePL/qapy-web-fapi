import secrets
from pydantic import BaseModel
from database import db_dependency
from auth import user_dependency
from typing import Optional
from fastapi import APIRouter, status, HTTPException
from models import URL, User

router = APIRouter(
    prefix="/short",
    tags=["short"]
)
class URLRequest(BaseModel):
    long_url: str
    custom_short_url: Optional[str] = None

class PatchURLRequest(BaseModel):
    long_url: Optional[str] = None
    custom_short_url: Optional[str] = None
class URLResponse(BaseModel):
    short_url: str

@router.get("/urls/", status_code=status.HTTP_200_OK)
async def list_urls(db: db_dependency, user: user_dependency):
    caller_user = db.query(User).filter(User.username == user.get('username')).first()
    if caller_user.no_permission_and_not_admin(13):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permission.")
    urls = db.query(URL).all()
    url_list = [{"id": url.id, "short_url": url.short_code, "long_url": url.long_url} for url in urls]
    return url_list

@router.post("/shorten", response_model=URLResponse, status_code=status.HTTP_201_CREATED)
async def shorten_url(request: URLRequest, db: db_dependency, user: user_dependency):
    caller_user = db.query(User).filter(User.username == user.get('username')).first()
    
    if caller_user.no_permission_and_not_admin(9):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permission.")
    if caller_user.no_permission_and_not_admin(10):
        short_code = secrets.token_urlsafe(6)

    else:
        short_code = request.custom_short_url or secrets.token_urlsafe(6)
    url = URL(short_code=short_code, long_url=request.long_url)
    db.add(url)
    db.commit()
    return {"short_url": f"http://localhost:8000/{short_code}"}

@router.patch("/urls/{url_id}", status_code=status.HTTP_200_OK)
async def update_url(url_id: int, url_update: PatchURLRequest, db: db_dependency, user: user_dependency):
    caller_user = db.query(User).filter(User.username == user.get('username')).first()
    if caller_user.no_permission_and_not_admin(11):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permission.")
    db_url = db.query(URL).filter(URL.id == url_id).first()
    if not db_url:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="URL not found")

    if url_update.long_url:
        db_url.long_url = url_update.long_url
    if url_update.custom_short_url:
        db_url.short_code = url_update.custom_short_url
    db.commit()

    return {"short_url": f"http://localhost:8000/{db_url.short_code}"}

@router.delete("/urls/{url_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_url_record(url_id: int, db: db_dependency, user: user_dependency):
    caller_user = db.query(User).filter(User.username == user.get('username')).first()
    if caller_user.no_permission_and_not_admin(12):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permission.")
    url = db.query(URL).get(url_id)
    if not url:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="URL not found")

    db.delete(url)
    db.commit()
    return
