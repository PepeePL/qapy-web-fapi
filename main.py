from fastapi.responses import RedirectResponse
from database import engine
from database import db_dependency
from fastapi import FastAPI, HTTPException, status
import models
import auth
import short
import permissions
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

app.include_router(auth.router)
app.include_router(permissions.router)
app.include_router(short.router)
models.Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/{short_code}", response_model=short.URLResponse)
async def redirect_to_long_url(short_code: str, db: db_dependency):
    url = db.query(models.URL).filter(models.URL.short_code == short_code).first()
    if not url:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="URL not found")
    return RedirectResponse(url=url.long_url)