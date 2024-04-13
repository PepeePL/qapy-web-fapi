from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from models import Permission, User
from database import db_dependency
from auth import user_dependency
router = APIRouter(
    prefix="/perms",
    tags=["permissions"]
)
class CreatePermissionRequest(BaseModel):
    name: str
    
@router.get("/permissions", status_code=status.HTTP_200_OK)
async def list_permissions(db: db_dependency, user: user_dependency):
    caller_user = db.query(User).filter(User.username == user.get('username')).first()
    if caller_user.no_permission_and_not_admin(8):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permission.")
    permissions = db.query(Permission).all()
    permission_list = [{"id": permission.id, "name": permission.name} for permission in permissions]
    return permission_list

@router.post("/permissions", status_code=status.HTTP_201_CREATED)
async def create_permission(permission: CreatePermissionRequest, db: db_dependency, user: user_dependency):
    caller_user = db.query(User).filter(User.username == user.get('username')).first()
    if caller_user.no_permission_and_not_admin(5):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permission.")
    db_permission = Permission(name=permission.name)
    db.add(db_permission)
    db.commit()
    db.refresh(db_permission)
    return db_permission

@router.patch("/permissions/{permission_id}", status_code=status.HTTP_200_OK)
async def patch_permission(permission_id: int, updated_permission: CreatePermissionRequest, db: db_dependency, user: user_dependency):
    caller_user = db.query(User).filter(User.username == user.get('username')).first()
    if caller_user.no_permission_and_not_admin(6):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permission.")
    permission = db.query(Permission).filter(Permission.id == permission_id).first()
    if not permission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")
    
    permission.name = updated_permission.name
    db.commit()
    
    return permission

@router.delete("/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_permission(permission_id: int, db: db_dependency, user: user_dependency):
    caller_user = db.query(User).filter(User.username == user.get('username')).first()
    if caller_user.no_permission_and_not_admin(7):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permission.")
    permission = db.query(Permission).filter(Permission.id == permission_id).first()
    if not permission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")
    
    db.delete(permission)
    db.commit()
    return