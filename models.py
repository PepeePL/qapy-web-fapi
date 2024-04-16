from database import Base
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Table
from sqlalchemy.orm import relationship

user_permissions = Table('user_permissions', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('permission_id', Integer, ForeignKey('permissions.id'))
)
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    hashed_pass = Column(String)
    permission_level = Column(Integer)
    permissions = relationship("Permission", secondary=user_permissions, back_populates="users")
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    def has_permission(self, permission_id):
        for permission in self.permissions:
            if permission.id == permission_id:
                return True
        return False
    def no_permission_and_not_admin(self, permission_id):
        if self.is_admin: return False
        for permission in self.permissions:
            if permission.id == permission_id:
                return False
        return True
    def permissions_as_list(self):
        return [item.id for item in self.permissions]
        

class Permission(Base):
    __tablename__ = 'permissions'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)

    # Relationship with users
    users = relationship("User", secondary=user_permissions, back_populates="permissions")

class URL(Base):
    __tablename__ = "urls"

    id = Column(Integer, primary_key=True, index=True)
    short_code = Column(String, index=True, unique=True)
    long_url = Column(String, index=True)