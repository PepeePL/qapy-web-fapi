from database import Base
from sqlalchemy import Column, Integer, String


class Users(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    hashed_pass = Column(String)
    permission_level = Column(Integer)