from database import Base
from sqlalchemy import Column, Integer, String


class Users(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    hashed_pass = Column(String)
    permission_level = Column(Integer)

class URL(Base):
    __tablename__ = "urls"

    id = Column(Integer, primary_key=True, index=True)
    short_code = Column(String, index=True, unique=True)
    long_url = Column(String, index=True)