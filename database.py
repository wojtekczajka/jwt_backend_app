from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import pymysql

pymysql.install_as_MySQLdb()

SQLALCHEMY_DATABASE_URL = "mysql://admin:!Bioshock13!@database-1.cqyfd9wssou1.eu-north-1.rds.amazonaws.com:3306/jwt_db"
#SQLALCHEMY_DATABASE_URL = "sqlite:///db/sql_app.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
