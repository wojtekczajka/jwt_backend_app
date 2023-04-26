from sqlalchemy.orm import Session
from security import get_password_hash
from datetime import datetime, timedelta

import models, schemas


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_user_by_name(db: Session, name: str):
    return db.query(models.User).filter(models.User.name == name).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(email=user.email, name=user.name,
                          hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def delete_user(db: Session, user_id: int):
    user = get_user(db=db, user_id=user_id)
    if not user:
        return False
    db.delete(user)
    db.commit()
    return user


def delete_null_user_roles(db: Session):
    db.query(models.UserRole).filter(models.UserRole.user_id == None).delete()
    db.commit()


# def delete_user_roles(db: Session, user_id: int):
#     return db.query(models.User).filter(models.User.id == user_id).first()


def set_user_is_active(db: Session, user_id: int, is_active: bool):
    user = get_user(db=db, user_id=user_id)
    if not user:
        return None
    user.is_active = is_active
    db.commit()
    db.refresh(user)
    return user


def create_role(db: Session, role: schemas.RollCreate):
    db_role = models.Role(name=role.name, description=role.description)
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return db_role


def get_role_by_name(db: Session, name: str):
    return db.query(models.Role).filter(models.Role.name == name).first()


def get_roles(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Role).offset(skip).limit(limit).all()


def create_user_role(db: Session, user_role: schemas.UserRoleCreate):
    db_user_role = models.UserRole(
        user_id=user_role.user_id, role_id=user_role.role_id)
    db.add(db_user_role)
    db.commit()
    db.refresh(db_user_role)
    return db_user_role


def get_users_roles(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.UserRole).offset(skip).limit(limit).all()

def get_user_roles_names(db: Session, user_id: int):
    roles = db.query(models.Role.name).join(models.UserRole).filter(models.UserRole.user_id == user_id).all()
    return [role[0] for role in roles]

def get_user_role_by_name(db: Session, user_id: int, role_name: str):
    return db.query(models.UserRole).join(models.Role).filter(models.UserRole.user_id == user_id, models.Role.name == role_name).first()


def get_user_roles(db: Session, user_id: int):
    return db.query(models.UserRole).join(models.Role).filter(models.UserRole.user_id == user_id)

def get_inactive_users(db: Session, skip: int = 0, limit: int = 100):
    #yesterday = datetime.utcnow() - timedelta(days=1)
    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
    return db.query(models.User).filter(models.User.is_active == False, models.User.created_at <= one_minute_ago).offset(skip).limit(limit).all()

def delete_inactive_users(db: Session):
    inactive_users = get_inactive_users(db)
    print(inactive_users)
    for user in inactive_users:
        print(user)
        delete_user(db, user.id)
    return len(inactive_users)
