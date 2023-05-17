from datetime import timedelta
import time
from fastapi import Depends, FastAPI, HTTPException, status, BackgroundTasks
from starlette.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session

from typing import Annotated

import crud
import models
import schemas
import security
import database

from mangum import Mangum


models.Base.metadata.create_all(bind=database.engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://main.d3f9gvqybmfju1.amplifyapp.com",
                   "http://main.d3f9gvqybmfju1.amplifyapp.com",
                   "http://127.0.0.1:8000/",
                   "https://ti4r36gvwlegcokae4ofeivnva0hwiqn.lambda-url.eu-north-1.on.aws/"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["x-access-token"],
)

background_tasks = BackgroundTasks()


def delete_inactive_users_task(db: Session):
    while True:
        crud.delete_inactive_users(db)
        time.sleep(10 * 60)  # Wait for 10 minutes before checking again


def start_inactive_users_deletion(db: Session):
    background_tasks.add_task(delete_inactive_users_task, db=db)


@app.on_event("startup")
def startup_event():
    db = database.get_db()
    start_inactive_users_deletion(db)


@app.post("/auth/signup/", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user = crud.get_user_by_name(db, name=user.name)
    if db_user:
        raise HTTPException(status_code=400, detail="Name already registered")
    # add user default user role after signup
    db_user = crud.create_user(db=db, user=user)
    user_role = schemas.UserRoleCreate(user_id=db_user.id, role_id=2)
    crud.create_user_role(db=db, user_role=user_role)
    return db_user


@app.post("/auth/signin/")
def login_user(form_data: schemas.UserLogin, db: Session = Depends(database.get_db)):
    user = security.authenticate_user(db, form_data.name, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token_expires = timedelta(
        minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.name}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "access_token_exp": access_token_expires}


@app.get("/resource/admin/", response_model=list[schemas.UserAll])
async def read_all_db_resources(user: Annotated[schemas.User, Depends(security.validate_token)],
                                db: Session = Depends(database.get_db),
                                skip: int = 0, limit: int = 100):
    security.verify_user_required_role(db, user, "admin")

    return crud.get_users(db, skip=skip, limit=limit)


@app.get("/resource/user/")
def read_user_data(user: Annotated[schemas.User, Depends(security.validate_token)],
                   db: Session = Depends(database.get_db),
                   skip: int = 0, limit: int = 100):
    security.verify_user_required_role(db, user, "user")
    return crud.get_roles(db, skip=skip, limit=limit)


@app.get("/resource/public/", response_model=schemas.PublicResources)
def get_public_resources():
    return schemas.PublicResources(public_resources="empty :(")


@app.get("/user/", response_model=schemas.User)
def read_user_info(user: Annotated[schemas.User, Depends(security.validate_token)],
                   db: Session = Depends(database.get_db)):
    return user


@app.delete("/user/")
def delete_user(  # user: Annotated[schemas.User, Depends(security.validate_token)],
        user_id: schemas.UserId,
        db: Session = Depends(database.get_db)):
    # security.verify_user_required_role(db, user, "admin")
    db_user = crud.get_user(db, user_id=user_id.user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db_user = crud.delete_user(db=db, user_id=user_id.user_id)
    crud.delete_null_user_roles(db=db)
    return db_user


@app.put("/activate_user/", response_model=schemas.User)
async def activate_user(  # user: Annotated[schemas.User, Depends(security.validate_token)],
        user_id: schemas.UserId,
        db: Session = Depends(database.get_db)):
    # security.verify_user_required_role(db, user, "admin")
    db_user = crud.set_user_is_active(
        db=db, user_id=user_id.user_id, is_active=True)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@app.post("/roles/", response_model=schemas.Role)
def create_role(  # user: Annotated[schemas.User, Depends(security.validate_token)],
        role: schemas.RollCreate,
        db: Session = Depends(database.get_db),):
    # security.verify_user_required_role(db, user, "admin")
    db_role = crud.get_role_by_name(db, name=role.name)
    if db_role:
        raise HTTPException(status_code=400, detail="Role already created")
    return crud.create_role(db=db, role=role)


@app.post("/user_roles/")
def create_user_role(  # user: Annotated[schemas.User, Depends(security.validate_token)],
        user_role: schemas.UserRoleBase,
        db: Session = Depends(database.get_db)):
    # security.verify_user_required_role(db, user, "admin")
    return crud.create_user_role(db=db, user_role=user_role)


handler = Mangum(app)
