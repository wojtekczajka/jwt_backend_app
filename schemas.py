from pydantic import BaseModel
from typing import List, Union
import datetime


class UserRoleBase(BaseModel):
    user_id: int
    role_id: int


class UserRoleCreate(UserRoleBase):
    pass


class UserRole(UserRoleBase):
    id: int

    class Config:
        orm_mode = True


class UserBase(BaseModel):
    name: str


class UserId(BaseModel):
    user_id: int


class UserCreate(UserBase):
    email: str
    password: str


class UserLogin(UserBase):
    password: str


class User(UserBase):
    id: int
    is_active: bool
    email: str
    created_at: datetime.datetime

    roles: list[UserRole] = []

    class Config:
        orm_mode = True

class UserAll(User):
    hashed_password: str


# class UserInfo(User):
#     roles: list[str]


class RoleBase(BaseModel):
    name: str
    description: str


class RollCreate(RoleBase):
    pass


class Role(RoleBase):
    id: int

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class UsersResponse(BaseModel):
    data: List[User]
    count: int


class PublicResources(BaseModel):
    public_resources: str
