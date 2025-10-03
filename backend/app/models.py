import uuid

from pydantic import EmailStr
from sqlmodel import Field, Relationship, SQLModel


# Shared properties
class UserBase(SQLModel):
    email: EmailStr = Field(unique=True, index=True, max_length=255)
    is_active: bool = True
    is_superuser: bool = False
    full_name: str | None = Field(default=None, max_length=255)


# Properties to receive via API on creation
class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=40)


class UserRegister(SQLModel):
    email: EmailStr = Field(max_length=255)
    password: str = Field(min_length=8, max_length=40)
    full_name: str | None = Field(default=None, max_length=255)


# Properties to receive via API on update, all are optional
class UserUpdate(UserBase):
    email: EmailStr | None = Field(default=None, max_length=255)  # type: ignore
    password: str | None = Field(default=None, min_length=8, max_length=40)


class UserUpdateMe(SQLModel):
    full_name: str | None = Field(default=None, max_length=255)
    email: EmailStr | None = Field(default=None, max_length=255)


class UpdatePassword(SQLModel):
    current_password: str = Field(min_length=8, max_length=40)
    new_password: str = Field(min_length=8, max_length=40)


# Database model, database table inferred from class name
class User(UserBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    hashed_password: str
    items: list["Item"] = Relationship(back_populates="owner", cascade_delete=True)


# Properties to return via API, id is always required
class UserPublic(UserBase):
    id: uuid.UUID


class UsersPublic(SQLModel):
    data: list[UserPublic]
    count: int


# Shared properties
class ItemBase(SQLModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=255)


# Properties to receive on item creation
class ItemCreate(ItemBase):
    pass


# Properties to receive on item update
class ItemUpdate(ItemBase):
    title: str | None = Field(default=None, min_length=1, max_length=255)  # type: ignore


# Database model, database table inferred from class name
class Item(ItemBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    owner_id: uuid.UUID = Field(
        foreign_key="user.id", nullable=False, ondelete="CASCADE"
    )
    owner: User | None = Relationship(back_populates="items")


# Properties to return via API, id is always required
class ItemPublic(ItemBase):
    id: uuid.UUID
    owner_id: uuid.UUID


class ItemsPublic(SQLModel):
    data: list[ItemPublic]
    count: int


# Generic message
class Message(SQLModel):
    message: str


# JSON payload containing access token
class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"


# Contents of JWT token
class TokenPayload(SQLModel):
    sub: str | None = None


class NewPassword(SQLModel):
    token: str
    new_password: str = Field(min_length=8, max_length=40)


# EdgeRouter (MikroTik Router) models
class EdgeRouterBase(SQLModel):
    router_ip: str = Field(max_length=45, index=True)  # IPv4 or IPv6
    device_name: str | None = Field(default=None, max_length=255)
    mac_address: str | None = Field(default=None, max_length=17)
    username: str = Field(max_length=255)
    status: str = Field(default="active", max_length=50)  # active, inactive, error
    port: int = Field(default=80, ge=1, le=65535)  # Port number (1-65535)


class EdgeRouterCreate(SQLModel):
    router_ip: str = Field(max_length=45)
    username: str = Field(max_length=255)
    password: str = Field(max_length=255)  # Plain password from form
    port: int = Field(default=80, ge=1, le=65535)  # Port number, default 80


class EdgeRouterUpdate(SQLModel):
    router_ip: str | None = Field(default=None, max_length=45)
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=255)
    device_name: str | None = Field(default=None, max_length=255)
    status: str | None = Field(default=None, max_length=50)
    port: int | None = Field(default=None, ge=1, le=65535)


class EdgeRouter(EdgeRouterBase, table=True):
    serial_number: str = Field(primary_key=True, max_length=255)
    hashed_password: str  # Encrypted password
    board_name: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=100)
    platform: str | None = Field(default=None, max_length=100)
    uptime: str | None = Field(default=None, max_length=100)
    cpu: str | None = Field(default=None, max_length=255)
    created_at: str = Field(default_factory=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat())
    created_by: uuid.UUID = Field(foreign_key="user.id", nullable=False)

    # Relationships
    creator: User | None = Relationship()
    neighbors: list["NeighborDevice"] = Relationship(
        back_populates="edge_router", cascade_delete=True
    )


class EdgeRouterPublic(EdgeRouterBase):
    serial_number: str
    board_name: str | None
    version: str | None
    platform: str | None
    uptime: str | None
    cpu: str | None
    created_at: str
    created_by: uuid.UUID


class EdgeRoutersPublic(SQLModel):
    data: list[EdgeRouterPublic]
    count: int


# NeighborDevice models (discovered devices)
class NeighborDeviceBase(SQLModel):
    router_ip: str | None = Field(default=None, max_length=45)
    device_name: str | None = Field(default=None, max_length=255)
    mac_address: str | None = Field(default=None, max_length=17, index=True)
    status: str = Field(default="discovered", max_length=50)
    interface: str | None = Field(default=None, max_length=100)
    platform: str | None = Field(default=None, max_length=100)
    version: str | None = Field(default=None, max_length=100)


class NeighborDevice(NeighborDeviceBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    edge_router_serial: str = Field(
        foreign_key="edgerouter.serial_number", nullable=False, ondelete="CASCADE"
    )
    discovered_at: str = Field(default_factory=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat())

    # Relationships
    edge_router: EdgeRouter | None = Relationship(back_populates="neighbors")


class NeighborDevicePublic(NeighborDeviceBase):
    id: uuid.UUID
    edge_router_serial: str
    discovered_at: str


class NeighborDevicesPublic(SQLModel):
    data: list[NeighborDevicePublic]
    count: int
