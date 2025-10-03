import uuid
from typing import Any

from sqlmodel import Session, select

from app.core.security import get_password_hash, verify_password
from app.models import (
    EdgeRouter,
    EdgeRouterCreate,
    EdgeRouterUpdate,
    Item,
    ItemCreate,
    NeighborDevice,
    User,
    UserCreate,
    UserUpdate,
)


def create_user(*, session: Session, user_create: UserCreate) -> User:
    db_obj = User.model_validate(
        user_create, update={"hashed_password": get_password_hash(user_create.password)}
    )
    session.add(db_obj)
    session.commit()
    session.refresh(db_obj)
    return db_obj


def update_user(*, session: Session, db_user: User, user_in: UserUpdate) -> Any:
    user_data = user_in.model_dump(exclude_unset=True)
    extra_data = {}
    if "password" in user_data:
        password = user_data["password"]
        hashed_password = get_password_hash(password)
        extra_data["hashed_password"] = hashed_password
    db_user.sqlmodel_update(user_data, update=extra_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


def get_user_by_email(*, session: Session, email: str) -> User | None:
    statement = select(User).where(User.email == email)
    session_user = session.exec(statement).first()
    return session_user


def authenticate(*, session: Session, email: str, password: str) -> User | None:
    db_user = get_user_by_email(session=session, email=email)
    if not db_user:
        return None
    if not verify_password(password, db_user.hashed_password):
        return None
    return db_user


def create_item(*, session: Session, item_in: ItemCreate, owner_id: uuid.UUID) -> Item:
    db_item = Item.model_validate(item_in, update={"owner_id": owner_id})
    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item


# EdgeRouter CRUD operations
def create_edge_router(
    *,
    session: Session,
    router_data: dict[str, Any],
    created_by: uuid.UUID,
) -> EdgeRouter:
    """
    Create a new EdgeRouter with hashed password.
    router_data should include all fields from MikroTik API response.
    """
    # Hash the password before storing
    hashed_password = get_password_hash(router_data["password"])
    router_data["hashed_password"] = hashed_password
    router_data["created_by"] = created_by

    # Remove plain password
    router_data.pop("password")

    db_router = EdgeRouter(**router_data)
    session.add(db_router)
    session.commit()
    session.refresh(db_router)
    return db_router


def get_edge_router_by_serial(
    *, session: Session, serial_number: str
) -> EdgeRouter | None:
    """Get EdgeRouter by serial number."""
    statement = select(EdgeRouter).where(EdgeRouter.serial_number == serial_number)
    return session.exec(statement).first()


def get_edge_router_by_ip(*, session: Session, router_ip: str) -> EdgeRouter | None:
    """Get EdgeRouter by IP address."""
    statement = select(EdgeRouter).where(EdgeRouter.router_ip == router_ip)
    return session.exec(statement).first()


def get_edge_routers(
    *, session: Session, skip: int = 0, limit: int = 100
) -> list[EdgeRouter]:
    """Get all EdgeRouters with pagination."""
    statement = select(EdgeRouter).offset(skip).limit(limit)
    return list(session.exec(statement).all())


def update_edge_router(
    *, session: Session, db_router: EdgeRouter, router_in: EdgeRouterUpdate
) -> EdgeRouter:
    """Update EdgeRouter fields."""
    router_data = router_in.model_dump(exclude_unset=True)
    extra_data = {}

    # Hash password if it's being updated
    if "password" in router_data:
        password = router_data.pop("password")
        extra_data["hashed_password"] = get_password_hash(password)

    db_router.sqlmodel_update(router_data, update=extra_data)
    session.add(db_router)
    session.commit()
    session.refresh(db_router)
    return db_router


def delete_edge_router(*, session: Session, db_router: EdgeRouter) -> None:
    """Delete EdgeRouter (will cascade delete neighbors)."""
    session.delete(db_router)
    session.commit()


# NeighborDevice CRUD operations
def create_neighbor_device(
    *, session: Session, neighbor_data: dict[str, Any], edge_router_serial: str
) -> NeighborDevice:
    """Create a new NeighborDevice."""
    neighbor_data["edge_router_serial"] = edge_router_serial
    db_neighbor = NeighborDevice(**neighbor_data)
    session.add(db_neighbor)
    session.commit()
    session.refresh(db_neighbor)
    return db_neighbor


def get_neighbors_by_router(
    *, session: Session, edge_router_serial: str
) -> list[NeighborDevice]:
    """Get all neighbors for a specific EdgeRouter."""
    statement = select(NeighborDevice).where(
        NeighborDevice.edge_router_serial == edge_router_serial
    )
    return list(session.exec(statement).all())


def delete_neighbors_by_router(
    *, session: Session, edge_router_serial: str
) -> None:
    """Delete all neighbors for a specific EdgeRouter (for refresh)."""
    statement = select(NeighborDevice).where(
        NeighborDevice.edge_router_serial == edge_router_serial
    )
    neighbors = session.exec(statement).all()
    for neighbor in neighbors:
        session.delete(neighbor)
    session.commit()
