import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from sqlmodel import func, select

from app import crud
from app.api.deps import CurrentUser, SessionDep
from app.models import (
    EdgeRouter,
    EdgeRouterCreate,
    EdgeRouterPublic,
    EdgeRoutersPublic,
    EdgeRouterUpdate,
    Message,
    NeighborDevice,
    NeighborDevicePublic,
    NeighborDevicesPublic,
)
from app.utils import (
    MikroTikAPIError,
    discover_mikrotik_neighbors,
    get_mikrotik_serial_number,
    test_mikrotik_connection,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/remote-devices", tags=["remote-devices"])


@router.post("/", response_model=EdgeRouterPublic)
async def create_remote_device(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    router_in: EdgeRouterCreate,
) -> Any:
    """
    Create a new EdgeRouter (Remote Device).

    This endpoint will:
    1. Test connection to the MikroTik router
    2. Fetch router details from /rest/system/resource
    3. Save the EdgeRouter to database
    4. Discover neighbors from /rest/ip/neighbor
    5. Save all discovered neighbors to database

    Only superusers can add remote devices.
    """
    # Check if user is superuser
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Only superusers can add remote devices"
        )

    # Check if router already exists by IP
    existing_router = crud.get_edge_router_by_ip(
        session=session, router_ip=router_in.router_ip
    )
    if existing_router:
        raise HTTPException(
            status_code=400,
            detail=f"Router with IP {router_in.router_ip} already exists",
        )

    try:
        # Step 1: Test connection and get router details
        logger.info(f"Testing connection to router {router_in.router_ip}:{router_in.port}")
        router_data = await test_mikrotik_connection(
            router_ip=router_in.router_ip,
            username=router_in.username,
            password=router_in.password,
            port=router_in.port,
        )

        # Step 2: Get serial number from routerboard
        logger.info(f"Fetching serial number for router {router_in.router_ip}:{router_in.port}")
        serial_number = await get_mikrotik_serial_number(
            router_ip=router_in.router_ip,
            username=router_in.username,
            password=router_in.password,
            port=router_in.port,
        )

        # Check if serial already exists
        existing_by_serial = crud.get_edge_router_by_serial(
            session=session, serial_number=serial_number
        )
        if existing_by_serial:
            raise HTTPException(
                status_code=400,
                detail=f"Router with serial {serial_number} already exists",
            )

        # Step 3: Prepare router data for database
        router_db_data = {
            "serial_number": serial_number,
            "router_ip": router_in.router_ip,
            "username": router_in.username,
            "password": router_in.password,  # Will be hashed in CRUD
            "port": router_in.port,
            "device_name": router_data.get("board-name"),
            "board_name": router_data.get("board-name"),
            "version": router_data.get("version"),
            "platform": router_data.get("platform"),
            "uptime": router_data.get("uptime"),
            "cpu": router_data.get("cpu"),
            "status": "active",
        }

        # Step 4: Save EdgeRouter to database
        logger.info(f"Saving router {router_in.router_ip} to database")
        db_router = crud.create_edge_router(
            session=session,
            router_data=router_db_data,
            created_by=current_user.id,
        )

        # Step 5: Discover neighbors
        logger.info(f"Discovering neighbors for router {router_in.router_ip}:{router_in.port}")
        try:
            neighbors = await discover_mikrotik_neighbors(
                router_ip=router_in.router_ip,
                username=router_in.username,
                password=router_in.password,
                port=router_in.port,
            )

            # Step 6: Save neighbors to database
            logger.info(f"Found {len(neighbors)} neighbors")
            for neighbor in neighbors:
                neighbor_data = {
                    "router_ip": neighbor.get("address"),
                    "device_name": neighbor.get("identity"),
                    "mac_address": neighbor.get("mac-address"),
                    "interface": neighbor.get("interface"),
                    "platform": neighbor.get("platform"),
                    "version": neighbor.get("version"),
                    "status": "discovered",
                }
                crud.create_neighbor_device(
                    session=session,
                    neighbor_data=neighbor_data,
                    edge_router_serial=db_router.serial_number,
                )

        except MikroTikAPIError as e:
            logger.warning(f"Failed to discover neighbors: {e}")
            # Don't fail the whole operation if neighbor discovery fails

        return db_router

    except MikroTikAPIError as e:
        logger.error(f"MikroTik API error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to add remote device: {str(e)}"
        )


@router.get("/", response_model=EdgeRoutersPublic)
def read_remote_devices(
    session: SessionDep,
    current_user: CurrentUser,
    skip: int = 0,
    limit: int = 100,
) -> Any:
    """
    Retrieve all EdgeRouters (Remote Devices).
    Only superusers can view remote devices.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Only superusers can view remote devices"
        )

    count_statement = select(func.count()).select_from(EdgeRouter)
    count = session.exec(count_statement).one()

    statement = select(EdgeRouter).offset(skip).limit(limit)
    routers = session.exec(statement).all()

    return EdgeRoutersPublic(data=routers, count=count)


@router.get("/{serial_number}", response_model=EdgeRouterPublic)
def read_remote_device(
    session: SessionDep, current_user: CurrentUser, serial_number: str
) -> Any:
    """
    Get EdgeRouter by serial number.
    Only superusers can view remote devices.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Only superusers can view remote devices"
        )

    router = crud.get_edge_router_by_serial(
        session=session, serial_number=serial_number
    )
    if not router:
        raise HTTPException(status_code=404, detail="Remote device not found")

    return router


@router.get("/{serial_number}/neighbors", response_model=NeighborDevicesPublic)
def read_neighbors(
    session: SessionDep, current_user: CurrentUser, serial_number: str
) -> Any:
    """
    Get all neighbors for a specific EdgeRouter.
    Only superusers can view neighbors.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Only superusers can view neighbors"
        )

    # Check if router exists
    router = crud.get_edge_router_by_serial(
        session=session, serial_number=serial_number
    )
    if not router:
        raise HTTPException(status_code=404, detail="Remote device not found")

    # Get neighbors
    neighbors = crud.get_neighbors_by_router(
        session=session, edge_router_serial=serial_number
    )

    return NeighborDevicesPublic(data=neighbors, count=len(neighbors))


@router.post("/{serial_number}/refresh", response_model=Message)
async def refresh_neighbors(
    session: SessionDep, current_user: CurrentUser, serial_number: str
) -> Any:
    """
    Refresh (re-discover) neighbors for a specific EdgeRouter.
    This will delete existing neighbors and discover new ones.
    Only superusers can refresh neighbors.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Only superusers can refresh neighbors"
        )

    # Get router
    router = crud.get_edge_router_by_serial(
        session=session, serial_number=serial_number
    )
    if not router:
        raise HTTPException(status_code=404, detail="Remote device not found")

    try:
        # Delete existing neighbors
        crud.delete_neighbors_by_router(
            session=session, edge_router_serial=serial_number
        )

        # Discover new neighbors (need to decrypt password or store it)
        # For now, we'll raise an error since we don't store plain password
        # You might want to ask for password again in the request
        raise HTTPException(
            status_code=501,
            detail="Refresh not implemented: Password decryption required",
        )

    except MikroTikAPIError as e:
        logger.error(f"Failed to refresh neighbors: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{serial_number}", response_model=EdgeRouterPublic)
def update_remote_device(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    serial_number: str,
    router_in: EdgeRouterUpdate,
) -> Any:
    """
    Update an EdgeRouter.
    Only superusers can update remote devices.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Only superusers can update remote devices"
        )

    router = crud.get_edge_router_by_serial(
        session=session, serial_number=serial_number
    )
    if not router:
        raise HTTPException(status_code=404, detail="Remote device not found")

    updated_router = crud.update_edge_router(
        session=session, db_router=router, router_in=router_in
    )
    return updated_router


@router.delete("/{serial_number}")
def delete_remote_device(
    session: SessionDep, current_user: CurrentUser, serial_number: str
) -> Message:
    """
    Delete an EdgeRouter (and all its neighbors via cascade).
    Only superusers can delete remote devices.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Only superusers can delete remote devices"
        )

    router = crud.get_edge_router_by_serial(
        session=session, serial_number=serial_number
    )
    if not router:
        raise HTTPException(status_code=404, detail="Remote device not found")

    crud.delete_edge_router(session=session, db_router=router)
    return Message(message="Remote device deleted successfully")
