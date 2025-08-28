import os
import uuid
import time
import json
import redis
from datetime import datetime
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from typing import List

from .pubkey import PublicKey


# OAuth2 scheme used to retrieve the access token from the request
security = OAuth2PasswordBearer(tokenUrl="login")


class User:
    """
    Represents an authenticated user with permissions and wallet balance.
    """

    def __init__(
        self,
        uid: int,
        username: str,
        permissions: List[str],
        requested: str,
        wallet_balance: int,
    ):
        """
        Initialize a User object.

        Args:
            uid (int): Unique identifier for the user.
            username (str): Username of the authenticated user.
            permissions (List[str]): List of permission keys assigned to the user.
            requested (str): The permission key requested for the current action.
            wallet_balance (int): The user’s wallet balance.
        """
        self.uid = uid
        self.username = username
        self.permissions = permissions
        self.requested = requested
        self.wallet_balance = wallet_balance


class Authorization(PublicKey):
    """
    Handles user authorization, JWT decoding, permission validation,
    and event logging in Redis.
    """

    def __init__(self):
        """
        Initialize the Authorization class by loading permissions and Redis config.
        """
        super().__init__()
        self.permissions = self.conf("permission.json")
        self.redis = self.conf("redis.json")

    def permission_required(self):
        """
        FastAPI dependency that enforces authentication and permission validation.

        Returns:
            Depends: Dependency function wrapper for route protection.
        """

        def wrapper(request: Request, token: str = Depends(security)):
            # Ensure token exists
            if not token:
                raise HTTPException(
                    status_code=401,
                    detail="Missing token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Decode and validate the JWT token
            user = self.decode_jwt(token)

            # Validate user permissions for the current route and method
            user = self.permission_check(user, request.url.path, request.method)

            # Create event log for Redis
            event = {
                "service": self.redis["service_name"],
                "event_id": uuid.uuid4().hex,
                "user_id": user.uid,
                "permission": user.requested,
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "timestamp": int(time.time()),
            }

            # Store event in Redis
            self.redis_insert(event)

            return user

        return Depends(wrapper)

    def decode_jwt(self, token: str) -> User:
        """
        Decode and validate a JWT access token.

        Args:
            token (str): The JWT token string.

        Returns:
            User: A User object containing the decoded payload.

        Raises:
            HTTPException: If the token is invalid or expired.
        """
        try:
            payload = jwt.decode(
                token,
                self.pubkey,
                algorithms=["RS256"],
                audience="AUDIENCE",
                issuer="ISSUER",
            )

            # Extract user info from token
            uid: int = payload.get("ui")
            username: str = payload.get("sub")
            permissions: List[str] = payload.get("permissions", [])
            wallet_info: dict = payload.get("wallet_info")

            # Reject if no username found in token
            if username is None:
                raise HTTPException(
                    status_code=401,
                    detail="Credentials not verified!",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            return User(
                uid=uid,
                username=username,
                permissions=permissions,
                requested="",
                wallet_balance=wallet_info.get("amount"),
            )

        except JWTError as e:
            print(e.__str__())
            raise HTTPException(
                status_code=401,
                detail="Credentials not verified!",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def permission_check(self, user: User, current_path: str, method: str):
        """
        Check if the user has permission for the requested route and HTTP method.

        Args:
            user (User): The authenticated user.
            current_path (str): The route being accessed.
            method (str): The HTTP method (GET, POST, etc.).

        Returns:
            User: User with updated requested permission.

        Raises:
            HTTPException: If the user is unauthorized or has insufficient balance.
        """
        detail = "Forbidden (Unauthorized route)!"
        status_code = status.HTTP_403_FORBIDDEN

        # Iterate over user permissions
        for p in user.permissions:
            requested: dict = self.permissions.get(p)
            if requested:
                if requested.get("route") == current_path and requested.get("method") == method:
                    user.requested = p
                    # Check wallet balance before allowing action
                    if user.wallet_balance <= 0:
                        detail = "Insufficient amount!"
                        status_code = status.HTTP_406_NOT_ACCEPTABLE
                    return user

        raise HTTPException(status_code=status_code, detail=detail)

    def redis_insert(self, event: dict):
        """
        Store authorization events in Redis with expiration.

        Args:
            event (dict): Event data containing user and permission details.
        """
        client = redis.StrictRedis(
            host=self.redis["host"],
            port=self.redis["port"],
            db=self.redis["db"],
            username=self.redis["username"],
            password=self.redis["password"],
            decode_responses=True,
        )

        # Save event with expiration time
        client.setex(event["event_id"], self.redis["expire_sec"], json.dumps(event))
        client.close()

    @staticmethod
    def conf(file: str) -> dict:
        """
        Load configuration from a JSON file inside the `config` directory.

        Args:
            file (str): Filename of the config JSON.

        Returns:
            dict: Parsed JSON configuration.
        """
        with open(os.path.dirname(__file__) + f"/config/{file}") as file:
            return json.load(file)
