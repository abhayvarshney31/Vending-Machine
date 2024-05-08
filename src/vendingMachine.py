from fastapi import Body, FastAPI, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
import jwt
import logging
import bcrypt
from credentials import TokenData
from models import Deposit, User, Product, Purchase
from models.user import UserInDB

app = FastAPI()
# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Secret key to sign JWT tokens
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

# Mock database for users and products
users_db = {
    "seller1": {"username": "seller1", "password": "password", "role": "seller"},
    "buyer1": {"username": "buyer1", "password": "password", "role": "buyer"},
}
products_db = {}

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(username: str):
    if username in users_db:
        user_dict = users_db[username]
        return UserInDB(**user_dict)


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


# Token functions
def create_access_token(data: dict):
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
        token_data = TokenData(username=username)
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    return token_data


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.role != "buyer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )
    return current_user


def hash_password(password: str) -> str:
    """
    Hashes the provided password using bcrypt.
    """
    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Return the hashed password as a string
    return hashed_password.decode("utf-8")


# CRUD for users
@app.post("/users/", response_model=User)
async def create_user(user: User, password: str = Body(...)):
    # Validate input
    if not user.username or not user.role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and role are required.",
        )
    if user.role not in ["seller", "buyer"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be 'seller' or 'buyer'.",
        )
    if user.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists."
        )

    # Add user to database
    users_db[user.username] = {
        "username": user.username,
        "role": user.role,
        "hashed_password": hash_password(password),
    }

    # Log user creation
    logger.info(f"User '{user.username}' created with role '{user.role}'.")

    return user


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    # Check if the current user exists in the database
    if current_user.username not in users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Return only the username and role of the current user
    return User(username=current_user.username, role=current_user.role)


@app.post("/products/", response_model=Product)
async def create_product(
    product: Product, current_user: User = Depends(get_current_user)
):
    # Check if the current user has the role of "seller"
    if current_user.role != "seller":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    # Validate input data
    if not product.name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Product name is required."
        )
    if product.price <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Product price must be greater than zero.",
        )
    if product.quantity < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Product quantity cannot be negative.",
        )
    # Here you can add additional validations as needed

    # Log product creation
    logger.info(f"User '{current_user.username}' created a product: {product.name}")

    # Your logic to create a product
    # For demonstration purposes, let's assume we add the product to the database
    products_db[product.id] = product

    return product


@app.get("/products/{product_id}", response_model=Product)
async def read_product(product_id: int, current_user: User = Depends(get_current_user)):
    # Validate product_id
    if product_id not in products_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Product not found"
        )

    # Log product read
    logger.info(f"User '{current_user.username}' read product with ID: {product_id}")

    # Your logic to read a product
    product = products_db[product_id]

    return product


@app.delete("/products/{product_id}", response_model=Product)
async def delete_product(
    product_id: int, current_user: User = Depends(get_current_user)
):
    # Validate user role
    if current_user.role != "seller":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    # Check if product exists
    if product_id not in products_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Product not found"
        )

    # Log the action
    logger.info(f"User '{current_user.username}' deleted product with ID: {product_id}")

    # Delete the product
    deleted_product = products_db.pop(product_id)

    return deleted_product


@app.put("/products/{product_id}", response_model=Product)
async def update_product(
    product_id: int, product: Product, current_user: User = Depends(get_current_user)
):
    # Validate user role
    if current_user.role != "seller":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    # Validate input data
    if not product.name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Product name is required."
        )
    if product.price <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Product price must be greater than zero.",
        )
    if product.quantity < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Product quantity cannot be negative.",
        )

    # Check if product exists
    if product_id not in products_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Product not found"
        )

    # Log the action
    logger.info(f"User '{current_user.username}' updated product with ID: {product_id}")

    # Update the product
    products_db[product_id] = product

    return product


@app.get("/seller-products/", response_model=List[Product])
async def read_seller_products(current_user: User = Depends(get_current_user)):
    # Validate user role
    if current_user.role != "seller":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    # Log the action
    logger.info(f"User '{current_user.username}' is retrieving seller's products")

    # Your logic to retrieve seller's products
    seller_products = [
        product
        for product in products_db.values()
        if product.seller == current_user.username
    ]

    return seller_products
