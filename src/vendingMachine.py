from fastapi import Body, FastAPI, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
import jwt
import logging
import bcrypt
import secrets
from src.models.credentials import TokenData
from src.models.deposit import Deposit
from src.models.product import Product
from src.models.purchase import Purchase
from src.models.user import User, UserInDB, UserRequest

app = FastAPI()

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Secret key to sign JWT tokens
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"

# Mock database for users and products
users_db = {
    "seller1": {"username": "seller1", "password": "password", "role": "seller"},
    "buyer1": {"username": "buyer1", "password": "password", "role": "buyer"},
}
user_balances_db = {"buyer1": 0, "buyer2": 0}
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
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials 2",
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
@app.post("/users/", response_model=UserRequest)
async def create_user(userRequest: UserRequest):
    # Validate input
    if not userRequest.username or not userRequest.role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and role are required.",
        )
    if userRequest.role not in ["seller", "buyer"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be 'seller' or 'buyer'.",
        )
    if userRequest.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists."
        )

    # Add user to database
    users_db[userRequest.username] = {
        "username": userRequest.username,
        "role": userRequest.role,
        "hashed_password": hash_password(userRequest.password),
    }

    # Log user creation
    logger.info(f"User '{userRequest.username}' created with role '{userRequest.role}'.")

    return userRequest


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    # Check if the current user exists in the database
    if current_user.username not in users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Return only the username and role of the current user
    return {"status": "ok"}


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

    if products_db[product_id].seller != current_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User deleting the product isn't the owner",
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

    if products_db[product_id].seller != current_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User updating the product isn't the owner",
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


@app.post("/deposit/")
async def deposit_coins(
    deposit: Deposit, current_user: User = Depends(get_current_user)
):
    # Validate user role
    if current_user.role != "buyer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    # Validate deposit amount
    if deposit.amount not in [5, 10, 20, 50, 100]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid deposit amount. Must be 5, 10, 20, 50, or 100 cents.",
        )

    # Update user's balance in the database
    if current_user.username not in user_balances_db:
        user_balances_db[current_user.username] = deposit.amount
    else:
        user_balances_db[current_user.username] += deposit.amount

    # Log the deposit action
    logger.info(f"User '{current_user.username}' deposited {deposit.amount} cents.")

    # Return success message
    return {"message": "Deposit successful"}


@app.post("/buy/")
async def buy_products(
    purchase: Purchase, current_user: User = Depends(get_current_user)
):
    # Validate user role
    if current_user.role != "buyer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    # Get product details from the database
    product = products_db.get(purchase.product_id)
    if product is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Product not found"
        )

    # Calculate total cost of purchase
    total_cost = product.price * purchase.amount

    # Check if user has sufficient balance
    if (
        current_user.username not in user_balances_db
        or user_balances_db[current_user.username] < total_cost
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient balance"
        )

    # Deduct total cost from user's balance
    user_balances_db[current_user.username] -= total_cost

    # Log the purchase action
    logger.info(
        f"User '{current_user.username}' bought {purchase.amount} of product '{product.name}'"
    )

    # Calculate change
    change = user_balances_db[current_user.username]

    # Return purchase details along with change
    return {
        "total_spent": total_cost,
        "products_purchased": f"{purchase.amount} of {product.name}",
        "change": change,
    }


# Reset endpoint
@app.post("/reset/")
async def reset_deposit(current_user: User = Depends(get_current_user)):
    # Validate user role
    if current_user.role != "buyer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    # Reset user's balance to zero
    user_balances_db[current_user.username] = 0

    # Log the reset action
    logger.info(f"User '{current_user.username}' reset their deposit.")

    # Return success message
    return {"message": "Deposit reset successful"}
