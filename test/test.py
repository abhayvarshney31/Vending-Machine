import json
import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.models.product import Product
from src.models.user import User
from src.vendingMachine import app


@pytest.fixture
def test_client():
    yield TestClient(app)


@pytest.fixture
def test_password():
    return "password"


@pytest.fixture
def test_user():
    return User(username="test_user", role="buyer")


@pytest.fixture
def test_product():
    return Product(id=1, name="Test Product", price=10, quantity=100, seller="seller1")


@pytest.mark.asyncio
async def test_create_user(test_client, test_user, test_password):
    user_data = test_user.dict()
    user_data["password"] = test_password  # Add password to the user data
    response = test_client.post(
        "/users/",
        headers={"Content-Type": "application/json"},
        json=user_data,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["username"] == test_user.username


@pytest.mark.asyncio
async def test_create_user_invalid_role(test_client, test_user, test_password):
    user_data = test_user.dict()
    user_data["password"] = test_password  # Add password to the user data
    user_data["role"] = "invalid_role"  # Set an invalid role
    response = test_client.post(
        "/users/",
        headers={"Content-Type": "application/json"},
        json=user_data,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_read_users_me(test_client, test_user):
    user_data = test_user.dict()
    user_data["password"] = test_password  # Add password to the user data
    response = test_client.post(
        "/users/",
        headers={"Content-Type": "application/json"},
        json=user_data,
    )
    response = test_client.get(
        "/users/me/", headers={"Authorization": "Bearer token"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["username"] == test_user.username


@pytest.mark.asyncio
async def test_create_product(test_client, test_product):
    response = test_client.post(
        "/products/",
        json=test_product.dict(),
        headers={"Authorization": "Bearer token"},
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == test_product.name


@pytest.mark.asyncio
async def test_read_product(test_client, test_product):
    response = test_client.get(
        "/products/1", headers={"Authorization": "Bearer token"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == test_product.id


@pytest.mark.asyncio
async def test_create_user_existing(test_client, test_user, test_password):
    user_data = test_user.dict()
    user_data["password"] = test_password  # Add password to the user data
    response = test_client.post(
        "/users/",
        headers={"Content-Type": "application/json"},
        json=user_data,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_create_user_missing_fields(test_client):
    response = test_client.post(
        "/users/", json={}, params={"password": "password"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_read_users_me_invalid_token(test_client):
    response = test_client.get(
        "/users/me/", headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_create_product_invalid_price(test_client, test_product):
    test_product.price = -1
    response = test_client.post(
        "/products/",
        json=test_product.dict(),
        headers={"Authorization": "Bearer token"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_create_product_invalid_quantity(test_client, test_product):
    test_product.quantity = -1
    response = test_client.post(
        "/products/",
        json=test_product.dict(),
        headers={"Authorization": "Bearer token"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_read_product_not_found(test_client):
    response = test_client.get(
        "/products/999", headers={"Authorization": "Bearer token"}
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_update_product_invalid_name(test_client, test_product):
    test_product.name = ""
    response = test_client.put(
        "/products/1",
        json=test_product.dict(),
        headers={"Authorization": "Bearer token"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_update_product_invalid_price(test_client, test_product):
    test_product.price = -1
    response = test_client.put(
        "/products/1",
        json=test_product.dict(),
        headers={"Authorization": "Bearer token"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_update_product_invalid_quantity(test_client, test_product):
    test_product.quantity = -1
    response = test_client.put(
        "/products/1",
        json=test_product.dict(),
        headers={"Authorization": "Bearer token"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_delete_product_not_found(test_client):
    response = test_client.delete(
        "/products/999", headers={"Authorization": "Bearer token"}
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_deposit_invalid_amount(test_client):
    response = test_client.post(
        "/deposit/", json={"amount": 7}, headers={"Authorization": "Bearer token"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_deposit_invalid_user(test_client):
    response = test_client.post(
        "/deposit/",
        json={"amount": 10},
        headers={"Authorization": "Bearer invalid_token"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_buy_insufficient_balance(test_client):
    response = test_client.post(
        "/buy/",
        json={"product_id": 1, "amount": 1},
        headers={"Authorization": "Bearer token"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_reset_deposit_invalid_user(test_client):
    response = test_client.post(
        "/reset/", headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
