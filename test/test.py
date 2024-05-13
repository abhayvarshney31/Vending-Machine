import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.models.product import Product
from src.models.user import User
from src.vendingMachine import app, hash_password


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
def test_seller():
    return User(username="test_seller", role="seller")


@pytest.fixture
def test_product():
    return Product(id=1, name="Test Product", price=10, quantity=100, seller="test_seller")


@pytest.mark.asyncio
async def test_create_user(test_client: TestClient, test_user: User, test_password):
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
async def test_create_user_invalid_role(
    test_client: TestClient, test_user: User, test_password
):
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
async def test_read_users_me(test_client: TestClient, test_user: User, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_user.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_user.username: {
                "username": test_user.username,
                "password": hash_password(password),
                "role": test_user.role,
            }
        },
    )

    response = test_client.get(
        "/users/me/",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {password}"},
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["username"] == test_user.username


@pytest.mark.asyncio
async def test_create_product(test_client, test_seller, test_product, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_seller.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_seller.username: {
                "username": test_seller.username,
                "password": hash_password(password),
                "role": test_seller.role,
            }
        },
    )

    response = test_client.post(
        "/products/",
        json=test_product.dict(),
        headers={"Authorization": f"Bearer {password}"},
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == test_product.name


@pytest.mark.asyncio
async def test_read_product_as_user(test_client, test_user, test_product, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_user.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_user.username: {
                "username": test_user.username,
                "password": hash_password(password),
                "role": test_user.role,
            }
        },
    )

    response = test_client.get("/products/1", headers={"Authorization": f"Bearer {password}"})
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == test_product.id


@pytest.mark.asyncio
async def test_read_product_as_seller(test_client, test_seller, test_product, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_seller.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_seller.username: {
                "username": test_seller.username,
                "password": hash_password(password),
                "role": test_seller.role,
            }
        },
    )

    response = test_client.get("/products/1", headers={"Authorization": f"Bearer {password}"})
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
async def test_create_user_missing_fields(test_client, test_user):
    user_data = test_user.dict()
    response = test_client.post(
        "/users/",
        headers={"Content-Type": "application/json"},
        json=user_data,
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
async def test_read_users_me_invalid_token(test_client, test_user, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    mock_jwt.decode.return_value = {"invalid": test_user.username}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_user.username: {
                "username": test_user.username,
                "password": "password",
                "role": test_user.role,
            }
        },
    )
    response = test_client.get(
        "/users/me/", headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_create_product_invalid_price(test_client, test_seller, test_product, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_seller.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_seller.username: {
                "username": test_seller.username,
                "password": hash_password(password),
                "role": test_seller.role,
            }
        },
    )

    test_product.price = -1
    response = test_client.post(
        "/products/",
        json=test_product.dict(),
        headers={"Authorization": f"Bearer {password}"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_create_product_invalid_quantity(test_client, test_seller, test_product, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_seller.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_seller.username: {
                "username": test_seller.username,
                "password": hash_password(password),
                "role": test_seller.role,
            }
        },
    )

    test_product.quantity = -1
    response = test_client.post(
        "/products/",
        json=test_product.dict(),
        headers={"Authorization": f"Bearer {password}"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_read_product_not_found(test_client, test_seller, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_seller.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_seller.username: {
                "username": test_seller.username,
                "password": hash_password(password),
                "role": test_seller.role,
            }
        },
    )

    response = test_client.get(
        "/products/999", headers={"Authorization": f"Bearer {password}"}
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_update_product_invalid_name(test_client, test_seller, test_product, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_seller.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_seller.username: {
                "username": test_seller.username,
                "password": hash_password(password),
                "role": test_seller.role,
            }
        },
    )

    test_product.name = ""
    response = test_client.put(
        "/products/1",
        json=test_product.dict(),
        headers={"Authorization": f"Bearer {password}"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_update_product_invalid_price(test_client, test_seller, test_product, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_seller.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_seller.username: {
                "username": test_seller.username,
                "password": hash_password(password),
                "role": test_seller.role,
            }
        },
    )

    test_product.price = -1
    response = test_client.put(
        "/products/1",
        json=test_product.dict(),
        headers={"Authorization": f"Bearer {password}"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_update_product_invalid_quantity(test_client, test_seller, test_product, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_seller.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_seller.username: {
                "username": test_seller.username,
                "password": hash_password(password),
                "role": test_seller.role,
            }
        },
    )

    test_product.quantity = -1
    response = test_client.put(
        "/products/1",
        json=test_product.dict(),
        headers={"Authorization": f"Bearer {password}"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_delete_product_not_found(test_client, test_seller, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_seller.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_seller.username: {
                "username": test_seller.username,
                "password": hash_password(password),
                "role": test_seller.role,
            }
        },
    )
    response = test_client.delete(
        "/products/999", 
        headers={"Authorization": f"Bearer {password}"},
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND

@pytest.mark.asyncio
async def test_delete_product(test_client, test_seller, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_seller.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_seller.username: {
                "username": test_seller.username,
                "password": hash_password(password),
                "role": test_seller.role,
            }
        },
    )
    mocker.patch(
        "src.vendingMachine.products_db",
        {
            999: {
                "id": 999,
                "name": "product",
                "price": 100,
                "quantity": 1,
                "seller": test_seller.username
            }
        },
    )
    response = test_client.delete(
        "/products/999", headers={"Authorization": f"Bearer {password}"}
    )
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_deposit_invalid_amount(test_client, test_user, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_user.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_user.username: {
                "username": test_user.username,
                "password": hash_password(password),
                "role": test_user.role,
            }
        },
    )
    mocker.patch(
        "src.vendingMachine.user_balances_db",
        {
            test_user.username: 0
        },
    )

    response = test_client.post(
        "/deposit/", json={"amount": 7}, headers={"Authorization": f"Bearer {password}"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_deposit_invalid_user(test_client, test_user, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    mock_jwt.decode.return_value = {"sub": test_user.username}
    mocker.patch(
        "src.vendingMachine.user_balances_db",
        {
            test_user.username: 0
        },
    )
    response = test_client.post(
        "/deposit/",
        json={"amount": 10},
        headers={"Authorization": "Bearer invalid_token"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_buy_sufficient_balance(test_client, test_user, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_user.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_user.username: {
                "username": test_user.username,
                "password": hash_password(password),
                "role": test_user.role,
            }
        },
    )
    mocker.patch(
        "src.vendingMachine.user_balances_db",
        {
            test_user.username: 10
        },
    )
    response = test_client.post(
        "/buy/",
        json={"product_id": 1, "amount": 1},
        headers={"Authorization": f"Bearer {password}"},
    )
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_buy_insufficient_balance(test_client, test_user, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_user.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_user.username: {
                "username": test_user.username,
                "password": hash_password(password),
                "role": test_user.role,
            }
        },
    )
    mocker.patch(
        "src.vendingMachine.user_balances_db",
        {
            test_user.username: 0
        },
    )
    response = test_client.post(
        "/buy/",
        json={"product_id": 1, "amount": 1},
        headers={"Authorization": f"Bearer {password}"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_reset_deposit_invalid_user(test_client, test_user, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_user.username, "password": "invalid_token"}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_user.username: {
                "username": test_user.username,
                "password": hash_password(password),
                "role": test_user.role,
            }
        },
    )
    response = test_client.post(
        "/reset/", headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED



@pytest.mark.asyncio
async def test_reset_deposit(test_client, test_user, mocker):
    mock_jwt = mocker.patch("src.vendingMachine.jwt")
    password = "password"
    mock_jwt.decode.return_value = {"sub": test_user.username, "password": password}
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_user.username: {
                "username": test_user.username,
                "password": hash_password(password),
                "role": test_user.role,
            }
        },
    )
    response = test_client.post(
        "/reset/", headers={"Authorization": f"Bearer {password}"}
    )
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_login(test_client, test_user, mocker):
    password = "password"
    mocker.patch(
        "src.vendingMachine.users_db",
        {
            test_user.username: {
                "username": test_user.username,
                "hashed_password": hash_password(password),
                "role": test_user.role,
            }
        },
    )
    response = test_client.post("/login/", data={"username": test_user.username, "password": password})
    assert response.status_code == status.HTTP_200_OK