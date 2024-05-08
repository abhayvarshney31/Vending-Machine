from pydantic import BaseModel


class Deposit(BaseModel):
    amount: int
