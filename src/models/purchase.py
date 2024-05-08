from pydantic import BaseModel


class Purchase(BaseModel):
    product_id: int
    amount: int
