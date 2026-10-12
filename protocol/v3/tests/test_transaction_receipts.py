import pytest
from dbp3.transaction import CommandTransaction
from dbp3.receipts import *
def test_transaction_expiry_and_digest():
    t=CommandTransaction('t1','i1','hold',100); assert t.validate(50).digest()
    with pytest.raises(ValueError): t.validate(101)
def test_receipt_chain():
    c=ReceiptChain(); a=Receipt('x',ReceiptStage.TRANSPORT_RECEIVED,'p'); c.append(a); b=Receipt('x',ReceiptStage.AUTHENTICATED,'p',a.receipt_id()); c.append(b); assert len(c.receipts)==2
