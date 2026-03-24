"""FastAPI app to provide HTTP REST API for Tang protocol."""

from fastapi import FastAPI, HTTPException

from tang.config import JWK_PATH
from tang.models import JwkModel, JwsModel, JwsMultiModel
from tang.services import Tang

app = FastAPI()
tang = Tang(path=JWK_PATH)


@app.get("/adv/")
@app.get("/adv/{thumbprint}")
def advertise(thumbprint: str | None = None) -> JwsModel | JwsMultiModel:
    """
    Advertise available public keys as JWS.

    If thumbprint is specified, add signature using matching key.
    """
    keys = tang.advertise(thumbprint)
    if not keys:
        raise HTTPException(status_code=404, detail="Signing key not found")
    return keys


@app.post("/rec/{thumbprint}")
def recover(thumbprint: str, key: JwkModel) -> JwkModel:
    """Recover shared key by exchanging key with private key matching thumbprint."""
    result = tang.recover(thumbprint, key)
    if not result:
        raise HTTPException(status_code=404, detail="Exchange key not found")
    return result
