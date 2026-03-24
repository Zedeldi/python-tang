"""FastAPI app to provide HTTP REST API for Tang protocol."""

from pathlib import Path

from fastapi import FastAPI, HTTPException

from tang.models import JwkModel, JwsModel
from tang.services import Tang

app = FastAPI()
tang = Tang(Path("keys"))


@app.get("/adv/")
@app.get("/adv/{thumbprint}")
def advertise(thumbprint: str | None = None) -> JwsModel:
    """Advertise available public keys as JWS, optionally filtered by thumbprint."""
    keys = tang.advertise(thumbprint)
    if not keys:
        raise HTTPException(status_code=404, detail="Thumbprint not found")
    return keys


@app.post("/rec/{thumbprint}")
def recover(thumbprint: str, key: JwkModel) -> JwkModel:
    """Recover shared key by exchanging key with private key matching thumbprint."""
    result = tang.recover(thumbprint, key)
    if not result:
        raise HTTPException(status_code=404, detail="Thumbprint not found")
    return result
