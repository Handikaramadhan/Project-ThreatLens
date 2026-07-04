from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.asset_routes import router as asset_router
from app.api.ai_routes import router as ai_router
from app.api.auth_routes import router as auth_router
from app.api.cve_routes import router as cve_router
from app.api.ioc_routes import router as ioc_router
from app.api.routes import router
from app.core.config import get_cors_origins, settings
from app.core.database import Base, SessionLocal, engine
from app.models import entities  # noqa: F401
from app.services.seed import seed_if_empty


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(asset_router, prefix="/api")
    app.include_router(ai_router, prefix="/api")
    app.include_router(auth_router, prefix="/api")
    app.include_router(cve_router, prefix="/api")
    app.include_router(ioc_router, prefix="/api")
    app.include_router(router, prefix="/api")

    @app.on_event("startup")
    def startup() -> None:
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            seed_if_empty(db)

    return app


app = create_app()
