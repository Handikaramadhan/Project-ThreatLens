from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse

from app.api.asset_routes import router as asset_router
from app.api.alert_routes import router as alert_router
from app.api.admin_routes import router as admin_router
from app.api.ai_routes import router as ai_router
from app.api.auth_routes import router as auth_router
from app.api.cve_routes import router as cve_router
from app.api.ioc_routes import router as ioc_router
from app.api.routes import router
from app.core.config import get_cors_origins, settings
from app.core.database import SessionLocal
from app.core.migrations import run_migrations
from app.models import entities  # noqa: F401
from app.services.auth import AuthContext, require_admin
from app.services.seed import cleanup_demo_records, seed_if_empty


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(asset_router, prefix="/api")
    app.include_router(alert_router, prefix="/api")
    app.include_router(admin_router, prefix="/api")
    app.include_router(ai_router, prefix="/api")
    app.include_router(auth_router, prefix="/api")
    app.include_router(cve_router, prefix="/api")
    app.include_router(ioc_router, prefix="/api")
    app.include_router(router, prefix="/api")

    @app.get("/api/openapi.json", include_in_schema=False)
    def protected_openapi(_: AuthContext = Depends(require_admin)) -> JSONResponse:
        return JSONResponse(
            get_openapi(
                title=app.title,
                version=app.version,
                routes=app.routes,
            )
        )

    @app.get("/api/docs", include_in_schema=False)
    def protected_docs(_: AuthContext = Depends(require_admin)) -> HTMLResponse:
        return get_swagger_ui_html(
            openapi_url="/api/openapi.json",
            title=f"{settings.app_name} API docs",
        )

    @app.on_event("startup")
    def startup() -> None:
        run_migrations()
        with SessionLocal() as db:
            if settings.seed_demo_data:
                seed_if_empty(db)
            else:
                cleanup_demo_records(db)

    return app


app = create_app()
