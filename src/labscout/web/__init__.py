"""Web UI for labscout: a React app (source in web/, built into static/) and its JSON API."""

from .server import ApiError, WebApp, build_argv, make_server, serve

__all__ = ["ApiError", "WebApp", "build_argv", "make_server", "serve"]
