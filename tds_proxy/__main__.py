#!/usr/bin/env python3
"""
TDS Proxy Main Entry Point
==========================

Run the TDS proxy server from command line.

Usage:
    python -m tds_proxy --config config.yaml
    python -m tds_proxy --host 0.0.0.0 --port 5000 --backend ase:hostname:5000

Examples:
    # Start with config file
    tds-proxy -c proxy.yaml

    # Start with command line args
    tds-proxy --port 5000 --backend primary:db.example.com:5000

    # Generate sample config
    tds-proxy generate-config > proxy.yaml
"""

import asyncio
import logging
import signal
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer

from tds_proxy.backend import BackendConfig, DatabaseType
from tds_proxy.config import create_sample_config, load_config_with_env
from tds_proxy.proxy import ProxyConfig, ProxyMode, TDSProxy

app = typer.Typer(
    name="tds-proxy",
    help="TDS Protocol Proxy for SAP ASE and IQ databases",
    add_completion=False,
)


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class Mode(str, Enum):
    transparent = "transparent"
    intercept = "intercept"
    multiplex = "multiplex"


def setup_logging(level: str = "INFO"):
    """Configure logging"""
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Reduce noise from asyncio
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def parse_backend_arg(backend_str: str) -> tuple:
    """Parse backend argument string: name:host:port[:type]"""
    parts = backend_str.split(":")

    if len(parts) < 3:
        raise typer.BadParameter(
            f"Invalid backend format: {backend_str}. Expected: name:host:port[:type]"
        )

    name = parts[0]
    host = parts[1]
    try:
        port = int(parts[2])
    except ValueError:
        raise typer.BadParameter(f"Invalid port number: {parts[2]}")
    db_type = parts[3] if len(parts) > 3 else "ase"

    return name, host, port, db_type


def build_config(
    host: str,
    port: int,
    server_name: str,
    backends: Optional[list[str]],
    default_backend: Optional[str],
    mode: Mode,
    log_queries: bool,
    log_level: LogLevel,
) -> ProxyConfig:
    """Build ProxyConfig from command line arguments"""
    backend_configs = {}

    if backends:
        for backend_str in backends:
            name, bhost, bport, db_type = parse_backend_arg(backend_str)
            backend_configs[name] = BackendConfig(
                name=name,
                host=bhost,
                port=bport,
                database_type=DatabaseType(db_type),
            )

    resolved_default = default_backend
    if not resolved_default and backend_configs:
        resolved_default = list(backend_configs.keys())[0]

    return ProxyConfig(
        listen_host=host,
        listen_port=port,
        backends=backend_configs,
        default_backend=resolved_default or "",
        mode=ProxyMode(mode.value),
        server_name=server_name,
        log_queries=log_queries,
        log_level=log_level.value,
    )


async def run_proxy(config: ProxyConfig):
    """Run the proxy server with graceful shutdown"""
    proxy = TDSProxy(config)

    # Setup signal handlers (Unix only)
    if sys.platform != "win32":
        loop = asyncio.get_running_loop()

        def shutdown_handler():
            logging.info("Shutdown signal received")
            asyncio.create_task(proxy.stop())

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, shutdown_handler)

    try:
        await proxy.start()
    except asyncio.CancelledError:
        pass
    finally:
        await proxy.stop()


def version_callback(value: bool):
    if value:
        typer.echo("TDS Proxy 1.0.0")
        raise typer.Exit()


@app.command("generate-config")
def generate_config():
    """Generate a sample configuration file."""
    typer.echo(create_sample_config())


@app.command("run")
def run(
    config: Annotated[
        Optional[Path],
        typer.Option(
            "-c",
            "--config",
            help="Path to YAML configuration file",
            exists=True,
            readable=True,
        ),
    ] = None,
    host: Annotated[
        str,
        typer.Option("-H", "--host", help="Listen address"),
    ] = "0.0.0.0",
    port: Annotated[
        int,
        typer.Option("-p", "--port", help="Listen port"),
    ] = 5000,
    server_name: Annotated[
        str,
        typer.Option("-n", "--server-name", help="Server name to report to clients"),
    ] = "TDS_Proxy",
    backend: Annotated[
        Optional[list[str]],
        typer.Option(
            "-b",
            "--backend",
            help="Backend server in format name:host:port[:type] (can specify multiple)",
        ),
    ] = None,
    default_backend: Annotated[
        Optional[str],
        typer.Option("-d", "--default-backend", help="Default backend name"),
    ] = None,
    mode: Annotated[
        Mode,
        typer.Option("-m", "--mode", help="Proxy mode"),
    ] = Mode.transparent,
    log_queries: Annotated[
        bool,
        typer.Option("-q", "--log-queries", help="Log all SQL queries"),
    ] = False,
    log_level: Annotated[
        LogLevel,
        typer.Option("-l", "--log-level", help="Logging level"),
    ] = LogLevel.INFO,
):
    """Run the TDS proxy server."""
    setup_logging(log_level.value)
    logger = logging.getLogger(__name__)

    # Load or build configuration
    if config:
        try:
            proxy_config = load_config_with_env(str(config))
            logger.info(f"Loaded configuration from {config}")
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise typer.Exit(1)
    else:
        proxy_config = build_config(
            host=host,
            port=port,
            server_name=server_name,
            backends=backend,
            default_backend=default_backend,
            mode=mode,
            log_queries=log_queries,
            log_level=log_level,
        )

    # Validate configuration
    if not proxy_config.backends:
        logger.error("No backend servers configured. Use --backend or --config.")
        raise typer.Exit(1)

    # Log configuration
    logger.info(f"Starting TDS Proxy on {proxy_config.listen_host}:{proxy_config.listen_port}")
    logger.info(f"Backends: {list(proxy_config.backends.keys())}")
    logger.info(f"Default backend: {proxy_config.default_backend}")
    logger.info(f"Mode: {proxy_config.mode.value}")

    # Run proxy
    try:
        asyncio.run(run_proxy(proxy_config))
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.error(f"Proxy error: {e}", exc_info=True)
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option("-v", "--version", callback=version_callback, is_eager=True, help="Show version"),
    ] = False,
):
    """TDS Protocol Proxy for SAP ASE and IQ databases."""
    if ctx.invoked_subcommand is None:
        # Default to run command with no args shows help
        typer.echo(ctx.get_help())


if __name__ == "__main__":
    app()
