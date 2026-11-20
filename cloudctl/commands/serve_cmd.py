"""cctl serve — run the control plane as an HTTP service (see docs/service.md)."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape

console = Console()


def serve(
    config: Optional[str] = typer.Option(None, "--config", help="Service settings (default: "
                                                                 "$CLOUDCTL_SERVICE_CONFIG or /etc/cctl/service.yaml)."),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address. 0.0.0.0 only inside a container."),
    port: int = typer.Option(8080, "--port"),
    trusted_proxies: str = typer.Option("127.0.0.1", "--trusted-proxies",
                                        help="Comma-separated IPs/CIDRs whose X-Forwarded-* headers are trusted."),
) -> None:
    """Run the control-plane API (requires the [service] extra)."""
    try:
        import uvicorn  # noqa: PLC0415
    except ImportError:
        console.print('[red]Install the service extra: pip install "cctl[service]"[/red]')
        raise typer.Exit(1) from None
    from cloudctl.gate.models import ConfigError  # noqa: PLC0415
    from cloudctl.service.app import create_app  # noqa: PLC0415
    from cloudctl.service.settings import build_context, load_settings  # noqa: PLC0415
    try:
        ctx = build_context(load_settings(config))
    except (ConfigError, ValueError, KeyError) as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1) from None
    uvicorn.run(create_app(ctx), host=host, port=port, proxy_headers=True, forwarded_allow_ips=trusted_proxies,
                server_header=False, date_header=False, log_level="info", access_log=True)
