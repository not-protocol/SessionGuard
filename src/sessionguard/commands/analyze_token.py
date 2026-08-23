"""`sessionguard analyze-token` — inspect a JWT's structure without
verifying its signature (we usually won't have the secret/key to verify
with — the point here is spotting risky structure, not validating auth)."""
import base64
import json
import time

import click


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _decode_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a 3-part JWT (header.payload.signature)")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload


@click.command()
@click.argument("token_or_file")
def analyze_token(token_or_file: str):
    """Decode and inspect a JWT's header/payload (signature is NOT verified).

    Pass a raw token string, or a path to a file containing one.
    """
    try:
        with open(token_or_file, "r") as f:
            token = f.read().strip()
    except OSError:
        token = token_or_file.strip()

    try:
        header, payload = _decode_jwt(token)
    except Exception as exc:
        click.echo(f"Could not parse token: {exc}", err=True)
        raise SystemExit(1)

    click.echo("Header:")
    click.echo(json.dumps(header, indent=2))
    click.echo("\nPayload:")
    click.echo(json.dumps(payload, indent=2))

    click.echo("\nFindings:")
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        click.echo("  [FAIL] alg=none — token requires no signature at all")
    elif alg.startswith("hs"):
        click.echo(f"  [INFO] alg={header.get('alg')} — symmetric signing (shared secret)")

    exp = payload.get("exp")
    if exp is None:
        click.echo("  [WARN] No 'exp' claim — token never expires")
    else:
        remaining = exp - time.time()
        if remaining < 0:
            click.echo(f"  [INFO] Token expired {-remaining:.0f}s ago")
        else:
            click.echo(f"  [INFO] Token expires in {remaining:.0f}s")
