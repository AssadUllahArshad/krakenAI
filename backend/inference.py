"""Minimal Ollama gateway for sandboxed Aider; never exposes pull, push or admin APIs."""
import hmac
import json

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response, StreamingResponse


def create_gateway(store, control, token):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.api_route('/api/{operation}', methods=['GET', 'POST'])
    async def forward(operation: str, request: Request):
        if not hmac.compare_digest(request.headers.get('authorization', ''), 'Bearer ' + token):
            raise HTTPException(401, 'Inference authorization required')
        control.check('coding', 'computer')
        if operation not in ('chat', 'generate', 'show', 'tags', 'version'):
            raise HTTPException(403, 'Inference-only gateway')
        raw = await request.body()
        if len(raw) > 2_000_000:
            raise HTTPException(413, 'Inference payload too large')
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            raise HTTPException(400, 'Inference payload must be valid JSON')
        if payload is not None and not isinstance(payload, dict):
            raise HTTPException(400, 'Inference payload must be a JSON object')
        if payload:
            selected = store.get('model', 'kraken')
            aliases = {selected, selected.removesuffix(':latest'), selected if ':' in selected else selected + ':latest'}
            if payload.get('model', selected) not in aliases:
                raise HTTPException(403, 'Only the configured local model is permitted')
            payload['model'] = selected
            if operation in ('chat', 'generate'):
                # Keep Aider's automatic +8192 context expansion within this Mac's budget.
                payload['think'] = False
                options = payload.get('options') or {}
                if not isinstance(options, dict):
                    raise HTTPException(400, 'Inference options must be an object')
                options['num_ctx'] = 4096
                options['num_predict'] = 2048
                payload['options'] = options
        client = httpx.AsyncClient(timeout=180, trust_env=False)
        try:
            upstream = await client.send(client.build_request(request.method, 'http://127.0.0.1:11434/api/' + operation, json=payload), stream=True)
        except Exception:
            await client.aclose()
            raise HTTPException(503, 'Local Ollama is unavailable')
        async def chunks():
            try:
                async for chunk in upstream.aiter_bytes():
                    control.check('coding', 'computer')
                    yield chunk
            finally:
                await upstream.aclose()
                await client.aclose()
        return StreamingResponse(chunks(), status_code=upstream.status_code,
                                 media_type=upstream.headers.get('content-type', 'application/json'))
    return app
