# Shared - cross-cutting contracts, routing, auth, and runtime helpers

> This module provides the shared types and infrastructure-facing helpers used by ingress, workflows, activities, and tests.

## Responsibilities

- Define shared runtime configuration, model contracts, and normalization/routing boundaries.
- Provide ingress/auth abstractions and validator wiring used by Lambda ingress paths.
- Provide tenant/bootstrap helper utilities used by workflows and activities.
- Host provider factory and protocol interfaces for AI and ChatOps integration.

## File Reference

| File                  | Responsibility                                                     |
| --------------------- | ------------------------------------------------------------------ |
| `__init__.py`         | Shared package marker.                                             |
| `approval/`           | Approval contracts, callback normalization, and token store logic. |
| `auth/`               | Auth contracts, registry, secret resolution, and validators.       |
| `config.py`           | Runtime constants (Temporal settings, queue names, and defaults).  |
| `graph_client.py`     | Graph token acquisition and token cache handling.                  |
| `ingress/`            | Ingress pipeline contracts and error definitions.                  |
| `models/`             | Pydantic model contracts and mapping helpers.                      |
| `normalization/`      | Canonical-to-intent normalization contracts and implementations.   |
| `providers/`          | Provider protocol interfaces and concrete AI/ChatOps providers.    |
| `README.md`           | Module documentation.                                              |
| `routing/`            | Route contracts, route registry, and default route mappings.       |
| `ssm_client.py`       | SSM helper methods for tenant-scoped parameter retrieval.          |
| `temporal/`           | Temporal dispatch/signal abstraction helpers.                      |
| `workflow_helpers.py` | Shared helper routines used by workflow bootstrap logic.           |
| `__pycache__/`        | Generated Python bytecode cache directory.                         |

## Key Concepts

- Contract-first boundaries: ingress, workflow, and activity layers exchange typed models to keep replay and serialization behavior stable.
- Route registry abstraction: workflow dispatch routes are centrally defined and reused across ingress handlers.
- Shared auth validation: channel/provider auth checks are routed through a registry to prevent duplicated security logic in handlers.

## Usage

Other modules import shared contracts and helpers instead of re-defining cross-cutting logic.

```python
from shared.config import QUEUE_SOC
from shared.routing.defaults import build_default_route_registry
from shared.models import SecurityEvent
```

## Testing

```bash
python -m pytest -q tests/test_models.py tests/test_graph_client.py tests/test_ingress_mappers.py
```

## Extension Points

1. Add new shared contracts under the relevant `shared/*` subpackage.
2. Keep naming and typing consistent with existing Pydantic model conventions.
3. For new dispatch behavior, update `shared/routing/defaults.py` and related contracts.
4. Add tests under `tests/` that validate compatibility across callers.
5. Update this file table when top-level module contents change.
