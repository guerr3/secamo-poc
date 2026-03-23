"""Authentication package for ingress validation architecture.

Responsibility: expose reusable auth contracts, resolver utilities, registry behavior, and validators.
This package must not contain workflow logic, route selection logic, or activity execution code.
"""

from .contracts import AuthValidationRequest, AuthValidationResult, ResolverContext
from .registry import AuthValidatorRegistry, build_default_validator_registry
from .secrets import CachedSecretResolver

__all__ = [
    "AuthValidationRequest",
    "AuthValidationResult",
    "AuthValidatorRegistry",
    "CachedSecretResolver",
    "ResolverContext",
    "build_default_validator_registry",
]
