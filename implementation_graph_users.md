# Graph User Activities — Implementation Walkthrough

## Changes Made

Replaced all 7 stub activities in [graph_users.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_users.py) with real Microsoft Graph API calls.

### New Helper
- **[_build_graph_client(secrets)](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_users.py#20-35)** — creates `ClientSecretCredential` + `GraphServiceClient` per call, returns both so the credential can be closed after use

### Implemented Activities

| Activity | Graph API Call | Key Details |
|---|---|---|
| [graph_get_user](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_users.py#39-66) | `GET /users/{email}` | Returns `None` on 404 for idempotency |
| [graph_create_user](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_users.py#68-109) | `POST /users` | Auto-generates temp password via `secrets.token_urlsafe(16)` |
| [graph_update_user](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_users.py#111-144) | `PATCH /users/{id}` | Maps dict keys (`jobTitle`→`job_title`) to SDK model |
| [graph_delete_user](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_users.py#146-165) | `PATCH /users/{id}` | Soft-delete: sets `account_enabled=False` |
| [graph_revoke_sessions](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_users.py#167-184) | `POST /users/{id}/revokeSignInSessions` | Security best practice for offboarding |
| [graph_assign_license](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_users.py#186-212) | `POST /users/{id}/assignLicense` | Uses `AssignLicensePostRequestBody` with `UUID(sku_id)` |
| [graph_reset_password](file:///c:/Users/ghost/Documents/codebases/secamo-poc/activities/graph_users.py#214-238) | `PATCH /users/{id}` | Sets `PasswordProfile` with `force_change_password_next_sign_in=True` |

### Error Handling
- All activities use `try/except APIError` with descriptive logging
- `finally` block calls `await credential.close()` to prevent resource leaks
- Failures re-raise for Temporal retry policy to handle

### Workflow Compatibility
Activity signatures and return types are **unchanged** — no modifications needed in [iam_onboarding.py](file:///c:/Users/ghost/Documents/codebases/secamo-poc/workflows/iam_onboarding.py).

## Verification Results

| Check | Result |
|---|---|
| `from activities.graph_users import *` | ✅ OK |
| `from workers.run_worker import *` | ✅ OK |
| `from workflows.iam_onboarding import IamOnboardingWorkflow` | ✅ OK |

```diff:graph_users.py
from temporalio import activity
from shared.models import UserData, GraphUser, TenantSecrets
from typing import Optional

@activity.defn
async def graph_get_user(tenant_id: str, email: str, secrets: TenantSecrets) -> Optional[GraphUser]:
    """
    Zoekt een gebruiker op in Entra ID via Graph API.
    Geeft None terug als de gebruiker niet bestaat (voor idempotency check).
    Later: GET /users/{email} via msgraph-sdk-python.
    """
    activity.logger.info(f"[{tenant_id}] Graph: opzoeken gebruiker '{email}'")

    # STUB: simuleer dat gebruiker nog niet bestaat
    return None

@activity.defn
async def graph_create_user(tenant_id: str, user_data: UserData, secrets: TenantSecrets) -> GraphUser:
    """
    Maakt een nieuwe gebruiker aan in Entra ID.
    Later: POST /users via msgraph-sdk-python.
    """
    activity.logger.info(f"[{tenant_id}] Graph: aanmaken gebruiker '{user_data.email}'")

    # STUB: simuleer succesvolle aanmaak
    return GraphUser(
        user_id="stub-user-id-12345",
        email=user_data.email,
        display_name=f"{user_data.first_name} {user_data.last_name}",
        account_enabled=True,
    )

@activity.defn
async def graph_update_user(tenant_id: str, user_id: str, updates: dict, secrets: TenantSecrets) -> bool:
    """
    Update gebruikerseigenschappen in Entra ID.
    Later: PATCH /users/{user_id}.
    """
    activity.logger.info(f"[{tenant_id}] Graph: updaten gebruiker '{user_id}' met {list(updates.keys())}")
    return True

@activity.defn
async def graph_delete_user(tenant_id: str, user_id: str, secrets: TenantSecrets) -> bool:
    """
    Soft delete: account wordt uitgeschakeld, niet permanent verwijderd.
    Later: PATCH /users/{user_id} met accountEnabled=false.
    """
    activity.logger.info(f"[{tenant_id}] Graph: uitschakelen gebruiker '{user_id}'")
    return True

@activity.defn
async def graph_revoke_sessions(tenant_id: str, user_id: str, secrets: TenantSecrets) -> bool:
    """
    Herroept alle actieve sessies van een gebruiker (security best practice bij delete).
    Later: POST /users/{user_id}/revokeSignInSessions.
    """
    activity.logger.info(f"[{tenant_id}] Graph: sessies herroepen voor gebruiker '{user_id}'")
    return True

@activity.defn
async def graph_assign_license(tenant_id: str, user_id: str, sku_id: str, secrets: TenantSecrets) -> bool:
    """
    Kent een M365-licentie toe aan de gebruiker.
    Later: POST /users/{user_id}/assignLicense.
    """
    activity.logger.info(f"[{tenant_id}] Graph: licentie '{sku_id}' toekennen aan '{user_id}'")
    return True

@activity.defn
async def graph_reset_password(tenant_id: str, user_id: str, temp_password: str, secrets: TenantSecrets) -> bool:
    """
    Dwingt een wachtwoordreset af.
    Later: PATCH /users/{user_id} met passwordProfile.
    """
    activity.logger.info(f"[{tenant_id}] Graph: wachtwoord resetten voor '{user_id}'")
    return True
===
import secrets as py_secrets
from uuid import UUID

from temporalio import activity
from kiota_abstractions.api_error import APIError
from azure.identity.aio import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.models.user import User
from msgraph.generated.models.password_profile import PasswordProfile
from msgraph.generated.models.assigned_license import AssignedLicense
from msgraph.generated.users.item.assign_license.assign_license_post_request_body import (
    AssignLicensePostRequestBody,
)

from shared.models import UserData, GraphUser, TenantSecrets
from typing import Optional


# ── Helper ────────────────────────────────────────────────────
def _build_graph_client(secrets: TenantSecrets) -> tuple[GraphServiceClient, ClientSecretCredential]:
    """
    Bouwt een GraphServiceClient op basis van tenant-specifieke credentials.
    Geeft ook de credential terug zodat deze na gebruik gesloten kan worden.
    """
    credential = ClientSecretCredential(
        tenant_id=secrets.tenant_azure_id,
        client_id=secrets.client_id,
        client_secret=secrets.client_secret,
    )
    client = GraphServiceClient(
        credentials=credential,
        scopes=["https://graph.microsoft.com/.default"],
    )
    return client, credential


# ── Activities ────────────────────────────────────────────────

@activity.defn
async def graph_get_user(tenant_id: str, email: str, secrets: TenantSecrets) -> Optional[GraphUser]:
    """
    Zoekt een gebruiker op in Entra ID via Graph API (GET /users/{email}).
    Geeft None terug als de gebruiker niet bestaat (idempotency check).
    """
    activity.logger.info(f"[{tenant_id}] Graph: opzoeken gebruiker '{email}'")

    client, credential = _build_graph_client(secrets)
    try:
        user = await client.users.by_user_id(email).get()
        if user:
            return GraphUser(
                user_id=user.id or "",
                email=user.user_principal_name or email,
                display_name=user.display_name or "",
                account_enabled=user.account_enabled or False,
            )
        return None
    except APIError as e:
        if e.response_status_code == 404:
            activity.logger.info(f"[{tenant_id}] Gebruiker '{email}' niet gevonden (404)")
            return None
        activity.logger.error(f"[{tenant_id}] Graph API fout bij opzoeken '{email}': {e.message}")
        raise
    finally:
        await credential.close()


@activity.defn
async def graph_create_user(tenant_id: str, user_data: UserData, secrets: TenantSecrets) -> GraphUser:
    """
    Maakt een nieuwe gebruiker aan in Entra ID (POST /users).
    Genereert een tijdelijk wachtwoord; gebruiker moet dit wijzigen bij eerste login.
    """
    activity.logger.info(f"[{tenant_id}] Graph: aanmaken gebruiker '{user_data.email}'")

    temp_password = py_secrets.token_urlsafe(16)
    mail_nickname = user_data.email.split("@")[0]

    request_body = User(
        account_enabled=True,
        display_name=f"{user_data.first_name} {user_data.last_name}",
        mail_nickname=mail_nickname,
        user_principal_name=user_data.email,
        password_profile=PasswordProfile(
            force_change_password_next_sign_in=True,
            password=temp_password,
        ),
        department=user_data.department,
        job_title=user_data.role,
    )

    client, credential = _build_graph_client(secrets)
    try:
        result = await client.users.post(request_body)
        if not result or not result.id:
            raise RuntimeError(f"Graph API gaf geen user ID terug voor '{user_data.email}'")

        return GraphUser(
            user_id=result.id,
            email=result.user_principal_name or user_data.email,
            display_name=result.display_name or f"{user_data.first_name} {user_data.last_name}",
            account_enabled=result.account_enabled or True,
        )
    except APIError as e:
        activity.logger.error(f"[{tenant_id}] Graph API fout bij aanmaken '{user_data.email}': {e.message}")
        raise
    finally:
        await credential.close()


@activity.defn
async def graph_update_user(tenant_id: str, user_id: str, updates: dict, secrets: TenantSecrets) -> bool:
    """
    Update gebruikerseigenschappen in Entra ID (PATCH /users/{user_id}).
    Ondersteunde keys: department, jobTitle, displayName, officeLocation.
    """
    activity.logger.info(f"[{tenant_id}] Graph: updaten gebruiker '{user_id}' met {list(updates.keys())}")

    # Map workflow dict-keys naar User model attributen
    FIELD_MAP = {
        "department": "department",
        "jobTitle": "job_title",
        "displayName": "display_name",
        "officeLocation": "office_location",
        "mobilePhone": "mobile_phone",
    }

    kwargs = {}
    for key, value in updates.items():
        attr_name = FIELD_MAP.get(key, key)
        kwargs[attr_name] = value

    request_body = User(**kwargs)

    client, credential = _build_graph_client(secrets)
    try:
        await client.users.by_user_id(user_id).patch(request_body)
        return True
    except APIError as e:
        activity.logger.error(f"[{tenant_id}] Graph API fout bij updaten '{user_id}': {e.message}")
        raise
    finally:
        await credential.close()


@activity.defn
async def graph_delete_user(tenant_id: str, user_id: str, secrets: TenantSecrets) -> bool:
    """
    Soft delete: schakelt het account uit in Entra ID (PATCH /users/{user_id}).
    Het account wordt NIET permanent verwijderd.
    """
    activity.logger.info(f"[{tenant_id}] Graph: uitschakelen gebruiker '{user_id}'")

    request_body = User(account_enabled=False)

    client, credential = _build_graph_client(secrets)
    try:
        await client.users.by_user_id(user_id).patch(request_body)
        return True
    except APIError as e:
        activity.logger.error(f"[{tenant_id}] Graph API fout bij uitschakelen '{user_id}': {e.message}")
        raise
    finally:
        await credential.close()


@activity.defn
async def graph_revoke_sessions(tenant_id: str, user_id: str, secrets: TenantSecrets) -> bool:
    """
    Herroept alle actieve sessies van een gebruiker (POST /users/{user_id}/revokeSignInSessions).
    Security best practice bij offboarding.
    """
    activity.logger.info(f"[{tenant_id}] Graph: sessies herroepen voor gebruiker '{user_id}'")

    client, credential = _build_graph_client(secrets)
    try:
        result = await client.users.by_user_id(user_id).revoke_sign_in_sessions.post()
        return bool(result and result.value)
    except APIError as e:
        activity.logger.error(f"[{tenant_id}] Graph API fout bij sessies herroepen '{user_id}': {e.message}")
        raise
    finally:
        await credential.close()


@activity.defn
async def graph_assign_license(tenant_id: str, user_id: str, sku_id: str, secrets: TenantSecrets) -> bool:
    """
    Kent een M365-licentie toe aan de gebruiker (POST /users/{user_id}/assignLicense).
    """
    activity.logger.info(f"[{tenant_id}] Graph: licentie '{sku_id}' toekennen aan '{user_id}'")

    request_body = AssignLicensePostRequestBody(
        add_licenses=[
            AssignedLicense(
                disabled_plans=[],
                sku_id=UUID(sku_id),
            ),
        ],
        remove_licenses=[],
    )

    client, credential = _build_graph_client(secrets)
    try:
        await client.users.by_user_id(user_id).assign_license.post(request_body)
        return True
    except APIError as e:
        activity.logger.error(f"[{tenant_id}] Graph API fout bij licentie toekennen '{user_id}': {e.message}")
        raise
    finally:
        await credential.close()


@activity.defn
async def graph_reset_password(tenant_id: str, user_id: str, temp_password: str, secrets: TenantSecrets) -> bool:
    """
    Dwingt een wachtwoordreset af (PATCH /users/{user_id} met passwordProfile).
    Gebruiker moet het wachtwoord wijzigen bij volgende aanmelding.
    """
    activity.logger.info(f"[{tenant_id}] Graph: wachtwoord resetten voor '{user_id}'")

    request_body = User(
        password_profile=PasswordProfile(
            force_change_password_next_sign_in=True,
            password=temp_password,
        ),
    )

    client, credential = _build_graph_client(secrets)
    try:
        await client.users.by_user_id(user_id).patch(request_body)
        return True
    except APIError as e:
        activity.logger.error(f"[{tenant_id}] Graph API fout bij wachtwoord reset '{user_id}': {e.message}")
        raise
    finally:
        await credential.close()

```
