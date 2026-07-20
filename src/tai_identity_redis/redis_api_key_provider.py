"""Redis-backed api-key identity provider.

Resolves an inbound api key to an identity and owns the whole api-key identity
record — the ``ac:key:{sha256(raw)}`` hash (key hash -> ``{user_id,
description}``) plus the ``user_id -> hash`` reverse lookup. Token validation is
the read side; provisioning/revocation/description edits are the write side, both
against the provider's OWN plain-Redis storage.

The provider registers itself as the ``"redis"`` identity provider in the
contract's module-level registry at import, with no app handle involved.
"""

from __future__ import annotations

import logging
import secrets
from typing import cast

from redis.exceptions import WatchError
from tai_contract.access_control import OWNER_USER_ID_CLAIM
from tai_contract.access_control.identity import (
    ApiKeyIdentityProvider,
    AuthIdentity,
    IdentityProviderSettings,
    ReadinessTarget,
)
from tai_contract.access_control.registry import register_identity_provider
from tai_kit.clients import RedisConnectionSettings, client_ctx
from tai_kit.clients.impl.redis import RedisClient, hgetall, hset_mapping, scan_iter
from tai_kit.utils.data.string_util import hash_api_key

logger = logging.getLogger(__name__)

# The ``user_id -> hashed-key`` reverse lookup. The provider owns the whole
# identity record: the ``ac:key:{hash}`` hash plus this reverse key, so a
# user id resolves to its stored hash for revoke/edit without a scan. Its value is
# the plain hash string, not the identity record itself.
_REVERSE_KEY_PREFIX = "ac:management:key:"

# Namespaced probe key the healthcheck reads. It never has to exist — ``HGETALL``
# on a missing key answers with an empty map on any plain Redis.
_PROBE_KEY = "ac:__identity_probe__"


class DuplicateIdentityError(ValueError):
    """``provision`` was called for a ``user_id`` that already has an identity
    record. A ``ValueError`` so the provisioning surface's existing duplicate
    handling catches it uniformly."""


def _generate_api_key() -> str:
    return f"sk-{secrets.token_urlsafe(32)}"


class RedisApiKeyProvider(ApiKeyIdentityProvider):
    """Validate and provision api keys against plain Redis hashes."""

    def __init__(self, settings: IdentityProviderSettings) -> None:
        self.settings = settings

    def _identity_key(self, hashed: str) -> str:
        return f"{self.settings.key_prefix}{hashed}"

    def _reverse_key(self, user_id: str) -> str:
        return f"{_REVERSE_KEY_PREFIX}{user_id}"

    def _redis_settings(self) -> RedisConnectionSettings:
        # tai-contract types ``settings.redis`` as ``Any`` (it cannot depend on
        # tai-kit to name ``RedisConnectionSettings``), and kit's ``client_ctx``
        # takes a NOMINAL settings param, so cast the structural value here — the
        # single spot the plugin bridges the contract Protocol to kit's client.
        return cast("RedisConnectionSettings", self.settings.redis)

    async def validate_token(self, token: str) -> AuthIdentity | None:
        hashed = hash_api_key(token)
        key = self._identity_key(hashed)

        # A genuine backend error must fail closed by RAISING, never by returning
        # ``None`` (which the backend would treat as a simply-invalid credential):
        # the error is logged at source for operator visibility and then
        # propagates so the auth decision fails closed loudly. A successful read
        # with no stored identity returns ``None`` (legitimately-unknown token).
        # ``HGETALL`` on a missing key answers with an empty map.
        try:
            async with client_ctx(RedisClient, self._redis_settings()) as r:
                data = await hgetall(r, key)
        except Exception as e:
            logger.error(f"Error validating redis token: {e}")
            raise

        if not data or "user_id" not in data:
            return None

        return AuthIdentity(
            user_id=data["user_id"],
            claims=data,  # Pass all metadata as claims
        )

    async def provision(self, user_id: str, description: str, *, owner_user_id: str | None = None) -> str:
        raw_key = _generate_api_key()
        hashed = hash_api_key(raw_key)
        reverse_key = self._reverse_key(user_id)
        identity_key = self._identity_key(hashed)

        # The stored identity hash carries the caller's ``user_id`` and description;
        # when the key is OWNED, the owner claim rides in the same hash under the
        # contract's shared claim key, so ``validate_token`` returns it in the
        # identity's claims for the backend's per-request attenuation without any
        # extra read. An ownerless key omits the field entirely (never a ``None``
        # value), so no spurious owner claim ever reaches the auth decision.
        identity_record = {"user_id": user_id, "description": description}
        if owner_user_id is not None:
            identity_record[OWNER_USER_ID_CLAIM] = owner_user_id

        # WATCH the reverse lookup, refuse if the user already has a record, then
        # commit the identity hash and the reverse lookup together in one MULTI.
        # The compare-and-set is the ATOMIC per-user duplicate guard: two concurrent
        # provisions of the same ``user_id`` cannot both write — the loser's EXEC
        # aborts (``WatchError``) and re-reads to find the record now present, so it
        # raises rather than stranding an unreachable, unrevocable identity record.
        # A key also never exists without the ``user_id -> hash`` lookup revoke/edit
        # resolve through.
        async with client_ctx(RedisClient, self._redis_settings()) as r, r.pipeline() as pipe:
            while True:
                try:
                    await pipe.watch(reverse_key)
                    if await pipe.get(reverse_key):
                        await pipe.unwatch()
                        raise DuplicateIdentityError(
                            f"user id {user_id!r} already has an identity record; revoke it "
                            "before minting a replacement"
                        )
                    pipe.multi()
                    hset_mapping(pipe, identity_key, identity_record)
                    pipe.set(reverse_key, hashed)
                    await pipe.execute()
                    break
                except WatchError:
                    # A concurrent writer changed the reverse key between WATCH and
                    # EXEC; re-read and re-decide (raises if the user now has one).
                    continue

        return raw_key

    async def revoke(self, user_id: str) -> bool:
        reverse_key = self._reverse_key(user_id)
        async with client_ctx(RedisClient, self._redis_settings()) as r:
            # The reverse lookup holds the plain hash string (redis-py types the
            # read loosely, so pin it to str for the identity-key build below).
            hashed = cast("str | None", await r.get(reverse_key))
            if not hashed:
                return False
            # Deleting the identity document uncaches the key immediately, so the
            # next request with it fails to authenticate.
            await r.delete(self._identity_key(hashed), reverse_key)
        return True

    async def update_description(self, user_id: str, description: str) -> bool:
        async with client_ctx(RedisClient, self._redis_settings()) as r:
            hashed = cast("str | None", await r.get(self._reverse_key(user_id)))
            if not hashed:
                return False
            identity_key = self._identity_key(hashed)
            identity = await hgetall(r, identity_key)
            if not identity:
                return False
            # The identity hash is the single home of ``description``; overwrite
            # that one field, leaving ``user_id`` untouched. The pre-write
            # existence check keeps the dangling-reverse-lookup ``False`` and never
            # creates a partial record on a missing key.
            await hset_mapping(r, identity_key, {"description": description})
        return True

    async def list_identities(self) -> list[tuple[str, str]]:
        identities: list[tuple[str, str]] = []
        async with client_ctx(RedisClient, self._redis_settings()) as r:
            async for key in scan_iter(r, f"{self.settings.key_prefix}*"):
                item = await hgetall(r, key)
                if not item:
                    continue
                user_id = item.get("user_id")
                if not user_id:
                    continue
                identities.append((user_id, item.get("description", "")))
        return identities

    async def healthcheck(self) -> None:
        # Probe the provider's OWN record store with the exact read shape token
        # validation uses: one ``HGETALL`` on a namespaced probe key, valid on any
        # plain Redis. Any Redis error (connection refused, auth failure,
        # WRONGTYPE, …) propagates untouched, so a broken identity store fails
        # startup LOUDLY and never serves.
        async with client_ctx(RedisClient, self._redis_settings()) as r:
            await hgetall(r, _PROBE_KEY)

    def readiness_targets(self) -> tuple[ReadinessTarget]:
        # Declare the provider's OWN Redis record store as core's readiness target:
        # the "access_control" check label, kit's RedisClient, and this provider's
        # redis settings. Core pings it generically — deduped against every other
        # subsystem sharing the connection — without knowing the store is Redis, so
        # the identity store is health-checked exactly as if core had wired it.
        return (ReadinessTarget("access_control", RedisClient, self._redis_settings()),)


# Module-level registration: the plugin registers itself as "redis" in the
# contract's direct-import registry at its own import, with no ``tai_app`` handle
# involved (the handle raises before ``bind()``, and this plugin must register in
# processes that never ``start()``). The factory is the class itself —
# ``RedisApiKeyProvider(settings)`` builds a live provider from the settings shape.
register_identity_provider("redis", RedisApiKeyProvider)
