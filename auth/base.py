"""Abstract auth adapter interface for the pentest harness."""

from abc import ABC, abstractmethod


class AuthConfigError(Exception):
    """Raised when an auth adapter cannot be created due to missing
    configuration (env vars, profile fields, API keys).

    This is the only exception that conftest will treat as a skip-worthy
    condition. All other exceptions propagate as test failures so that
    real adapter regressions are not silently swallowed.
    """


class CaptchaEnforcedError(AuthConfigError):
    """Raised when CAPTCHA verification blocks the authentication request.

    The target has CAPTCHA enforcement enabled.  Headless callers cannot
    complete the CAPTCHA challenge.  Disable CAPTCHA for the test project
    or provide a pre-obtained token via env vars.
    """


class AbstractAuthAdapter(ABC):
    """Interface all auth adapters must implement."""

    @abstractmethod
    def get_token(self, account_name: str) -> str:
        """Return a fresh Bearer token for the named account.

        Args:
            account_name: Logical name for the test account (e.g. "user_a").

        Returns:
            JWT string suitable for use as a Bearer token.

        Raises:
            ValueError: If ``account_name`` is not known to this adapter.
            RuntimeError: If the token cannot be obtained or refreshed.
        """
        ...

    @property
    def auth_type(self) -> str:
        """Return 'bearer' or 'cookie' to indicate the auth mechanism."""
        return "bearer"  # default for most adapters

    @abstractmethod
    def get_headers(self, account_name: str) -> dict:
        """Return full auth headers ready for inclusion in an HTTP request.

        The returned dict contains the authentication headers appropriate for
        the adapter type:

        - Bearer-token adapters: ``{"Authorization": "Bearer <token>"}``
        - Cookie-based adapters: ``{"Cookie": "<name>=<value>"}``

        Adapters may include additional headers (e.g. ``apikey`` for PostgREST).
        """
        ...

    @abstractmethod
    def is_expired(self, account_name: str) -> bool:
        """Check whether the cached token for an account is expired or near-expiry.

        "Near-expiry" is defined by each adapter (e.g. within 10 seconds of the
        ``exp`` claim).  Callers should treat ``True`` as a signal that
        :meth:`get_token` will transparently refresh before returning.

        Args:
            account_name: Logical name for the test account.

        Returns:
            ``True`` if the token is expired or within the adapter's refresh
            window; ``False`` otherwise.
        """
        ...
