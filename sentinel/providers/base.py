"""Provider interface - each cloud is pluggable and returns normalized Resources."""


class ProviderError(Exception):
    pass


class BaseProvider:
    name = "base"

    def collect(self):
        """Return (list[Resource], status_dict). status_dict describes provider health."""
        raise NotImplementedError

    def healthy(self):
        return self.collect()[1].get("healthy", False)
