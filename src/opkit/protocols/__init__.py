"""Protocol backends.

Every machine speaks some management protocol; this package implements the
ones opkit ships with. Each module is self-contained: it defines its YAML
protocol dataclass and ``parse_config`` (invoked by ``opkit.config`` while
loading ``devices:``), owns at most one live session per device through a
manager class, and exposes session-oriented operations to the UI layer.

Adding a protocol means: write a module in this style, register its
``parse_config`` in ``opkit.config.PARSERS``, and wire manager calls into
``opkit.mcp_server``. Three greppable places, no registration machinery.
"""
