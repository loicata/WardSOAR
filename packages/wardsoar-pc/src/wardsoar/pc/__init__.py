"""WardSOAR PC — Windows desktop application layer.

Everything in this package assumes a Windows host: pywin32, WMI, DPAPI,
Sysmon, YARA, PySide6. For cross-platform code, see ``wardsoar.core``.

This is the package the MSI installer ships. The version here drives
the top-level meta-distribution's ``__version__`` (see the root
``pyproject.toml``) and the WiX product version.
"""

__version__ = "0.22.10"
