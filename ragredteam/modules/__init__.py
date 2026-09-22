"""Import all attack modules so they self-register."""
from . import direct_injection  # noqa: F401
from . import jailbreak  # noqa: F401
from . import indirect_injection  # noqa: F401
from . import exfiltration  # noqa: F401
from . import refusal  # noqa: F401
from . import citation_faithfulness  # noqa: F401
from . import controls  # noqa: F401
