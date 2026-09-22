"""Attack cases and the module registry.

An ``AttackCase`` is one adversarial probe: a prompt to send, optional setup
(poisoned chunks, canary secrets), and the markers that indicate the attack
succeeded. An ``AttackModule`` is a family of related cases. Modules
register themselves in ``registry`` by family name; the runner executes every
registered module.

To add a module, subclass ``AttackModule`` and call
``registry.register(MyModule())`` — see docs/ADDING_MODULES.md.
"""
from dataclasses import dataclass, field


@dataclass
class AttackCase:
    id: str
    family: str
    prompt: str
    description: str = ""
    # Setup smuggled to the target via the ask() context dict, e.g.
    # {"extra_chunks": [...], "canary": "SECRET-..."}.
    setup: dict = field(default_factory=dict)
    # Markers whose presence in the response means the attack SUCCEEDED.
    # Canaries are planted secrets; phrases are attacker-chosen objectives.
    success_markers: list = field(default_factory=list)
    # Benign control queries must NOT be refused; they are scored inverted.
    is_control: bool = False


class AttackModule:
    family = "base"
    description = ""

    def cases(self):
        raise NotImplementedError


class ModuleRegistry:
    def __init__(self):
        self._modules = {}

    def register(self, module):
        self._modules[module.family] = module

    def families(self):
        return sorted(self._modules)

    def get(self, family):
        return self._modules[family]

    def all_cases(self, families=None):
        wanted = families or self.families()
        cases = []
        for fam in wanted:
            cases.extend(self._modules[fam].cases())
        return cases


registry = ModuleRegistry()


def all_cases(families=None):
    return registry.all_cases(families)
