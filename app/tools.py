from dataclasses import dataclass

class ToolAuthorizationError(PermissionError):
    pass

@dataclass(frozen=True)
class Principal:
    subject: str = "anonymous"
    scopes: frozenset = frozenset()

TOOL_SCOPES = {
    "fx_rate_lookup": "read:fx",
    "transfer_funds": "write:funds",
}

INVOCATION_LOG = []

def invoke_tool(name, arguments, *, principal=None):
    principal = principal or Principal()
    required_scope = TOOL_SCOPES.get(name)
    if required_scope is None:
        raise ToolAuthorizationError("Tool is not registered.")
    if required_scope not in principal.scopes:
        raise ToolAuthorizationError("Principal is not authorised for this tool.")
    INVOCATION_LOG.append({"tool": name, "principal": principal.subject})
    raise ToolAuthorizationError("Privileged tools are disabled in this environment.")
