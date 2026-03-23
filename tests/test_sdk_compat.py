from oci_iam_mcp.chat import get_structured_tool_content as get_chat_structured_tool_content
from oci_iam_mcp.repl import get_structured_tool_content as get_repl_structured_tool_content


class ResultCamel:
    def __init__(self):
        self.structuredContent = {"ok": True}


class ResultSnake:
    def __init__(self):
        self.structured_content = {"ok": True}


def test_chat_sdk_compat_uses_camel_case():
    assert get_chat_structured_tool_content(ResultCamel()) == {"ok": True}


def test_chat_sdk_compat_falls_back_to_snake_case():
    assert get_chat_structured_tool_content(ResultSnake()) == {"ok": True}


def test_repl_sdk_compat_uses_camel_case():
    assert get_repl_structured_tool_content(ResultCamel()) == {"ok": True}
