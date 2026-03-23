from oci_sip_mcp.chat import (
    build_openai_tools,
    extract_function_calls,
    extract_stream_text_delta,
    extract_text_output,
    parse_sse_event,
)


class DummyTool:
    def __init__(self, name, description, input_schema):
        self.name = name
        self.description = description
        self.inputSchema = input_schema


def test_build_openai_tools():
    tool = DummyTool("list_policies", "List policies", {"type": "object", "properties": {}})

    result = build_openai_tools([tool])

    assert result[0]["type"] == "function"
    assert result[0]["name"] == "list_policies"
    assert result[0]["parameters"]["type"] == "object"


def test_extract_text_output_collects_all_output_text():
    response = {
        "output": [
            {
                "type": "message",
                "content": [
                    {"type": "output_text", "text": "Hello"},
                    {"type": "output_text", "text": "World"},
                ],
            }
        ]
    }

    assert extract_text_output(response) == "Hello\nWorld"


def test_extract_function_calls_returns_only_function_calls():
    response = {
        "output": [
            {"type": "message", "content": []},
            {"type": "function_call", "name": "list_policies", "arguments": "{}", "call_id": "call_1"},
        ]
    }

    calls = extract_function_calls(response)

    assert len(calls) == 1
    assert calls[0]["name"] == "list_policies"


def test_parse_sse_event_collects_event_and_data():
    event_name, data = parse_sse_event(
        [
            "event: response.output_text.delta",
            'data: {"type":"response.output_text.delta","delta":"Hello"}',
        ]
    )

    assert event_name == "response.output_text.delta"
    assert '"delta":"Hello"' in data


def test_extract_stream_text_delta_from_delta_event():
    payload = {"type": "response.output_text.delta", "delta": "Hello"}

    assert extract_stream_text_delta("response.output_text.delta", payload) == "Hello"
