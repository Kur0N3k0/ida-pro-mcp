import os
import json
import http.client
from urllib.parse import urlparse

import idaapi
import ida_kernwin


CONTROL_URL_DEFAULT = os.environ.get("IDA_MMCP_CONTROL", "http://127.0.0.1:8760")


def _http(method: str, path: str, body: dict | None = None):
    url = urlparse(os.environ.get("IDA_MMCP_CONTROL", CONTROL_URL_DEFAULT))
    conn = http.client.HTTPConnection(url.hostname, url.port)
    try:
        payload = json.dumps(body or {}).encode("utf-8") if method in ("POST", "PUT") else None
        headers = {"Content-Type": "application/json"}
        conn.request(method, path, payload, headers if payload else {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, json.loads(data or b"{}")
    except Exception as e:
        return 500, {"error": str(e)}
    finally:
        conn.close()


def register_session(name: str, host: str, port: int):
    _http("POST", "/register", {"name": name, "host": host, "port": port})


def unregister_session(name: str):
    _http("POST", "/unregister", {"name": name})


class MMCPPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MMCP Helper"
    help = "MMCP"
    wanted_name = "MMCP"
    wanted_hotkey = "Ctrl-Alt-N"

    def init(self):
        self._name = idaapi.get_root_filename()
        self._host = os.environ.get("IDA_MCP_HOST", "127.0.0.1")
        try:
            self._port = int(os.environ.get("IDA_MCP_PORT", "13337"))
        except Exception:
            self._port = 13337
        # Register an action for configuring MMCP (works across IDA versions)
        try:
            class _ConfigureAction(idaapi.action_handler_t):
                def __init__(self, plugin):
                    idaapi.action_handler_t.__init__(self)
                    self._plugin = plugin
                def activate(self, ctx):
                    self._plugin._configure_ui(None)
                    return 1
                def update(self, ctx):
                    return ida_kernwin.AST_ENABLE_ALWAYS

            action_name = "mmcp:configure"
            desc = ida_kernwin.action_desc_t(
                action_name,
                "MMCP: Configure server...",
                _ConfigureAction(self),
                None,
                "Configure MMCP aggregator",
                -1,
            )
            if ida_kernwin.unregister_action(action_name):
                pass
            ida_kernwin.register_action(desc)
            try:
                ida_kernwin.attach_action_to_menu(
                    "Edit/Plugins/",
                    action_name,
                    ida_kernwin.SETMENU_APP,
                )
            except Exception:
                pass
        except Exception:
            pass
        print("[MMCP] Plugin loaded; use Edit -> Plugins -> MMCP to configure aggregator registration")
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        self._configure_ui(None)

    def term(self):
        try:
            unregister_session(self._name)
        except Exception:
            pass

    def _configure_ui(self, _):
        # Use simple prompts for maximum compatibility across IDA versions (8.3+)
        control_url = ida_kernwin.ask_str(os.environ.get("IDA_MMCP_CONTROL", CONTROL_URL_DEFAULT), 0, "MMCP Control URL")
        if control_url is None:
            return
        name = ida_kernwin.ask_str(self._name, 0, "MMCP Session name")
        if name is None:
            return
        host = ida_kernwin.ask_str(self._host, 0, "IDA host")
        if host is None:
            return
        port = ida_kernwin.ask_long(self._port, "IDA port")
        if port is None:
            return

        os.environ["IDA_MMCP_CONTROL"] = control_url
        self._name, self._host, self._port = name, host, int(port)
        try:
            register_session(self._name, self._host, self._port)
            ida_kernwin.info("Registered session with MMCP")
        except Exception as e:
            ida_kernwin.warning(f"Failed to register with MMCP: {e}")


def PLUGIN_ENTRY():
    return MMCPPlugin()


