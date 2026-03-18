from __future__ import annotations

from .channel import ChannelSession
from .http_client import HTTPClient


class ServerAPI:
    def __init__(self, base_url: str, network_logger=None):
        self.http = HTTPClient(base_url, network_logger=network_logger)

    def restore_channel(self, data: dict) -> ChannelSession:
        return ChannelSession.from_dict(self.http, data)

    def open_and_login(self, username: str, password: str) -> tuple[str, ChannelSession]:
        channel = ChannelSession(self.http)
        channel.open()
        login_resp = channel.request("/api/login", {"username": username, "password": password})
        token = str(login_resp.get("token") or "")
        if not token:
            raise ValueError("missing_login_token")
        return token, channel

    def send_message(self, channel: ChannelSession, token: str, recipient: str, body: str, msg_id: str) -> dict:
        return channel.request(
            "/api/messages/send",
            {"token": token, "to": recipient, "body": body, "msg_id": msg_id},
        )

    def pull_messages(self, channel: ChannelSession, token: str) -> dict:
        return channel.request("/api/messages/pull", {"token": token})
