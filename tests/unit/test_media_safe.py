from hermes_feishu_card.install.media_safe import (
    MEDIA_SAFE_DELIVERY_BEGIN,
    MEDIA_SAFE_EXTRACT_BEGIN,
    patch_adapter_source,
)


def test_patch_adapter_source_inserts_media_extraction_and_delivery():
    source = '''class FeishuAdapter:
    async def send(self, chat_id, content, reply_to=None, metadata=None):
        if not self._client:
            return SendResult(success=False, error="Not connected")

        formatted = self.format_message(content)
        chunks = self.truncate_message(formatted, self.MAX_MESSAGE_LENGTH)
        last_response = None

        try:
            for chunk in chunks:
                last_response = await self._feishu_send_with_retry(chat_id, "text", chunk)

            return self._finalize_send_result(last_response, "send failed")
        except Exception as exc:
            return SendResult(success=False, error=str(exc))
'''

    patched = patch_adapter_source(source)

    assert MEDIA_SAFE_EXTRACT_BEGIN in patched
    assert MEDIA_SAFE_DELIVERY_BEGIN in patched
    assert "self.extract_media" in patched
    assert "await self.send_image_file" in patched
    assert "MEDIA file disappeared before delivery" in patched


def test_patch_adapter_source_is_idempotent():
    source = '''class FeishuAdapter:
    async def send(self, chat_id, content, reply_to=None, metadata=None):
        if not self._client:
            return SendResult(success=False, error="Not connected")

        formatted = self.format_message(content)
        chunks = self.truncate_message(formatted, self.MAX_MESSAGE_LENGTH)
        last_response = None

        try:
            for chunk in chunks:
                last_response = await self._feishu_send_with_retry(chat_id, "text", chunk)

            return self._finalize_send_result(last_response, "send failed")
        except Exception as exc:
            return SendResult(success=False, error=str(exc))
'''

    once = patch_adapter_source(source)
    twice = patch_adapter_source(once)

    assert twice == once
