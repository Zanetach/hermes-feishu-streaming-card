from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


MEDIA_SAFE_EXTRACT_BEGIN = "# HERMES_FEISHU_CARD_MEDIA_SAFE_EXTRACT_BEGIN"
MEDIA_SAFE_EXTRACT_END = "# HERMES_FEISHU_CARD_MEDIA_SAFE_EXTRACT_END"
MEDIA_SAFE_DELIVERY_BEGIN = "# HERMES_FEISHU_CARD_MEDIA_SAFE_DELIVERY_BEGIN"
MEDIA_SAFE_DELIVERY_END = "# HERMES_FEISHU_CARD_MEDIA_SAFE_DELIVERY_END"


@dataclass(frozen=True)
class MediaSafePatchResult:
    adapter_path: Path | None
    changed: bool
    applied: bool
    message: str


def apply_media_safe_patch(hermes_dir: str | Path) -> MediaSafePatchResult:
    """Patch Hermes Feishu adapter to deliver MEDIA files natively.

    Hermes cards are best used for progress and final text. Explicit MEDIA
    directives need to become real Feishu attachments; otherwise users see
    internal server paths in chat. This patch is deliberately marker based and
    idempotent so setup/install can run repeatedly.
    """
    adapter_path = _find_feishu_adapter(Path(hermes_dir).expanduser())
    if adapter_path is None:
        return MediaSafePatchResult(
            adapter_path=None,
            changed=False,
            applied=False,
            message="media-safe: skipped; Feishu adapter was not found",
        )

    original = adapter_path.read_text(encoding="utf-8")
    patched = patch_adapter_source(original)
    if patched == original:
        applied = _has_marker_patch(patched) or _has_compatible_media_delivery(patched)
        status = "already ok" if applied else "skipped; no supported send anchor found"
        return MediaSafePatchResult(
            adapter_path=adapter_path,
            changed=False,
            applied=applied,
            message=f"media-safe: {status} {adapter_path}",
        )

    adapter_path.write_text(patched, encoding="utf-8")
    return MediaSafePatchResult(
        adapter_path=adapter_path,
        changed=True,
        applied=True,
        message=f"media-safe: patched {adapter_path}",
    )


def patch_adapter_source(content: str) -> str:
    content = _apply_extract_patch(content)
    return _apply_delivery_patch(content)


def _has_marker_patch(content: str) -> bool:
    return MEDIA_SAFE_EXTRACT_BEGIN in content and MEDIA_SAFE_DELIVERY_BEGIN in content


def _has_compatible_media_delivery(content: str) -> bool:
    required = (
        "self.extract_media",
        "self.filter_media_delivery_paths",
        "await self.send_image_file",
        "await self.send_document",
        "No deliverable text or media remained after processing MEDIA tags",
    )
    return all(item in content for item in required)


def _find_feishu_adapter(hermes_dir: Path) -> Path | None:
    candidates = [
        hermes_dir / "plugins" / "platforms" / "feishu" / "adapter.py",
        hermes_dir / "hermes-agent" / "plugins" / "platforms" / "feishu" / "adapter.py",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _apply_extract_patch(content: str) -> str:
    if MEDIA_SAFE_EXTRACT_BEGIN in content:
        return content

    anchor = (
        '        if not self._client:\n'
        '            return SendResult(success=False, error="Not connected")\n'
        "\n"
        "        formatted = self.format_message(content)\n"
    )
    if anchor not in content:
        return content

    replacement = (
        '        if not self._client:\n'
        '            return SendResult(success=False, error="Not connected")\n'
        "\n"
        f"        {MEDIA_SAFE_EXTRACT_BEGIN}\n"
        "        media_files = []\n"
        '        if "MEDIA:" in str(content or "") or "[[audio_as_voice]]" in str(content or ""):\n'
        "            try:\n"
        '                media_files, content = self.extract_media(str(content or ""))\n'
        "                media_files = self.filter_media_delivery_paths(media_files)\n"
        "            except Exception as exc:\n"
        '                logger.warning("[Feishu] Failed to extract MEDIA directives before send: %s", exc)\n'
        "                media_files = []\n"
        f"        {MEDIA_SAFE_EXTRACT_END}\n"
        "\n"
        "        formatted = self.format_message(content)\n"
    )
    return content.replace(anchor, replacement, 1)


def _apply_delivery_patch(content: str) -> str:
    if MEDIA_SAFE_DELIVERY_BEGIN in content:
        return content

    anchor = '            return self._finalize_send_result(last_response, "send failed")\n'
    if anchor not in content:
        return content

    replacement = (
        f"            {MEDIA_SAFE_DELIVERY_BEGIN}\n"
        '            last_result = self._finalize_send_result(last_response, "send failed") if last_response is not None else None\n'
        "            for media_path, is_voice in media_files:\n"
        "                if not os.path.exists(media_path):\n"
        '                    logger.warning("[Feishu] MEDIA file disappeared before delivery: %s", media_path)\n'
        "                    continue\n"
        "                ext = Path(media_path).suffix.lower()\n"
        "                if ext in _MIGRATION_IMAGE_EXTS and not is_voice:\n"
        "                    media_result = await self.send_image_file(chat_id, media_path, metadata=metadata)\n"
        "                elif ext in _MIGRATION_VIDEO_EXTS:\n"
        "                    media_result = await self.send_video(chat_id, media_path, metadata=metadata)\n"
        "                elif ext in _MIGRATION_AUDIO_EXTS:\n"
        "                    media_result = await self.send_voice(chat_id, media_path, metadata=metadata)\n"
        "                else:\n"
        "                    media_result = await self.send_document(chat_id, media_path, metadata=metadata)\n"
        "                if not media_result.success:\n"
        '                    logger.warning("[Feishu] MEDIA delivery failed for %s: %s", media_path, media_result.error)\n'
        "                last_result = media_result\n"
        "\n"
        "            if last_result is None:\n"
        '                return SendResult(success=False, error="No deliverable text or media remained after processing MEDIA tags")\n'
        f"            {MEDIA_SAFE_DELIVERY_END}\n"
        "            return last_result\n"
    )
    return content.replace(anchor, replacement, 1)
