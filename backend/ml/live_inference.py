"""Live packet window buffer for streaming WiFi intrusion detection inference."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

try:
    from ml.inference_service import V3InferenceService, create_v3_inference_service
except ImportError:
    try:
        from .inference_service import V3InferenceService, create_v3_inference_service
    except ImportError:
        from backend.ml.inference_service import (
            V3InferenceService,
            create_v3_inference_service,
        )


DEFAULT_WINDOW_SECONDS = 5.0


class LiveInferenceBuffer:
    """Buffer streaming packets into 5-second chronological windows for ML inference."""

    def __init__(
        self,
        inference_service: V3InferenceService | None = None,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than 0.")

        self.window_seconds = float(window_seconds)
        self.inference_service = (
            inference_service
            if inference_service is not None
            else create_v3_inference_service()
        )
        self.current_window: list[dict[str, Any]] = []
        self.window_start: float | None = None
        self.latest_result: dict[str, Any] | None = None

    def add_packet(self, packet: Any) -> dict[str, Any] | None:
        """Add a packet to the current window buffer.

        The first packet establishes the window start. Subsequent packets with
        timestamp < window_start + window_seconds remain in the current window.
        A packet at or after the boundary finalizes the previous window, triggers
        inference via V3InferenceService, and becomes the first packet of the
        next window.

        Returns the inference result if a window completed, otherwise None.
        """
        packet_dict = self._convert_packet(packet)
        timestamp = float(packet_dict["timestamp_epoch"])

        if self.window_start is None or not self.current_window:
            self.window_start = timestamp
            self.current_window = [packet_dict]
            return None

        if timestamp < self.window_start + self.window_seconds:
            self.current_window.append(packet_dict)
            return None

        # Boundary reached: finalize the current window and start the next window.
        completed_window = self.current_window
        self.current_window = [packet_dict]
        self.window_start = timestamp

        result = self.inference_service.analyze_window(
            completed_window,
            window_seconds=self.window_seconds,
        )
        self.latest_result = result
        return result

    def get_latest_result(self) -> dict[str, Any] | None:
        """Return the latest completed inference result, or None if no window was analyzed."""
        return self.latest_result

    def flush(self) -> dict[str, Any] | None:
        """Immediately infer the current non-empty window.

        Never runs inference if the window is empty.
        Returns the inference result if a window was analyzed, otherwise None.
        """
        if not self.current_window:
            return None

        completed_window = self.current_window
        self.current_window = []
        self.window_start = None

        result = self.inference_service.analyze_window(
            completed_window,
            window_seconds=self.window_seconds,
        )
        self.latest_result = result
        return result

    def reset(self) -> None:
        """Reset the buffer state and clear the latest result."""
        self.current_window = []
        self.window_start = None
        self.latest_result = None

    def clear(self) -> None:
        """Clear the buffer state and latest result (alias for reset)."""
        self.reset()

    @staticmethod
    def _convert_packet(packet: Any) -> dict[str, Any]:
        """Convert a PacketAnalysis object or dict to the format expected by V3InferenceService."""
        if isinstance(packet, dict):
            converted = dict(packet)
        elif is_dataclass(packet):
            converted = asdict(packet)
        elif hasattr(packet, "__dict__"):
            converted = dict(vars(packet))
        else:
            raise TypeError(f"Unsupported packet type: {type(packet)!r}")

        if "timestamp_epoch" not in converted or converted["timestamp_epoch"] is None:
            raise ValueError("Packet is missing required field: 'timestamp_epoch'")

        return converted
