from .base import Detector


def __getattr__(name):
	if name == "DetectionEngine":
		from .engine import DetectionEngine

		return DetectionEngine
	raise AttributeError(name)


__all__ = ["Detector", "DetectionEngine"]
