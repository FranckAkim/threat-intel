from dataclasses import dataclass
from typing import Optional


@dataclass
class ThreatEvent:
    id: str
    source: str
    severity: float
    description: str
    published: str
    raw_data: dict
    cvss_version: Optional[str] = None

    def is_critical(self) -> bool:
        return self.severity >= 9.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "severity": self.severity,
            "description": self.description,
            "published": self.published,
            "cvss_version": self.cvss_version
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity}/10] {self.id}"
            f"({self.published[:10]}) - {self.description[:100]}"
        )
