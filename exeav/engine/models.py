"""Estruturas de dados do motor de detecção."""
from __future__ import annotations

from dataclasses import dataclass, field

CLEAN = "limpo"
SUSPICIOUS = "suspeito"
MALICIOUS = "malicioso"

SEVERITY_ORDER = {"info": 0, "baixa": 1, "media": 2, "alta": 3, "critica": 4}


@dataclass
class Indicator:
    """Uma evidência encontrada no conteúdo do arquivo."""
    id: str
    name: str
    category: str
    description: str
    weight: int
    severity: str = "media"
    evidence: list[str] = field(default_factory=list)
    family: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "description": self.description, "weight": self.weight,
            "severity": self.severity, "evidence": self.evidence[:12], "family": self.family,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Indicator":
        return cls(**{k: d.get(k) for k in ("id", "name", "category", "description", "weight",
                                             "severity", "evidence", "family") if k in d})


@dataclass
class ScanResult:
    path: str
    verdict: str = CLEAN
    score: int = 0
    threat_name: str = ""
    file_type: str = ""
    size: int = 0
    sha256: str = ""
    indicators: list[Indicator] = field(default_factory=list)
    error: str = ""
    skipped: bool = False
    from_cache: bool = False
    action: str = ""
    container: str = ""      # arquivo compactado que contém o item (se houver)

    @property
    def is_threat(self) -> bool:
        return self.verdict in (SUSPICIOUS, MALICIOUS)

    @property
    def evidence_groups(self) -> list[str]:
        """Categorias INDEPENDENTES de evidência positiva (ex.: Rede, Persistência, Ofuscação)."""
        return sorted({i.category for i in self.indicators if i.weight > 0 and i.category not in ("Confiança",)})

    @property
    def confidence(self) -> str:
        """Nível de confiança da detecção. Uma única evidência fraca nunca vira 'alta'.
        confirmada: idêntico a malware catalogado (hash) ou EICAR
        alta: veredito malicioso com 3+ tipos independentes de evidência
        média: 2 tipos independentes, ou 1 evidência crítica bem específica
        baixa: o resto (só um tipo de evidência)"""
        if self.verdict == CLEAN:
            return ""
        ids = {i.id for i in self.indicators}
        if ids & {"sig.hash", "test.eicar"}:
            return "confirmada"
        groups = self.evidence_groups
        crit = any(i.weight >= 70 and i.severity == "critica" for i in self.indicators)
        if self.verdict == MALICIOUS and len(groups) >= 3:
            return "alta"
        if len(groups) >= 2 or crit:
            return "média"
        return "baixa"

    def reasons(self) -> list[str]:
        return [f"{i.name} (+{i.weight})" if i.weight >= 0 else f"{i.name} ({i.weight})"
                for i in sorted(self.indicators, key=lambda x: -x.weight)]

    def to_dict(self) -> dict:
        return {
            "path": self.path, "verdict": self.verdict, "score": self.score,
            "threat_name": self.threat_name, "file_type": self.file_type, "size": self.size,
            "sha256": self.sha256, "indicators": [i.to_dict() for i in self.indicators],
            "error": self.error, "action": self.action, "container": self.container,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        r = cls(path=d.get("path", ""))
        for k in ("verdict", "score", "threat_name", "file_type", "size", "sha256", "error",
                  "action", "container"):
            if k in d:
                setattr(r, k, d[k])
        r.indicators = [Indicator.from_dict(x) for x in d.get("indicators", [])]
        return r
