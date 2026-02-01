from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanResult:
    """Minimal scan result model used by SearchEngine ML modules."""

    url_tested: str
    vulnerability_type: str
    severity: str
    confidence: float
    evidence: str = ""
    response_code: Optional[int] = None
    response_time: Optional[float] = None
    response_size: Optional[int] = None
    response_body: Optional[str] = None
    payload_used: Optional[str] = None
    parameter_tested: Optional[str] = None
    parameters_tested: Optional[list] = None
    error_message: Optional[str] = None

