"""
Module de traçabilité inaltérable pour bases TCIM.
"""

from src.db.audit.tamper_evident_log import AuditEntry, TamperEvidentAuditTrail

__all__ = ["AuditEntry", "TamperEvidentAuditTrail"]
