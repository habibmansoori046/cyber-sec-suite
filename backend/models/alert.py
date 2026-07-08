"""Alert model — centralized notification system."""

import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, Boolean, JSON
from sqlalchemy.orm import Mapped, mapped_column
from database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # Which module generated it
    source_id: Mapped[str] = mapped_column(String(36), nullable=True)  # Link to scan/case/incident
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[str] = mapped_column(String(36), nullable=True)
    alert_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
