"""Pydantic request/response models for the ISGd REST API."""
from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class SessionUpdate(BaseModel):
    """PUT /sessions/{id} — all fields optional; any combination accepted."""
    in_kbps:  Optional[int]  = Field(None, ge=0, description='Input (upload) rate kbps')
    out_kbps: Optional[int]  = Field(None, ge=0, description='Output (download) rate kbps')
    approve:  Optional[bool] = Field(None, description='Approve session')
    block:    Optional[bool] = Field(None, description='Block / disconnect session')


class SessionInfo(BaseModel):
    session_id:        str
    ip:                str
    nat_ip:            Optional[str]
    mac:               Optional[str]
    port:              int
    duration:          int
    in_bytes:          int
    out_bytes:         int
    in_packets:        int
    out_packets:       int
    in_rate:           int
    out_rate:          int
    in_burst:          int
    out_burst:         int
    alive_interval:    int
    idle_timeout:      int
    max_duration:      int
    flags:             int
    service_name:      Optional[str]
    parent_session_id: Optional[str]


class StatusInfo(BaseModel):
    approved:       int
    unapproved:     int
    dying:          int
    no_accounting:  int
    total:          int
    uptime_seconds: float
    auth_backends:  list[str]
    acct_backends:  list[str]


class UpdateResult(BaseModel):
    actions: list[str]


class ArpingResult(BaseModel):
    ip:               str
    iface:            str
    reachable:        bool
    packets_sent:     int
    packets_received: int
    rtt_ms:           list[float]
    avg_rtt_ms:       Optional[float]
