"""
Analytics and Reporting API Endpoints

Provides endpoints for analytics and reporting with RBAC integration.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from app.core.rbac import (
    get_db_session, get_current_user, require_permissions, require_roles
)
from app.models.threat import Threat
from app.models.incident import Incident
from app.models.vulnerability import Vulnerability
from app.models.asset import Asset

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/dashboard/overview")
@require_permissions(["analytics:read"])
async def get_dashboard_overview(
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get dashboard overview with key metrics."""
    # Get basic counts
    total_threats = db.query(Threat).count()
    total_incidents = db.query(Incident).count()
    total_vulnerabilities = db.query(Vulnerability).count()
    total_assets = db.query(Asset).count()
    
    # Get recent activity
    recent_threats = db.query(Threat).order_by(Threat.created_at.desc()).limit(5).all()
    recent_incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()
    
    return {
        "summary": {
            "total_threats": total_threats,
            "total_incidents": total_incidents,
            "total_vulnerabilities": total_vulnerabilities,
            "total_assets": total_assets
        },
        "recent_activity": {
            "recent_threats": [
                {
                    "id": t.id,
                    "name": t.name,
                    "severity": t.severity,
                    "created_at": t.created_at
                } for t in recent_threats
            ],
            "recent_incidents": [
                {
                    "id": i.id,
                    "title": i.title,
                    "priority": i.priority,
                    "status": i.status,
                    "created_at": i.created_at
                } for i in recent_incidents
            ]
        }
    }


@router.get("/threats/trends")
@require_permissions(["threat:read", "analytics:read"])
async def get_threat_trends(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get threat trends over time."""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    # Get threats by date
    threats = db.query(Threat).filter(
        Threat.created_at >= start_date,
        Threat.created_at <= end_date
    ).all()
    
    # Group by date and severity
    trends = {}
    for threat in threats:
        date_str = threat.created_at.strftime("%Y-%m-%d")
        if date_str not in trends:
            trends[date_str] = {"high": 0, "medium": 0, "low": 0, "total": 0}
        
        trends[date_str][threat.severity] += 1
        trends[date_str]["total"] += 1
    
    return {
        "period_days": days,
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "trends": trends
    }


@router.get("/incidents/performance")
@require_permissions(["incident:read", "analytics:read"])
async def get_incident_performance(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get incident response performance metrics."""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    # Get incidents in the period
    incidents = db.query(Incident).filter(
        Incident.created_at >= start_date,
        Incident.created_at <= end_date
    ).all()
    
    # Calculate metrics
    total_incidents = len(incidents)
    closed_incidents = len([i for i in incidents if i.status == "closed"])
    avg_resolution_time = 0
    
    if closed_incidents > 0:
        # Mock resolution time calculation
        avg_resolution_time = 24  # hours
    
    # Priority distribution
    priority_distribution = {
        "high": len([i for i in incidents if i.priority == "high"]),
        "medium": len([i for i in incidents if i.priority == "medium"]),
        "low": len([i for i in incidents if i.priority == "low"])
    }
    
    return {
        "period_days": days,
        "total_incidents": total_incidents,
        "closed_incidents": closed_incidents,
        "open_incidents": total_incidents - closed_incidents,
        "closure_rate": (closed_incidents / total_incidents * 100) if total_incidents > 0 else 0,
        "avg_resolution_time_hours": avg_resolution_time,
        "priority_distribution": priority_distribution
    }


@router.get("/vulnerabilities/risk-assessment")
@require_permissions(["vulnerability:read", "analytics:read"])
async def get_vulnerability_risk_assessment(
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get vulnerability risk assessment summary."""
    # Get all vulnerabilities
    vulnerabilities = db.query(Vulnerability).all()
    
    # Calculate risk scores
    high_risk = len([v for v in vulnerabilities if v.severity == "high"])
    medium_risk = len([v for v in vulnerabilities if v.severity == "medium"])
    low_risk = len([v for v in vulnerabilities if v.severity == "low"])
    
    # Calculate average CVSS score
    total_cvss = sum([v.cvss_score or 0 for v in vulnerabilities])
    avg_cvss = total_cvss / len(vulnerabilities) if vulnerabilities else 0
    
    # Get top vulnerabilities by CVSS score
    top_vulnerabilities = sorted(
        [v for v in vulnerabilities if v.cvss_score],
        key=lambda x: x.cvss_score or 0,
        reverse=True
    )[:10]
    
    return {
        "total_vulnerabilities": len(vulnerabilities),
        "risk_distribution": {
            "high": high_risk,
            "medium": medium_risk,
            "low": low_risk
        },
        "cvss_metrics": {
            "average_score": round(avg_cvss, 2),
            "highest_score": max([v.cvss_score or 0 for v in vulnerabilities]) if vulnerabilities else 0
        },
        "top_vulnerabilities": [
            {
                "id": v.id,
                "name": v.name,
                "cvss_score": v.cvss_score,
                "severity": v.severity
            } for v in top_vulnerabilities
        ]
    }


@router.get("/assets/security-posture")
@require_permissions(["asset:read", "analytics:read"])
async def get_asset_security_posture(
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get asset security posture summary."""
    # Get all assets
    assets = db.query(Asset).all()
    
    # Calculate security metrics
    total_assets = len(assets)
    critical_assets = len([a for a in assets if a.criticality == "critical"])
    high_assets = len([a for a in assets if a.criticality == "high"])
    medium_assets = len([a for a in assets if a.criticality == "medium"])
    low_assets = len([a for a in assets if a.criticality == "low"])
    
    # Mock compliance score calculation
    compliance_score = 85.5  # Mock value
    
    return {
        "total_assets": total_assets,
        "criticality_distribution": {
            "critical": critical_assets,
            "high": high_assets,
            "medium": medium_assets,
            "low": low_assets
        },
        "security_metrics": {
            "compliance_score": compliance_score,
            "risk_level": "medium" if compliance_score < 90 else "low"
        }
    }


@router.get("/reports/security-summary")
@require_permissions(["report:read", "analytics:read"])
async def generate_security_summary_report(
    report_type: str = Query("monthly", description="Report type: daily, weekly, monthly"),
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Generate a comprehensive security summary report."""
    # Parse dates
    if start_date and end_date:
        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d")
    else:
        end = datetime.now()
        if report_type == "daily":
            start = end - timedelta(days=1)
        elif report_type == "weekly":
            start = end - timedelta(weeks=1)
        else:  # monthly
            start = end - timedelta(days=30)
    
    # Get data for the period
    threats = db.query(Threat).filter(
        Threat.created_at >= start,
        Threat.created_at <= end
    ).all()
    
    incidents = db.query(Incident).filter(
        Incident.created_at >= start,
        Incident.created_at <= end
    ).all()
    
    vulnerabilities = db.query(Vulnerability).filter(
        Vulnerability.created_at >= start,
        Vulnerability.created_at <= end
    ).all()
    
    # Generate report
    report = {
        "report_type": report_type,
        "period": {
            "start_date": start.isoformat(),
            "end_date": end.isoformat()
        },
        "executive_summary": {
            "total_threats": len(threats),
            "total_incidents": len(incidents),
            "total_vulnerabilities": len(vulnerabilities),
            "overall_risk_level": "medium"
        },
        "threat_analysis": {
            "threat_count": len(threats),
            "severity_distribution": {
                "high": len([t for t in threats if t.severity == "high"]),
                "medium": len([t for t in threats if t.severity == "medium"]),
                "low": len([t for t in threats if t.severity == "low"])
            }
        },
        "incident_analysis": {
            "incident_count": len(incidents),
            "status_distribution": {
                "open": len([i for i in incidents if i.status == "open"]),
                "investigating": len([i for i in incidents if i.status == "investigating"]),
                "resolved": len([i for i in incidents if i.status == "closed"])
            },
            "priority_distribution": {
                "high": len([i for i in incidents if i.priority == "high"]),
                "medium": len([i for i in incidents if i.priority == "medium"]),
                "low": len([i for i in incidents if i.priority == "low"])
            }
        },
        "vulnerability_analysis": {
            "vulnerability_count": len(vulnerabilities),
            "severity_distribution": {
                "high": len([v for v in vulnerabilities if v.severity == "high"]),
                "medium": len([v for v in vulnerabilities if v.severity == "medium"]),
                "low": len([v for v in vulnerabilities if v.severity == "low"])
            }
        },
        "recommendations": [
            "Implement additional monitoring for high-severity threats",
            "Review incident response procedures",
            "Prioritize patching of high-risk vulnerabilities"
        ],
        "generated_by": current_user.id,
        "generated_at": datetime.now().isoformat()
    }
    
    return report


@router.post("/reports/export")
@require_permissions(["report:export", "analytics:export"])
async def export_analytics_report(
    report_data: Dict[str, Any],
    format: str = Query("pdf", description="Export format: pdf, excel, json"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Export analytics report in various formats."""
    # Mock export functionality
    return {
        "message": f"Report exported successfully in {format} format",
        "format": format,
        "exported_by": current_user.id,
        "exported_at": datetime.now().isoformat(),
        "download_url": f"/downloads/reports/{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
    }


@router.get("/metrics/real-time")
@require_permissions(["analytics:read"])
async def get_real_time_metrics(
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get real-time security metrics."""
    # Get current counts
    active_threats = db.query(Threat).filter(Threat.status == "active").count()
    open_incidents = db.query(Incident).filter(Incident.status == "open").count()
    critical_vulnerabilities = db.query(Vulnerability).filter(Vulnerability.severity == "high").count()
    
    # Mock real-time data
    return {
        "timestamp": datetime.now().isoformat(),
        "active_threats": active_threats,
        "open_incidents": open_incidents,
        "critical_vulnerabilities": critical_vulnerabilities,
        "system_status": "healthy",
        "last_incident": "2 hours ago",
        "threat_level": "medium"
    }


@router.get("/comparison/period")
@require_permissions(["analytics:read"])
async def compare_periods(
    period1_start: str = Query(..., description="Period 1 start date (YYYY-MM-DD)"),
    period1_end: str = Query(..., description="Period 1 end date (YYYY-MM-DD)"),
    period2_start: str = Query(..., description="Period 2 start date (YYYY-MM-DD)"),
    period2_end: str = Query(..., description="Period 2 end date (YYYY-MM-DD)"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Compare security metrics between two time periods."""
    # Parse dates
    p1_start = datetime.strptime(period1_start, "%Y-%m-%d")
    p1_end = datetime.strptime(period1_end, "%Y-%m-%d")
    p2_start = datetime.strptime(period2_start, "%Y-%m-%d")
    p2_end = datetime.strptime(period2_end, "%Y-%m-%d")
    
    # Get data for both periods
    p1_threats = db.query(Threat).filter(
        Threat.created_at >= p1_start,
        Threat.created_at <= p1_end
    ).count()
    
    p2_threats = db.query(Threat).filter(
        Threat.created_at >= p2_start,
        Threat.created_at <= p2_end
    ).count()
    
    p1_incidents = db.query(Incident).filter(
        Incident.created_at >= p1_start,
        Incident.created_at <= p1_end
    ).count()
    
    p2_incidents = db.query(Incident).filter(
        Incident.created_at >= p2_start,
        Incident.created_at <= p2_end
    ).count()
    
    # Calculate changes
    threat_change = ((p2_threats - p1_threats) / p1_threats * 100) if p1_threats > 0 else 0
    incident_change = ((p2_incidents - p1_incidents) / p1_incidents * 100) if p1_incidents > 0 else 0
    
    return {
        "period_1": {
            "start": period1_start,
            "end": period1_end,
            "threats": p1_threats,
            "incidents": p1_incidents
        },
        "period_2": {
            "start": period2_start,
            "end": period2_end,
            "threats": p2_threats,
            "incidents": p2_incidents
        },
        "changes": {
            "threats_percentage_change": round(threat_change, 2),
            "incidents_percentage_change": round(incident_change, 2),
            "trend": "improving" if threat_change < 0 and incident_change < 0 else "worsening"
        }
    } 