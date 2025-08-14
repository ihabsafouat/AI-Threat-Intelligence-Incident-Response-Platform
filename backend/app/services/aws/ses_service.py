"""
SES Service Module

Handles email notifications using Amazon SES for threat intelligence alerts.
"""

import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import logging

from .config import AWSConfig

logger = logging.getLogger(__name__)


class SESService:
    """Amazon SES Service for email notifications"""
    
    def __init__(self, config: AWSConfig, from_email: Optional[str] = None):
        """
        Initialize SES service.
        
        Args:
            config: AWS configuration
            from_email: Default sender email address
        """
        self.config = config
        self.from_email = from_email or 'threat-intel@example.com'
        self.ses_client = config.get_client('ses')
    
    def send_email(
        self,
        to_addresses: List[str],
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        from_address: Optional[str] = None,
        reply_to_addresses: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Send an email using SES.
        
        Args:
            to_addresses: List of recipient email addresses
            subject: Email subject
            body_text: Plain text email body
            body_html: HTML email body (optional)
            from_address: Sender email address
            reply_to_addresses: Reply-to email addresses
            
        Returns:
            Email sending result dictionary
        """
        try:
            email_params = {
                'Source': from_address or self.from_email,
                'Destination': {
                    'ToAddresses': to_addresses
                },
                'Message': {
                    'Subject': {
                        'Data': subject,
                        'Charset': 'UTF-8'
                    },
                    'Body': {
                        'Text': {
                            'Data': body_text,
                            'Charset': 'UTF-8'
                        }
                    }
                }
            }
            
            if body_html:
                email_params['Message']['Body']['Html'] = {
                    'Data': body_html,
                    'Charset': 'UTF-8'
                }
            
            if reply_to_addresses:
                email_params['ReplyToAddresses'] = reply_to_addresses
            
            response = self.ses_client.send_email(**email_params)
            
            logger.info(f"Successfully sent email to {to_addresses}")
            
            return {
                'success': True,
                'message_id': response['MessageId'],
                'to_addresses': to_addresses,
                'subject': subject
            }
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return {'success': False, 'error': str(e)}
    
    def send_threat_alert(
        self,
        to_addresses: List[str],
        threat_data: Dict[str, Any],
        alert_type: str = 'new_threat',
        severity: str = 'medium'
    ) -> Dict[str, Any]:
        """
        Send a threat intelligence alert email.
        
        Args:
            to_addresses: List of recipient email addresses
            threat_data: Threat intelligence data
            alert_type: Type of alert (new_threat, update, critical)
            severity: Alert severity
            
        Returns:
            Alert sending result dictionary
        """
        try:
            threat_id = threat_data.get('threat_id', 'Unknown')
            threat_type = threat_data.get('threat_type', 'Unknown')
            description = threat_data.get('description', 'No description available')
            
            # Create subject line
            severity_emoji = {
                'low': '🟢',
                'medium': '🟡',
                'high': '🟠',
                'critical': '🔴'
            }.get(severity.lower(), '⚪')
            
            subject = f"{severity_emoji} Threat Alert: {threat_type} - {threat_id}"
            
            # Create plain text body
            body_text = f"""
Threat Intelligence Alert

Threat ID: {threat_id}
Type: {threat_type}
Severity: {severity.upper()}
Alert Type: {alert_type.replace('_', ' ').title()}

Description: {description}

Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

Additional Details:
{json.dumps(threat_data, indent=2)}

This is an automated alert from the Threat Intelligence Platform.
Please review and take appropriate action if necessary.
            """.strip()
            
            # Create HTML body
            body_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Threat Intelligence Alert</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; }}
        .alert {{ border-left: 4px solid {self._get_severity_color(severity)}; padding: 10px; margin: 10px 0; }}
        .details {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .footer {{ color: #6c757d; font-size: 12px; margin-top: 20px; }}
        .severity-high {{ color: #dc3545; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
    </style>
</head>
<body>
    <div class="header">
        <h2>{severity_emoji} Threat Intelligence Alert</h2>
    </div>
    
    <div class="alert">
        <h3>Threat Details</h3>
        <p><strong>Threat ID:</strong> {threat_id}</p>
        <p><strong>Type:</strong> {threat_type}</p>
        <p><strong>Severity:</strong> <span class="severity-{severity.lower()}">{severity.upper()}</span></p>
        <p><strong>Alert Type:</strong> {alert_type.replace('_', ' ').title()}</p>
        <p><strong>Description:</strong> {description}</p>
        <p><strong>Timestamp:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
    
    <div class="details">
        <h4>Additional Details</h4>
        <pre>{json.dumps(threat_data, indent=2)}</pre>
    </div>
    
    <div class="footer">
        <p>This is an automated alert from the Threat Intelligence Platform.</p>
        <p>Please review and take appropriate action if necessary.</p>
    </div>
</body>
</html>
            """
            
            return self.send_email(
                to_addresses=to_addresses,
                subject=subject,
                body_text=body_text,
                body_html=body_html
            )
            
        except Exception as e:
            logger.error(f"Failed to send threat alert: {e}")
            return {'success': False, 'error': str(e)}
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        color_map = {
            'low': '#28a745',
            'medium': '#ffc107',
            'high': '#fd7e14',
            'critical': '#dc3545'
        }
        return color_map.get(severity.lower(), '#6c757d')
    
    def send_daily_report(
        self,
        to_addresses: List[str],
        report_data: Dict[str, Any],
        date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Send a daily threat intelligence report.
        
        Args:
            to_addresses: List of recipient email addresses
            report_data: Daily report data
            date: Report date (defaults to today)
            
        Returns:
            Report sending result dictionary
        """
        try:
            if not date:
                date = datetime.now(timezone.utc)
            
            subject = f"Daily Threat Intelligence Report - {date.strftime('%Y-%m-%d')}"
            
            # Create plain text body
            body_text = f"""
Daily Threat Intelligence Report
Date: {date.strftime('%Y-%m-%d')}

Summary:
- Total Threats: {report_data.get('total_threats', 0)}
- New Threats: {report_data.get('new_threats', 0)}
- Critical Threats: {report_data.get('critical_threats', 0)}
- High Severity: {report_data.get('high_severity', 0)}
- Medium Severity: {report_data.get('medium_severity', 0)}
- Low Severity: {report_data.get('low_severity', 0)}

Threat Types:
{self._format_threat_types_text(report_data.get('threat_types', {}))}

Top Sources:
{self._format_sources_text(report_data.get('top_sources', []))}

Recent Alerts:
{self._format_alerts_text(report_data.get('recent_alerts', []))}

This report was generated automatically by the Threat Intelligence Platform.
            """.strip()
            
            # Create HTML body
            body_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Daily Threat Intelligence Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #007bff; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .section {{ margin: 20px 0; }}
        .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #e9ecef; border-radius: 3px; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #dee2e6; padding: 8px; text-align: left; }}
        th {{ background-color: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Daily Threat Intelligence Report</h1>
        <p>Date: {date.strftime('%Y-%m-%d')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="metric">Total Threats: {report_data.get('total_threats', 0)}</div>
        <div class="metric">New Threats: {report_data.get('new_threats', 0)}</div>
        <div class="metric critical">Critical: {report_data.get('critical_threats', 0)}</div>
        <div class="metric high">High: {report_data.get('high_severity', 0)}</div>
        <div class="metric medium">Medium: {report_data.get('medium_severity', 0)}</div>
        <div class="metric low">Low: {report_data.get('low_severity', 0)}</div>
    </div>
    
    <div class="section">
        <h3>Threat Types</h3>
        {self._format_threat_types_html(report_data.get('threat_types', {}))}
    </div>
    
    <div class="section">
        <h3>Top Sources</h3>
        {self._format_sources_html(report_data.get('top_sources', []))}
    </div>
    
    <div class="section">
        <h3>Recent Alerts</h3>
        {self._format_alerts_html(report_data.get('recent_alerts', []))}
    </div>
    
    <div class="footer">
        <p>This report was generated automatically by the Threat Intelligence Platform.</p>
    </div>
</body>
</html>
            """
            
            return self.send_email(
                to_addresses=to_addresses,
                subject=subject,
                body_text=body_text,
                body_html=body_html
            )
            
        except Exception as e:
            logger.error(f"Failed to send daily report: {e}")
            return {'success': False, 'error': str(e)}
    
    def _format_threat_types_text(self, threat_types: Dict[str, int]) -> str:
        """Format threat types for text email."""
        if not threat_types:
            return "No threat types data available"
        
        lines = []
        for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- {threat_type}: {count}")
        
        return '\n'.join(lines)
    
    def _format_threat_types_html(self, threat_types: Dict[str, int]) -> str:
        """Format threat types for HTML email."""
        if not threat_types:
            return "<p>No threat types data available</p>"
        
        html = "<table><tr><th>Threat Type</th><th>Count</th></tr>"
        for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True):
            html += f"<tr><td>{threat_type}</td><td>{count}</td></tr>"
        html += "</table>"
        
        return html
    
    def _format_sources_text(self, sources: List[Dict[str, Any]]) -> str:
        """Format sources for text email."""
        if not sources:
            return "No sources data available"
        
        lines = []
        for source in sources[:10]:  # Top 10 sources
            lines.append(f"- {source.get('source', 'Unknown')}: {source.get('count', 0)}")
        
        return '\n'.join(lines)
    
    def _format_sources_html(self, sources: List[Dict[str, Any]]) -> str:
        """Format sources for HTML email."""
        if not sources:
            return "<p>No sources data available</p>"
        
        html = "<table><tr><th>Source</th><th>Count</th></tr>"
        for source in sources[:10]:  # Top 10 sources
            html += f"<tr><td>{source.get('source', 'Unknown')}</td><td>{source.get('count', 0)}</td></tr>"
        html += "</table>"
        
        return html
    
    def _format_alerts_text(self, alerts: List[Dict[str, Any]]) -> str:
        """Format alerts for text email."""
        if not alerts:
            return "No recent alerts"
        
        lines = []
        for alert in alerts[:5]:  # Top 5 alerts
            lines.append(f"- {alert.get('threat_id', 'Unknown')}: {alert.get('description', 'No description')}")
        
        return '\n'.join(lines)
    
    def _format_alerts_html(self, alerts: List[Dict[str, Any]]) -> str:
        """Format alerts for HTML email."""
        if not alerts:
            return "<p>No recent alerts</p>"
        
        html = "<table><tr><th>Threat ID</th><th>Description</th><th>Severity</th></tr>"
        for alert in alerts[:5]:  # Top 5 alerts
            severity = alert.get('severity', 'unknown')
            html += f"<tr><td>{alert.get('threat_id', 'Unknown')}</td><td>{alert.get('description', 'No description')}</td><td class='severity-{severity.lower()}'>{severity.upper()}</td></tr>"
        html += "</table>"
        
        return html
    
    def verify_email_identity(self, email_address: str) -> Dict[str, Any]:
        """
        Verify an email address with SES.
        
        Args:
            email_address: Email address to verify
            
        Returns:
            Verification result dictionary
        """
        try:
            self.ses_client.verify_email_identity(
                EmailAddress=email_address
            )
            
            logger.info(f"Verification email sent to {email_address}")
            
            return {
                'success': True,
                'email_address': email_address,
                'message': 'Verification email sent'
            }
            
        except Exception as e:
            logger.error(f"Failed to verify email identity: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_send_quota(self) -> Dict[str, Any]:
        """
        Get SES sending quota information.
        
        Returns:
            Quota information dictionary
        """
        try:
            response = self.ses_client.get_send_quota()
            
            return {
                'success': True,
                'max_24_hour_send': response['Max24HourSend'],
                'sent_last_24_hours': response['SentLast24Hours'],
                'max_send_rate': response['MaxSendRate'],
                'sending_enabled': response.get('SendingEnabled', False)
            }
            
        except Exception as e:
            logger.error(f"Failed to get send quota: {e}")
            return {'success': False, 'error': str(e)} 