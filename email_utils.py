import smtplib
import os
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
import security_config

# Configure Logger for observability
logger = logging.getLogger(__name__)

def _get_smtp_connection():
    """Helper to establish a secure SMTP connection with timeout."""
    if not security_config.is_email_configured():
        logger.warning("[Email] SMTP not fully configured. Skipping delivery.")
        return None
        
    try:
        # 10s timeout to prevent hanging the process
        server = smtplib.SMTP(security_config.SMTP_SERVER, security_config.SMTP_PORT, timeout=10)
        server.starttls()
        # Clean the password of spaces (common with Gmail App Passwords)
        clean_pass = security_config.SMTP_PASS.replace(" ", "")
        server.login(security_config.SMTP_USER, clean_pass)
        return server
    except Exception as e:
        logger.error(f"[Email] SMTP Connection Failed: {e}")
        return None

def send_email(to_email: str, subject: str, message: str, html_content: str = None):
    """Send a standard email. Never crashes the app."""
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f"Secure File System <{security_config.SMTP_USER}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(message, 'plain', 'utf-8'))
        if html_content:
            msg.attach(MIMEText(html_content, 'html', 'utf-8'))
            
        server = _get_smtp_connection()
        if not server:
            return False
            
        with server:
            server.send_message(msg)
            
        logger.info(f"[Email] Sent to {to_email}: {subject}")
        return True
    except Exception as e:
        logger.error(f"[Email] Delivery Error to {to_email}: {e}")
        return False

def send_email_with_qr(to_email: str, subject: str, message_text: str, qr_path: str, url_link: str):
    """Send email with an embedded QR code image. Never crashes the app."""
    try:
        msg = MIMEMultipart('related')
        msg['From'] = f"Secure File System <{security_config.SMTP_USER}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg_alternative = MIMEMultipart('alternative')
        msg.attach(msg_alternative)
        
        msg_alternative.attach(MIMEText(message_text, 'plain', 'utf-8'))
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="background: #f4f4f4; padding: 20px;">
                <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <h2 style="color: #6c63ff;">{subject}</h2>
                    <p>{message_text.replace(chr(10), '<br>')}</p>
                    <div style="text-align: center; margin: 20px 0;">
                        <p style="font-weight: bold; margin-bottom: 10px;">Scan to Access:</p>
                        <img src="cid:qrcode" alt="QR Code" style="width: 200px; height: 200px; border: 4px solid #333; border-radius: 8px;">
                    </div>
                    <div style="text-align: center; margin-top: 20px;">
                        <a href="{url_link}" style="display: inline-block; background: #6c63ff; color: white; text-decoration: none; padding: 12px 24px; border-radius: 5px; font-weight: bold;">Access Secure File directly</a>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 20px; font-size: 12px; color: #888;">
                    <p>Secured by Antigravity CSP System.</p>
                </div>
            </div>
        </body>
        </html>
        """
        msg_alternative.attach(MIMEText(html_content, 'html', 'utf-8'))
        
        # Attach QR Image
        if os.path.exists(qr_path):
            with open(qr_path, 'rb') as f:
                img_data = f.read()
            img = MIMEImage(img_data)
            img.add_header('Content-ID', '<qrcode>')
            img.add_header('Content-Disposition', 'inline', filename='qrcode.png')
            msg.attach(img)
            
        server = _get_smtp_connection()
        if not server:
            return False
            
        with server:
            server.send_message(msg)
            
        logger.info(f"[Email] QR sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"[Email] QR Delivery Error to {to_email}: {e}")
        return False

def send_alert_email(to_email: str, case_id: str, event_type: str, reason: str, forensics: dict):
    """Sends detailed forensic alert. Never crashes the app."""
    try:
        subject = f"Security Alert: {event_type} - {case_id[:8]}"
        msg = MIMEMultipart('alternative')
        msg['From'] = f"Secure File System <{security_config.SMTP_USER}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Plain Text Fallback
        text_body = f"""
        SECURITY ALERT
        ----------------
        Case ID: {case_id}
        Event: {event_type}
        Reason: {reason}
        
        FORENSICS:
        IP: {forensics.get('ip', 'Unknown')}
        Device: {forensics.get('device', 'Unknown')}
        OS/Browser: {forensics.get('ua_parsed', 'Unknown')}
        Location: {forensics.get('city', 'Unknown')}, {forensics.get('region', 'Unknown')}, {forensics.get('country', 'Unknown')}
        """
        msg.attach(MIMEText(text_body, 'plain', 'utf-8'))
        
        # HTML Content
        html_content = f"""
        <html>
        <body style="font-family: 'Courier New', monospace; background-color: #f0f0f0; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background: #fff; border: 1px solid #cc0000; border-top: 5px solid #cc0000; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
                <div style="background: #cc0000; color: white; padding: 15px; text-align: center;">
                    <h2 style="margin: 0; font-size: 24px;">⚠ SECURITY ALERT</h2>
                </div>
                
                <div style="padding: 20px;">
                    <p style="font-size: 16px;"><strong>Event:</strong> {event_type}</p>
                    <p style="color: #d63333; font-weight: bold; font-size: 18px;">Reason: {reason}</p>
                    
                    <table style="width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px;">
                        <tr style="background: #f8f8f8;">
                            <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Case ID</td>
                            <td style="padding: 10px; border: 1px solid #ddd;">{case_id}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Timestamp</td>
                            <td style="padding: 10px; border: 1px solid #ddd;">{forensics.get('timestamp')}</td>
                        </tr>
                        <tr style="background: #f8f8f8;">
                            <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Receiver Email</td>
                            <td style="padding: 10px; border: 1px solid #ddd;">{forensics.get('receiver_email', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">IP Address</td>
                            <td style="padding: 10px; border: 1px solid #ddd; font-family: monospace;">{forensics.get('ip')}</td>
                        </tr>
                        <tr style="background: #f8f8f8;">
                            <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Device</td>
                            <td style="padding: 10px; border: 1px solid #ddd;">{forensics.get('device')}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">OS / Browser</td>
                            <td style="padding: 10px; border: 1px solid #ddd;">{forensics.get('ua_parsed')}</td>
                        </tr>
                        <tr style="background: #f8f8f8;">
                            <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">Approx Location</td>
                            <td style="padding: 10px; border: 1px solid #ddd;">{forensics.get('city')}, {forensics.get('region')}, {forensics.get('country')}</td>
                        </tr>
                    </table>
                    
                    <div style="margin-top: 20px; font-size: 12px; color: #666; text-align: center;">
                        <p>This is an automated system message. Do not reply.</p>
                        <p>IP Geolocation by ip-api.com</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        msg.attach(MIMEText(html_content, 'html', 'utf-8'))
        
        server = _get_smtp_connection()
        if not server:
            return False
            
        with server:
            server.send_message(msg)
            
        logger.info(f"[Email] Alert sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"[Email] Alert Delivery Error to {to_email}: {e}")
        return False
