import smtplib
from email.message import EmailMessage

SENDER_EMAIL = "darshanpc2606@gmail.com"
APP_PASSWORD = "hoaiphonukmspdur"
RECIPIENT_EMAIL = "sivadarshan2270@gmail.com"

def send_alert_email(ip):
    msg = EmailMessage()
    msg.set_content(f"🚨 Rate limit exceeded from IP: {ip}")
    msg["Subject"] = "Firewall Alert: Rate Limit Triggered"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECIPIENT_EMAIL

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)
        print(f"Alert email sent for IP: {ip}")
    except Exception as e:
        print(f"Failed to send alert email: {e}")
