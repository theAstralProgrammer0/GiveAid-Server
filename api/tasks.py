# api/tasks.py
from celery import shared_task
from django.core.mail import send_mail
from giveaid.models import UnregisteredDonation, UserDonation
import qrcode
from io import BytesIO
from django.core.files.base import ContentFile

@shared_task
def send_donation_receipt(donation_id):
    donation = UnregisteredDonation.objects.get(id=donation_id)
    img = qrcode.make(f"http://127.0.0.1:3000/", image_factory=qrcode.image.svg.SvgImage)
    buffer = BytesIO()
    img.save(buffer)
    qr_code_image = buffer.getvalue().decode()

    subject = 'Thank you for your donation'
    message = f"""
    Dear {donation.name},

    Thank you for your donation of {donation.amount} to {donation.cause}.

    Amount: {donation.amount}
    Cause: {donation.cause}

    Please use the QR code below to access our website:
    {qr_code_image}

    Regards,
    GiveAid Team
    """
    email_from = 'noreply@giveaid.com'
    recipient_list = [donation.email]
    send_mail(subject, message, email_from, recipient_list, fail_silently=False)
    # Save QR Code to the model if you want to
    donation.qr_code = qr_code_image
    donation.save()


