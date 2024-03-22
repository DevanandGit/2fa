import io
from cryptography.fernet import Fernet
from django.http import JsonResponse
from django.core.mail import EmailMessage
import random


def generate_key_file(unique_id):
    unique_id = str(unique_id)
    key = Fernet.generate_key()
    # Encrypt the unique_id using the key
    fernet = Fernet(key)
    encrypted_id = fernet.encrypt(unique_id.encode())
    # Create an in-memory binary stream
    file_stream = io.BytesIO()
    # Write key and encrypted_id to the stream
    file_stream.write(key)
    file_stream.write(b'\n')
    file_stream.write(encrypted_id)
    # Move the stream cursor to the beginning
    file_stream.seek(0)
    # Read the content from the stream
    content = file_stream.read()
    return content


#function to send email
def send_email(data):
    email = EmailMessage(subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
    email.send()
    response_data = {'message': 'Email sent successfully!'}
    return JsonResponse(response_data)


#method to generate OTP
def otpgenerator():
    rand_no = [x for x in range(10)]
    code_items_for_otp = []
    for i in range(6):
        num = random.choice(rand_no)
        code_items_for_otp.append(num)
        code_string = "".join(str(item) for item in code_items_for_otp)
    return code_string


#method to validate OTP
def checkOTP(otp, saved_otp_instance):
    if saved_otp_instance.otp == otp:
        return True
    else:
        return False


#method to delete OTP
def deleteOTP(saved_otp_instance):
    saved_otp_instance.delete()
    

