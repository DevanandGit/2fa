from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.views.generic import CreateView, TemplateView
from .forms import (UserRegistrationForm, UserLoginForm,
                    MessageForm, ChangePasswordForm, OtpVerificationForm)
from django.contrib.auth import authenticate, login, logout
from django.urls import reverse_lazy
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from .models import Message, CustomUser, Otp
from .utils import generate_key_file, send_email,otpgenerator
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
import uuid
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages

#On succesfull password change, user will redirect to this view
class Thankyou(TemplateView):
    template_name = 'thankyou.html'

#view for user registration. 
#After Redirection it will redirect to login page along with downloading a key.txt file. 
def user_reg(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            unique_id = user.unique_id
            if not unique_id:
                return HttpResponse(status=400)  # Return an appropriate HTTP response for error
            key_content = generate_key_file(unique_id=unique_id)
            key_response = HttpResponse(key_content, content_type='text/plain')
            key_response['Content-Disposition'] = 'attachment; filename="key.txt"'
            # Return the HttpResponse for download
            return render(request, 'download_and_redirect.html', {'key_response': key_response})
    else:
        form = UserRegistrationForm()
    return render(request, 'registration_form.html', {'form': form})


#login view
def user_login(request):
    form = UserLoginForm()  # Move the form definition outside the if-else block
    if request.method == 'POST':
        form = UserLoginForm(request.POST)  # Pass POST data to the form
        if form.is_valid():  # Check if the form is valid
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(username = username, password = password)
            if user is not None:
                login(request, user=user)
                return redirect('get_received_messages')
            else:
                form.add_error(None, 'Invalid login credentials')
    return render(request, 'login_form.html', {'form': form})

#logout view
@login_required(login_url='/user/user-login/')
def user_logout(request):
    if request.method == 'POST':
        user = request.user
        user.verified = False
        user.save()
        logout(request=request)
        return redirect(reverse('user_login'))
    return render(request, 'logout_form.html')

#view for sending message
@login_required(login_url='/user/user-login/')
def sent_message(request):
    form = MessageForm()
    if request.method == 'POST':
        form = MessageForm(request.POST)
        user = request.user
        if form.is_valid():
            sender = request.user
            recipient = form.cleaned_data['recipient']
            message = form.cleaned_data['message']
            Message.objects.create(sender=sender, recipient=recipient, message=message)
            messages.success(request, 'Message sent successfully!')
            #sent email on succesfull message
            email_subject = f"Received a message"
            email_body = f"You received a message from {user.first_name} {user.last_name}.\nHope phycial key is with you!"
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': email_subject}
            send_email(data)
            # Redirect to the same page to prevent form resubmission on refresh
            return redirect('sent_message')
    return render(request, 'send_message.html', {'form': form})


#This can be used by authenticator.py to check the key.txt and assign verification status to user
@csrf_exempt
def physical_key_authentication(request):
    if request.method == "POST":
        unique_id = request.POST.get('unique_id')
        authentication = request.POST.get('authentication')
        print(f"uniqueid is:{unique_id}")
        users = CustomUser.objects.get(unique_id=unique_id)
        if authentication == "success": 
            users.verified = True
            users.save()
        else:
            users.verified = False
            users.save()
        return JsonResponse({'data':'success'})
    return JsonResponse({'data':'error'})

#This view can be used for generating new key.txt, if existing key has lost.
#it check if user is otp verified, otherwise it ask the user to send an otp
#make an otp verification here.
@login_required(login_url='/user/user-login/')
def revoke_key_and_generate_new(request):
    user = request.user
    otp, _ = Otp.objects.get_or_create(user = user)
    if otp.otp_validated == True:
        if request.method == 'POST':
            user = request.user
            user.unique_id = None
            user.save()
            new_unique_id = uuid.uuid4()
            user.unique_id = new_unique_id
            user.save()
            unique_id = user.unique_id
            print(unique_id)
            key_content = generate_key_file(unique_id=unique_id)
            response = HttpResponse(content_type='text/plain')
            response['Content-Disposition'] = 'attachment; filename="key.txt"'
            response.write(key_content)
            otp.otp_validated = False
            otp.save() #make otp validate to false after key generation.
            return response
        return render(request, 'revoke_and_generate_new.html')
    else:
        if request.method == 'POST':
            user = request.user
            otp = otpgenerator()
            otp_instance, _ = Otp.objects.get_or_create(user=user)
            otp_instance.otp = otp
            otp_instance.otp_validated = False
            otp_instance.save()
            email_subject = f"OTP for Key Generation"
            email_body = f"Your OTP for key generation is {otp}"
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': email_subject}
            send_email(data)
            return redirect('otp_verification')
        return render(request, 'send_otp.html')

#user can verify the otp here
@login_required(login_url='/user/user-login/')
def verify_otp(request):
    form = OtpVerificationForm()
    if request.method == 'POST':
        user = request.user
        otp_instance, _ = Otp.objects.get_or_create(user=user)
        form = OtpVerificationForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']
            if otp == otp_instance.otp:
                otp_instance.otp_validated = True
                otp_instance.otp = None
                otp_instance.save()
                return redirect('revoke_and_generate')
            else:
                return render(request, 'incorrect_otp.html')  # Render a template for incorrect OTP
    return render(request, 'otp_verification.html', {'form': form})

#it is used to resend the otp to the user
@login_required(login_url='/user/user-login/')
def resend_otp(request):
    user = request.user
    otp_instance, _ = Otp.objects.get_or_create(user=user)
    otp = otpgenerator()  # Generate a new OTP
    otp_instance.otp = otp
    otp_instance.otp_validated = False
    otp_instance.save()
    
    email_subject = f"OTP for Key Generation"
    email_body = f"Your OTP for key generation is {otp}"
    data = {'email_body': email_body, 'to_email': user.email, 'email_subject': email_subject}
    send_email(data)
    
    return redirect('otp_verification')  # Redirect to the OTP verification page

#it shows the verification page for physical authentication. after successfull verification, redirect to get_received_message view.
@csrf_exempt
@login_required(login_url='/user/user-login/')
def show_message(request):
    if request.method == 'POST':
        try:
            user = request.user
            user = CustomUser.objects.get(username=user)
        except CustomUser.DoesNotExist:
            return JsonResponse({'data': 'User not found'})
        if user.verified is not None:
            if user.verified:
                return redirect('get_received_messages')
            else:
                user.verified = None
                user.save()
                return render(request, 'verification_template.html')
        else:
            # Show verification page.
            return render(request, 'verification_template.html')
    return render(request, 'verification_template.html')

#After succesfull physical authentication this view shows the messages a user received.
@login_required(login_url='/user/user-login/')
def get_received_messages(request):
    try:
        user = request.user
        user = CustomUser.objects.get(username=user)
    except CustomUser.DoesNotExist:
        return JsonResponse({'data': 'User not found'})
    if user.verified:
        received_messages = Message.objects.filter(recipient=user)
        user.verified = None
        user.save()
        return render(request, 'show_messages.html', {'received_messages': received_messages})
    else:
        # Show verification page.
        return render(request, 'verification_template.html')
    

#home view
@login_required(login_url='/user/user-login/')
def home(request):
    return render(request, 'home.html')

#view for show the unique_id of the user
@login_required(login_url='/user/user-login/')
def show_key(request):
    user = request.user
    unique_id = str(user.unique_id)
    return render(request, 'show_key.html', {'unique_id': unique_id})

#change password view
@login_required(login_url='/user/user-login/')
def change_password(request):
    if request.method == 'POST':
        form = ChangePasswordForm(request.POST)
        if form.is_valid():
            user = request.user
            print(user)
            old_password = form.cleaned_data['old_password']
            new_password = form.cleaned_data['new_password']
            print(old_password)
            print(new_password)
            # Check if the old password is correct
            if not user.check_password(old_password):
                print('password not changed')
                messages.error(request, 'Incorrect old password. Please try again.')
                return redirect(reverse('change_password'))
                
            if user.check_password(old_password):
                print('passwordchanged')
                user.set_password(new_password)
                user.save()
                update_session_auth_hash(request, user)
                return redirect(reverse('thankyou'))
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = ChangePasswordForm()
    return render(request, 'change_password.html', {'form': form})

#show all sended messages
@login_required(login_url='/user/user-login/')
def get_sended_messages(request):
    try:
        user = request.user
        user = CustomUser.objects.get(username=user)
    except CustomUser.DoesNotExist:
        return JsonResponse({'data': 'User not found'})
    sended_messages = Message.objects.filter(sender=user)
    return render(request, 'sended_messages.html', {'sended_messages': sended_messages})
