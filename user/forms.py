from django import forms
from .models import CustomUser, Message

#user registration form. renders the Customuser model
class UserRegistrationForm(forms.ModelForm):
    confirm_password = forms.CharField(max_length = 200, widget=forms.PasswordInput)
    password = forms.CharField(max_length = 200, widget=forms.PasswordInput)
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'username', 'email', 'password', 'confirm_password']
    
    def clean_confirm_password(self):
        password = self.cleaned_data.get('password')
        confirm_password = self.cleaned_data.get('confirm_password')
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords do not match")
        return confirm_password
    
#login form
class UserLoginForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        help_text="Enter Your E-mail")
    password = forms.CharField(max_length = 200, widget=forms.PasswordInput)


# Message form
class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ['recipient', 'message']

# form for password changing
class ChangePasswordForm(forms.Form):
    old_password = forms.CharField(max_length=200, widget=forms.PasswordInput)
    new_password = forms.CharField(max_length=200, widget=forms.PasswordInput)
    confirm_password = forms.CharField(max_length=200, widget=forms.PasswordInput)

    def clean_confirm_password(self):
        old_password = self.cleaned_data.get('old_password')
        new_password = self.cleaned_data.get('new_password')
        confirm_password = self.cleaned_data.get('confirm_password')

        if new_password and confirm_password and new_password != confirm_password:
            raise forms.ValidationError("New passwords do not match")
        return confirm_password
    
# OTP verification form
class OtpVerificationForm(forms.Form):
    otp = forms.CharField(max_length=200)