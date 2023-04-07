from django import forms
from .models import *

class GiverForm(forms.ModelForm):
    class Meta:
        model = Giver
        fields = ['firstname', 'profile_image']