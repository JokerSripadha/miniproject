from django import forms
from CheckUrl.models import UrlModel

class UrlForm(forms.ModelForm):
    class Meta:
        model = UrlModel
        fields = ("Url",)
