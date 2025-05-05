from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError


class ScanFileForm(forms.Form):
    contract_file = forms.FileField(
        label='Upload your contract file',
        widget=forms.FileInput(
            attrs={
                "class": "form-control",
                "accept": ".sol",
                "id": "formFile",

            }
        ),
        required=False)  # Make this optional initially

    contract_input = forms.CharField(
        label='Paste your contract code here',
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 3,
                "id": "textarea",
                "placeholder": "Enter...",
            }
        ),
        required=False)  # Make this optional initially

    def clean(self):
        cleaned_data = super().clean()
        contract_file = cleaned_data.get('contract_file')
        contract_input = cleaned_data.get('contract_input')

        if not contract_file and not contract_input:
            raise ValidationError(
                "Either upload a contract file or paste your contract code."
            )

        if contract_file and contract_input:
            raise ValidationError(
                "Please provide only one: either a contract file or contract code, not both."
            )

        return cleaned_data
