from django.db import models

class UrlModel(models.Model):
    Url = models.CharField(max_length=200,null=True)
    SubD = models.TextField(max_length=10000,null=True)
    IPa = models.GenericIPAddressField(protocol='both',null=True)
    Region = models.CharField(max_length=200,null=True)
    Results = models.CharField(max_length=200,null=True)
