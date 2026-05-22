from django.db import models

# Create your models here.
from django.db.models import CASCADE


class ClientRegister_Model(models.Model):
    username = models.CharField(max_length=30)
    email = models.EmailField(max_length=30)
    password = models.CharField(max_length=10)
    phoneno = models.CharField(max_length=10)
    country = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=30)
    address = models.CharField(max_length=300)
    gender = models.CharField(max_length=30)

class detection_of_ongoing_cyber_attacks(models.Model):

    cve_id=models.CharField(max_length=300)
    vendor_project=models.CharField(max_length=300)
    product=models.CharField(max_length=300)
    threat_name=models.CharField(max_length=300)
    date_added=models.CharField(max_length=300)
    short_description=models.CharField(max_length=300)
    required_action=models.CharField(max_length=300)
    due_date=models.CharField(max_length=300)
    pub_date=models.CharField(max_length=300)
    cvss=models.CharField(max_length=300)
    cwe=models.CharField(max_length=300)
    Type=models.CharField(max_length=300)
    complexity=models.CharField(max_length=300)
    Prediction=models.CharField(max_length=300)


class cyber_threat_type_ratio(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)

class detection_accuracy(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)



