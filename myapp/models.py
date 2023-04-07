from django.db import models, connection
from django.contrib.auth.models import AbstractUser
from datetime import datetime

# Create your models here.
class User(AbstractUser):
    is_email_verified = models.BooleanField(default=False)
    is_mentor =  models.BooleanField(default=False)
    firstname = models.CharField(max_length=100)
    lastname = models.CharField(max_length=100)


class Giver(models.Model):
    firstname = models.CharField(max_length=100)
    lastname = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    gender  = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    university = models.CharField(max_length=100)
    major = models.CharField(max_length=100)
    minor = models.CharField(max_length=100, null=True)
    profile_image = models.ImageField(null=True, blank=True, upload_to="images/")
    resume = models.FileField(null=True, blank=True, upload_to="resumes/")
    linkedin = models.URLField(max_length=300, null=True)
    brief_introduction = models.CharField(max_length=10000)
    additional_information = models.CharField(max_length=10000, null=True)
    education_level = models.CharField(max_length=100)
    timezone = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    stripe_access_token = models.CharField(max_length=100)
    stripe_user_id = models.CharField(max_length=100)
    def __str__(self):
        temp = self.firstname + " / " + self.username + " / " + self.email
        return temp


class Receiver(models.Model):
    firstname = models.CharField(max_length=100)
    lastname = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    def __str__(self):
        temp = self.firstname + " / " + self.username + " / " + self.email
        return temp


class Meeting(models.Model):
    is_confirmed = models.BooleanField(default=False)
    is_completed = models.BooleanField(default=False)
    is_waiting_for_video =  models.BooleanField(default=False)
    is_video_uploaded = models.BooleanField(default=False)

    is_rejected = models.BooleanField(default=False)
    is_cancelled = models.BooleanField(default=False)

    giver = models.CharField(max_length=100)
    receiver = models.CharField(max_length=100)

    video = models.FileField(null=True, blank=True, upload_to="videos/")

    is_waiting_for_rating =  models.BooleanField(default=False)
    is_rating_submitted = models.BooleanField(default=False)
    stars = models.IntegerField(default=0)
    feedback = models.CharField(max_length=10000, null=True, blank=True)

    datetime = models.DateTimeField(default=datetime.now, blank=True)


class Universities(models.Model):
    name = models.CharField(max_length=100)
    def __str__(self):
         return self.name


class Product(models.Model):
    name = models.CharField(max_length=100)
    price = models.IntegerField(default=0)  # cents
    file = models.FileField(upload_to="product_files/", blank=True, null=True)
    url = models.URLField()

    def __str__(self):
        return self.name
    
    def get_display_price(self):
        return "{0:.2f}".format(self.price / 100)