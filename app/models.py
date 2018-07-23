from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
# from django.contrib.auth.hashers import make_password
from django.utils import timezone
# from django.utils.translation import ugettext_lazy as _

class Post(models.Model):
    category = models.IntegerField(null=True)
    title = models.CharField(max_length=100)
    content = models.TextField()
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='post', on_delete=models.DO_NOTHING)
    # owner = models.ForeignKey(get_user_model(), null=True, related_name='post', on_delete=models.DO_NOTHING)
    created = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('created', )

class Comment(models.Model):
    post = models.ForeignKey('app.Post', related_name='comment', on_delete=models.DO_NOTHING)
    content = models.TextField()
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='comment', on_delete=models.DO_NOTHING)
    created = models.DateTimeField(auto_now=True)

class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None):
        if not email:
            raise ValueError(_('Users must have an email address'))
        user = self.model(email=self.normalize_email(email), username=username)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, last_name, first_name, password):
        user = self.create_user(email=email, username=username, password=password)
        user.is_staff = true
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    # id = models.IntegerField(primary_key=True)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=20, unique=True)
    major = models.CharField(max_length=30, null=True)
    enterYear = models.IntegerField(null=True)
    github = models.CharField(max_length=20, null=True)
    is_active = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELD = ['username', ]

    def __str__(self):
        return self.email

    # def get_full_name(self):
    #     return self.username
    #
    # def get_short_name(self):
    #     return self.username

    @property
    def is_staff(self):
        return self.is_superuser

    # get_full_name.short_description = ugettext_lazy('Full name')
