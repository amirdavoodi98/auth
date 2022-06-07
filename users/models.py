import enum
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

class Enum(enum.Enum):
    @classmethod
    def choices(cls):
        return [(item.value, item.name) for item in cls]

    @classmethod
    def get_complete_choices(cls):
        return [(item.name, item.name) for item in cls]

class UserType(Enum):
    admin = "ADMIN"
    bankMnager = 'Bank_Manager'
    branchManager = 'Branch_Manager'
    employee = 'Employee'
    customer = 'Customer'

class UserManager(BaseUserManager):

    def create_user(self, username, password, mobile_number):
        if not username:
            raise ValueError(('The username must be set'))
        if not password:
            raise ValueError(('The password must be set'))
            
        user = self.model(username=username, mobile_number= mobile_number)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password):
        user = self.create_user(
        username=username,
        password=password,
        mobile_number = str("00000000000")
        )
        
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.user_type = UserType.admin.value
        user.save(using=self._db)
        return user


class User(AbstractUser):
    user_type = models.CharField(max_length=20, choices=UserType.choices(), default=UserType.customer.value)
    mobile_number = models.CharField(max_length=11, unique=True, null=False)