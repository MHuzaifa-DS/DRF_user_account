from rest_framework import serializers
from .models import User
from .utils import validate_strong_password , validate_email_domain
from django.contrib.auth import authenticate



class RegisterSerializers(serializers.ModelSerializer):
    password = serializers.CharField(write_only = True)
    class Meta:
        model  = User
        fields = '__all__'

    def validate_password(self,value):
        validate_strong_password(value)
        return value
    def validate_email(self, value):
        return validate_email_domain(value) or value

    def create(self,validated_data):
        return User.objects.create_user(**validated_data)
    
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required = True)
    password = serializers.CharField(required = True)

    def validate(self, data):
        user = authenticate(username = data['username'],password=data['password'])
        if user:
            data['user'] = user
            return data
        else:
            raise serializers.ValidationError("Invalid username or password")


class ProfileSerializer(serializers.ModelSerializer):
    profile_image = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'phone_number', 'profile_image']

