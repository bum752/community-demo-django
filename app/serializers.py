from datetime import datetime
from django.contrib.auth import authenticate
from rest_framework import serializers
# from rest_framework_jwt.serializers import JSONWebTokenSerializer, jwt_payload_handler, jwt_encode_handler
from rest_framework_jwt.compat import PasswordField
from rest_framework_jwt.settings import api_settings
from app.models import Post, Comment, User

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

class CommentSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        model = Comment
        fields = ('id', 'post', 'content', 'owner', 'created', )

class PostListSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    owner = serializers.ReadOnlyField(source='owner.username')
    comments = serializers.IntegerField(source="comment.count", read_only=True)

    class Meta:
        model = Post
        fields = ('id', 'category', 'title', 'content', 'owner', 'created', 'comments')

class PostSerializer(serializers.HyperlinkedModelSerializer):
    id = serializers.IntegerField(read_only=True)
    owner = serializers.ReadOnlyField(source='owner.username')
    comment = CommentSerializer(many=True, read_only=True)

    def create(self, validated_data):
        return Post.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.title = validated_data.get('title', instance.title)
        instance.content = validated_data.get('content', instance.content)
        instance.save()
        return instance

    class Meta:
        model = Post
        fields = ('id', 'category', 'title', 'content', 'owner', 'created', 'comment')

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    post = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    comment = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    def to_internal_value(self, data):
        ret = super(UserSerializer, self).to_internal_value(data)
        return ret

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'major', 'enterYear', 'github', 'post', 'comment', )

class SignInSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    class Meta:
        model = User
        fields = ('email', 'password', )

class JSONWebTokenSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        super(JSONWebTokenSerializer, self).__init__(*args, **kwargs)

        self.fields['email'] = serializers.EmailField()
        self.fields['password'] = PasswordField(write_only=True)

    @property
    def object(self):
        return self.validated_data

    def validate(self, attrs):
        credentials = {
            'email': attrs.get('email'),
            'password': attrs.get('password')
        }

        if all(credentials.values()):
            user = authenticate(**credentials)

            if user:
                if user.is_active:
                    payload = jwt_payload_handler(user)

                    if api_settings.JWT_ALLOW_REFRESH:
                        payload['orig_iat'] = timegm(datetime.utcnow().utctimetuple())

                    return {
                        'token': jwt_encode_handler(payload),
                        'user': user
                    }
                else:
                    raise serializers.ValidationError('not activated')
            else:
                raise serializers.ValidationError('not valid')
        else:
            raise serializer.ValidationError('include email and password')
