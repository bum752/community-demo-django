# from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework.reverse import reverse

from rest_framework import status
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework_jwt.authentication import JSONWebTokenAuthentication

from django.conf import settings
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_protect, csrf_exempt, ensure_csrf_cookie
from django.http import Http404, HttpResponse
from app.tokens import account_activation_token

from datetime import datetime
import re

from app.models import Post, Comment, User
from app.serializers import PostListSerializer, PostSerializer, CommentSerializer, UserSerializer, SignInSerializer, JSONWebTokenSerializer
from app.permissions import IsAuthenticatedAllowSafeMethod, IsOwnerOrReadOnly
# from app.jwt import obtain_token

jwt_response_payload_handler = settings.JWT_AUTH.get('JWT_RESPONSE_PAYLOAD_HANDLER')

# class JSONWebTokenAPIView(APIView):
#     def get_serializer_context(self):
#         return {
#             'request': self.request,
#             'view': self,
#         }
#
#     def get_serializer_class(self):
#         assert self.serializer_class is not None, (
#             "'%s' should either include a `serializer_class` attribute, "
#             "or override the `get_serializer_class()` method."
#             % self.__class__.__name__)
#         return self.serializer_class
#
#     def get_serializer(self, *args, **kwargs):
#         serializer_class = self.get_serializer_class()
#         kwargs['context'] = self.get_serializer_context()
#         return serializer_class(*args, **kwargs)
#
#     def post(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#
#         if serializer.is_valid():
#             user = serializer.object.get('user') or request.user
#             token = serializer.object.get('token')
#             response_data = jwt_response_payload_handler(token, user, request)
#             response = Response(response_data)
#             if settings.JWT_AUTH.get('JWT_AUTH_COOKIE'):
#                 expireation = datetime.utcnow() + settings.JWT_AUTH.get('JWT_EXPIRATION_DELTA')
#                 response.set_cookie(key=settings.JWT_AUTH.get('JWT_AUTH_COOKIE'), value=jwtToken, expires=expireation, httponly=True)
#             return response
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CSRFView(APIView):
    @method_decorator(ensure_csrf_cookie)
    def get(self, request, format=None):
        return Response()

class PostList(GenericAPIView):
    permission_classes = (IsAuthenticatedAllowSafeMethod, )
    serializer_class = PostListSerializer
    queryset = Post.objects.all()

    def get(self, request, format=None):
        page = request.GET.get('page')
        if page is None:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        category = request.GET.get('category')
        paginator = PageNumberPagination()
        if category is not None:
            posts = Post.objects.filter(category=category).order_by('-created')
        else:
            posts = Post.objects.all().order_by('-created')
        paginatedPosts = paginator.paginate_queryset(posts, request)
        serializer = PostListSerializer(paginatedPosts, many=True)
        return Response({
            'page': int(page),
            'length': posts.count(),
            'size': settings.REST_FRAMEWORK.get('PAGE_SIZE'),
            'results': serializer.data
        })

    @method_decorator(csrf_protect)
    def post(self, request, format=None):
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(owner=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PostDetail(GenericAPIView):
    permission_classes = (IsAuthenticatedAllowSafeMethod, IsOwnerOrReadOnly, )
    serializer_class = PostSerializer

    def get_object(self, pk):
        try:
            return Post.objects.get(pk=pk)
        except:
            raise Http404

    def get(self, request, pk, format=None):
        post = self.get_object(pk)
        serializer = PostSerializer(post)
        return Response(serializer.data)

    @method_decorator(csrf_protect)
    def put(self, request, pk, format=None):
        post = self.get_object(pk)
        self.check_object_permissions(self.request, post)

        if post.category != request.data.get('category'):
            return Response(status=status.HTTP_400_BAD_REQUEST)

        serializer = PostSerializer(post, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @method_decorator(csrf_protect)
    def delete(self, request, pk, format=None):
        post = self.get_object(pk)
        self.check_object_permissions(self.request, post)
        post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class CommentView(GenericAPIView):
    permission_classes = (IsAuthenticated, )
    serializer_class = CommentSerializer

    @method_decorator(csrf_protect)
    def post(self, request, format=None):
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(owner=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)

class UserList(APIView):
    permission_classes = (IsAdminUser, )
    def get(self, reuqest, format=None):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

class UserDetail(APIView):
    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except:
            raise Http404

    def get(self, request, pk, format=None):
        user = self.get_object(pk)
        serializer = UserSerializer(user)
        return Response(serializer.data)

class ActivateView(APIView):
    def get(self, request, uidb64, token, format=None):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except:
            user = None
        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)

class SignUpView(GenericAPIView):
    serializer_class = UserSerializer

    @method_decorator(csrf_protect)
    def post(self, request, format=None):
        """
        회원가입

        ---
        parameters:
        - username: string (필수)
        - email: email (필수)
        - password: string (필수)
        - department: string
        - enterYear: integer
        - github: string
        """
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            subject = 'UniDev 인증 메일입니다.'
            message = render_to_string('user_activate.html', {
                'user': user,
                'domain': get_current_site(request).domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode('utf-8'),
                'token': account_activation_token.make_token(user),
            })
            email = EmailMessage(subject, message, to=[user.email])
            email.send()

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SignInView(GenericAPIView):
    serializer_class = JSONWebTokenSerializer
    @method_decorator(csrf_protect)
    def post(self, request, format=None):
        regex = re.compile(r'(.ac.kr)$')
        if not regex.search(request.data.get('email')):
            return Response('Invalid email', status=status.HTTP_400_BAD_REQUEST)

        serializer = JSONWebTokenSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.object.get('user') or request.user
            token = serializer.object.get('token')
            # print(type(user), user)
            # print(type(token), token)
            # print(type(request), request)
            # response_data = jwt_response_payload_handler(token, user, request)
            # response = Response(response_data)
            response = Response()
            if settings.JWT_AUTH.get('JWT_AUTH_COOKIE'):
                expireation = datetime.utcnow() + settings.JWT_AUTH.get('JWT_EXPIRATION_DELTA')
                response.set_cookie(key=settings.JWT_AUTH.get('JWT_AUTH_COOKIE'), value=token, expires=expireation, httponly=True)
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # def post(self, request, format=None):
    #     """
    #     로그인
    #
    #     ---
    #     parameters:
    #     - name: email
    #       description: 이메일
    #       required: true
    #       type: email
    #       paramType: json
    #     - name: password
    #       description: 비밀번호
    #       required: true
    #       type: string
    #       paramType: form
    #     """
    #     try:
    #         email = request.data['email']
    #         password = request.data['password']
    #         user = User.objects.get(email=email)
    #         if user.check_password(password):
    #             if user.is_active:
    #                 jwtToken = obtain_token(user)
    #                 response = Response()
    #
    #                 if settings.JWT_AUTH.get('JWT_AUTH_COOKIE'):
    #                     expireation = datetime.utcnow() + settings.JWT_AUTH.get('JWT_EXPIRATION_DELTA')
    #                     response.set_cookie(key=settings.JWT_AUTH.get('JWT_AUTH_COOKIE'), value=jwtToken, expires=expireation, httponly=True)
    #                 return response
    #             else:
    #                 return Response(status=status.HTTP_400_BAD_REQUEST)
    #         else:
    #             return Response(status=status.HTTP_404_NOT_FOUND)
    #     except User.DoesNotExist:
    #         return Response(status=status.HTTP_404_NOT_FOUND)
    #     except KeyError:
    #         return Response(status=status.HTTP_400_BAD_REQUEST)

class SignOutView(APIView):
    def get(self, request, format=None):
        response = Response()
        response.delete_cookie('jwttoken')
        return response

# class MailView(APIView):
#     def post(self, request, format=None):
#         email = request.data['email']
#         if email is not None:
#             subject = 'Django를 통해 발송된 메일입니다.'
#             message = 'Google SMTP에서 발송되었습니다.'
#             mail = EmailMessage(subject, message, to=[email])
#             mail.send()
#             return Response(status=status.HTTP_200_OK)
#         else:
#             return Response(status=status.HTTP_400_BAD_REQUEST)
