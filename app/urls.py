from django.conf.urls import url, include
from rest_framework.routers import DefaultRouter
from rest_framework.urlpatterns import format_suffix_patterns
from app import views

urlpatterns = [
    url(r'^hello$', views.CSRFView.as_view(), name='csrf'),
    url(r'^posts$', views.PostList.as_view(), name='post-list'),
    url(r'^posts/(?P<pk>[0-9]+)$', views.PostDetail.as_view(), name='post-detail'),
    url(r'^comments$', views.CommentView.as_view(), name='comment'),
    url(r'^users$', views.UserList.as_view(), name='user-list'),
    url(r'^users/(?P<pk>[0-9]+)$', views.UserDetail.as_view(), name='user-detail'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', views.ActivateView.as_view(), name='activate'),
    url(r'^signup$', views.SignUpView.as_view(), name='signup'),
    url(r'^signin$', views.SignInView.as_view(), name='signin'),
    url(r'^signout$', views.SignOutView.as_view(), name='signout'),
]

urlpatterns = format_suffix_patterns(urlpatterns)
