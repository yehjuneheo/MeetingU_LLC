from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.home, name='home'),
    path('selection', views.selection, name='selection'),
    
    path('login', views.login, name='login'),
    path('logout', views.logout_view, name='logout_view'),
    path('register', views.register, name='register'),
    path('register/register_teacher', views.register_teacher, name='register_teacher'),
    path('register/register_student', views.register_student, name='register_student'),
    path('agreement/', views.agreement_view, name="agreement"),
    path('register/authorize', views.StripeAuthorizeView.as_view(), name='authorize'),
    path('register/callback', views.StripeAuthorizeCallbackView.as_view(), name='authorize_callback'),

    path('reset_password', auth_views.PasswordResetView.as_view(template_name="password_reset.html"), name="reset_password"),
    path('reset_password_sent', auth_views.PasswordResetDoneView.as_view(template_name="password_reset_sent.html"), name="password_reset_done"),
    path('reset/<uidb64>/<token>', auth_views.PasswordResetConfirmView.as_view(template_name="password_reset_form.html"), name="password_reset_confirm"),
    path('reset_password_complete', auth_views.PasswordResetCompleteView.as_view(template_name="password_reset_done.html"), name="password_reset_complete"),

    path('search', views.search, name='search'),
    path('profile/<str:pk>', views.profile, name='profile'),
    
    path('profile/<str:pk>/product_landing', views.ProductLandingPageView.as_view(), name='landing-page'),
    path('profile/<str:pk>/create_checkout_session/<str:pk2>', views.CreateCheckoutSessionView.as_view(), name='create-checkout-session'),
    path('webhooks/stripe/', views.stripe_webhook, name='stripe-webhook'),
    path('profile/<str:pk>/cancel/<str:pk2>/', views.CancelView.as_view(), name='cancel'),
    path('profile/<str:pk>/success/<str:pk2>/', views.SuccessView.as_view(), name='success'),

    path('profile/<str:pk>/confirm_reservation', views.confirm_reservation, name='confirm_reservation'),
    path('profile/<str:pk>/confirm_reservation/confirmed', views.confirmed, name='confirmed'),
    path('activate-user<uidb64>/<token>', views.activate_user, name='activate'),
    path('confirm_meeting<uidb64>/<token>', views.confirm_meeting, name='confirm_meeting'),

    path('student_profile/<str:pk>', views.student_profile, name='student_profile'),
    path('student_profile/<str:pk>/student_meetings', views.student_meetings, name='student_meetings'),
    path('student_profile/<str:pk>/student_meetings/cancel_reservation/<str:pk2>', views.cancel_reservation, name='cancel_reservation'),
    path('student_profile/<str:pk>/student_meetings/cancel_reservation/<str:pk2>/cancelled', views.cancel_for_sure, name='cancel_for_sure'),
    path('student_profile/<str:pk>/student_meetings/submit_rating/<str:pk2>', views.submit_rating, name='submit_rating'),
    path('student_profile/<str:pk>/student_meetings/submit_rating/<str:pk2>/rating_upload_completed', views.rating_upload_completed, name='rating_upload_completed'),

    path('my_profile/<str:pk>', views.my_profile, name='my_profile'),
    path('my_profile/<str:pk>/my_meetings', views.my_meetings, name='my_meetings'),
    path('my_profile/<str:pk>/my_meetings/confirmation_successful/<str:pk2>', views.confirmation_successful, name='confirmation_successful'),
    path('my_profile/<str:pk>/my_meetings/reject_reservation/<str:pk2>', views.reject_reservation, name='reject_reservation'),
    path('my_profile/<str:pk>/my_meetings/reject_reservation/<str:pk2>/rejected', views.reject_for_sure, name='reject_for_sure'),
    path('my_profile/<str:pk>/my_meetings/upload_video/<str:pk2>', views.upload_video, name='upload_video'),
]
