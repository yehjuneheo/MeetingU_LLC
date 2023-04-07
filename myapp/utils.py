from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six


class EmailTokenGenerator(PasswordResetTokenGenerator):

    def _make_hash_value(self, user, timestamp):
        return (six.text_type(user.pk)+six.text_type(timestamp)+six.text_type(user.is_email_verified))


class ConfirmationTokenGenerator(PasswordResetTokenGenerator):

    def _make_hash_value(self, meeting, timestamp):
        return (six.text_type(meeting.pk)+six.text_type(timestamp)+six.text_type(meeting.is_confirmed))

generate_email_token = EmailTokenGenerator()
generate_confirmation_token = ConfirmationTokenGenerator()