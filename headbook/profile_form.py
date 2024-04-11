from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField, URLField, validators
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

class ProfileForm(FlaskForm):
    username = StringField('Username', render_kw={'readonly': True})
    password = PasswordField('Password')
    password_again = PasswordField('Repeat Password')
    birthdate = DateField('Birth date', [validators.optional()])
    color = StringField('Favourite color')
    picture_url = URLField('Picture URL', [validators.url(), validators.optional()])
    about = TextAreaField('About')
    save = SubmitField('Save changes')

    def validate_password(self, field):
            # Check if the password field is not empty
            if field.data:
                # Apply password-related validators only if the password field is not empty
                if not self.password.data:
                    raise ValidationError("Password field is empty. Please enter your current password.")
                if not self.password_again.data:
                    raise ValidationError("Please repeat your new password.")
                if self.password.data != self.password_again.data:
                    raise ValidationError("Passwords must match.")
                if not (any(char.isdigit() for char in self.password.data) and any(not char.isalnum() for char in self.password.data)):
                    raise ValidationError("Password must contain at least one number and one special character.")

            # If password field is empty, allow saving changes without changing the password