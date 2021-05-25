from django.db import models

class User(models.Model):
    user_id=models.CharField(max_length=255,primary_key=True)
    user_password = models.CharField(max_length=255,null=False)
    user_email = models.CharField(max_length=255,null=False)
    collection_id = models.CharField(max_length=255,null=True)

    class Meta:
        db_table = 'user'

    def __str__(self):
        return self.user_id