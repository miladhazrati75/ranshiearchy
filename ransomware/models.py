from django.db import models


class Ransomwares(models.Model):
    ransom_name = models.CharField(primary_key=True, max_length=200)
    parent = models.CharField(max_length=200, null=True)
    sibling = models.CharField(max_length=200, null=True)
    family = models.CharField(max_length=200, null=True)
    similar = models.CharField(max_length=200, null=True)
    isroot = models.BooleanField(max_length=200, null=True)
    attacktype = models.CharField(max_length=200, null=True)
    author = models.CharField(max_length=200, null=True)


class Samples(models.Model):
    sample = models.IntegerField(primary_key=True)
    sha256 = models.CharField(max_length=200)
    ransom_name = models.ForeignKey(Ransomwares, on_delete=models.CASCADE)
    extension = models.CharField(max_length=200, null=True)
    wallettype = models.CharField(max_length=200, null=True)
    walletno = models.CharField(max_length=200, null=True)
    mutex = models.CharField(max_length=200, null=True)
    publickey = models.CharField(max_length=200, null=True)
    encryption = models.CharField(max_length=200, null=True)
    deckey = models.CharField(max_length=200, null=True)
    imphash = models.CharField(max_length=200, null=True)
    ssdeep = models.CharField(max_length=200, null=True)
    authentihash = models.CharField(max_length=200, null=True)


class AVs(models.Model):
    sample_id = models.ForeignKey(Samples, on_delete=models.CASCADE)
    avast = models.CharField(max_length=200, null=True)
    bitdefender = models.CharField(max_length=200, null=True)
    drweb = models.CharField(max_length=200, null=True)
    emsisoft = models.CharField(max_length=200, null=True)
    eset = models.CharField(max_length=200, null=True)
    kasp = models.CharField(max_length=200, null=True)
    symantec = models.CharField(max_length=200, null=True)
    malwarebytes = models.CharField(max_length=200, null=True)


class Network(models.Model):
    sample_id = models.ForeignKey(Samples, on_delete=models.CASCADE)
    ip = models.CharField(max_length=200, null=True)
    domain = models.CharField(max_length=200, null=True)


class Social(models.Model):
    sample_id = models.ForeignKey(Samples, on_delete=models.CASCADE)
    email = models.CharField(max_length=200, null=True)
    social_id = models.CharField(max_length=200, null=True)
    platform = models.CharField(max_length=200, null=True)


class Mitre(models.Model):
    sample_id = models.ForeignKey(Samples, on_delete=models.CASCADE)
    attack_id = models.CharField(max_length=200, null=True)
    tactic = models.CharField(max_length=200, null=True)
    technique = models.CharField(max_length=200, null=True)


class NoHA(models.Model):
    sample_id = models.ForeignKey(Samples, on_delete=models.CASCADE)
    sha256 = models.CharField(max_length=200)


class Sections(models.Model):
    sample_id = models.ForeignKey(Samples, on_delete=models.CASCADE)
    sec_name = models.CharField(max_length=20, null=True)
    sec_hash = models.CharField(max_length=32, null=True)


class Times(models.Model):
    sample_id = models.ForeignKey(Samples, on_delete=models.CASCADE)
    compiletime = models.CharField(max_length=10)
    firstsubmisison = models.CharField(max_length=10)
