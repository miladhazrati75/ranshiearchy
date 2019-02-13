from django.shortcuts import render
from ransomware import functions
from ransomware import models
import requests, os, subprocess
from bs4 import BeautifulSoup
import string


def index(request):
    return render(request, 'index.html')


def newRansomware(request):
    return render(request, 'ransomware.html')


def newSample(request):
    return render(request, 'sample.html')


def handle_sample(request):
    sha256 = request.POST.get('sha256')
    resp = requests.get('https://www.virustotal.com/en/file/'+sha256+'/analysis/12756494724/')
    os.chdir('C:\\Users\\Milad\\PycharmProjects\\ransomwares\\vxapi\\')
    p = subprocess.Popen(
        'python vxapi.py report_get_summary ' + sha256 + ':100',
        stdout=subprocess.PIPE)
    content = p.stdout.read().decode('utf-8')
    soup = BeautifulSoup(resp.content, 'html.parser')
    ransom_name = request.POST.get('ransomname')
    hashes = functions.hash(soup)
    avs = functions.avs(soup, sha256)

    hash = models.Samples(ransom_name=models.Ransomwares.objects.get(ransom_name=ransom_name), sha256=sha256,
                          ssdeep=hashes[0] if hashes[0] != '' else '' , authentihash=hashes[1] if hashes[1] != '' else '', imphash=hashes[2] if hashes[2] != '' else '')
    hash.save()

    antiviruses = models.AVs(sample_id=models.Samples.objects.get(sha256=sha256), avast=avs[0], bitdefender=avs[1], drweb=avs[2], emsisoft=avs[3], eset=avs[4], kasp=avs[5],
                             symantec=avs[6], malwarebytes=avs[7])
    antiviruses.save()

    if '"message": "Failed to get summary. Possibly requested sample does not exist."' not in content:
        all = []
        s = content.splitlines()
        for line in s:
            if not "]" in line:
                all.append(line)
        hosts, domains, mitre = functions.hybrid_analysis(all)
        if len(hosts) > 0:
            for i in range(len(hosts)):
                ips = models.Network(sample_id=models.Samples.objects.get(sha256=sha256), ip=hosts[i])
                ips.save()
        if len(domains) > 0:
            for i in range(len(domains)):
                domain = models.Network(sample_id=models.Samples.objects.get(sha256=sha256), domain=domains[i])
                domain.save()
        if len(mitre) > 0:
            for i in range(len(mitre)):
                mitres = models.Mitre(sample_id=models.Samples.objects.get(sha256=sha256), attack_id=mitre[i][0], tactic=mitre[i][1], technique=mitre[i][2])
                mitres.save()
    else:
        noha = models.NoHA(sample_id=models.Samples.objects.get(sha256=sha256), sha256=sha256)
        noha.save()
    return render(request, 'test.html', {'msg':'ok!'})


def handle_ransomware(request):
    ransom = models.Ransomwares(ransom_name=request.POST.get('name'))
    ransom.save()
    return render(request, 'test.html', {'msg':'Ransom'})