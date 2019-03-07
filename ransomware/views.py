from django.shortcuts import render, redirect
from ransomware import functions
from ransomware import models
import requests, os, subprocess
from bs4 import BeautifulSoup
import json


def index(request):
    return render(request, 'index.html')


def newRansomware(request):
    ransomlist = models.Ransomwares.objects.values('ransom_name')
    parentslist = models.Ransomwares.objects.values('parent')
    parents = []
    for parent in parentslist:
        for ransom in ransomlist:
            if parent['parent'] == ransom['ransom_name']:
                continue
        if parent['parent'] != '':
            parents.append(parent['parent'])
    return render(request, 'ransomware.html', {'ransomlist':ransomlist, 'parentslist':parents})


def newSample(request):
    ransomlist = models.Ransomwares.objects.values('ransom_name')
    return render(request, 'sample.html', {'ransomlist':ransomlist})


def handle_sample(request):
    sha256 = request.POST.get('sha256')
    resp = requests.get('https://www.virustotal.com/en/file/'+sha256+'/analysis/12756494724/')
    soup = BeautifulSoup(resp.content, 'html.parser')
    os.chdir('C:\\Users\\Milad\\PycharmProjects\\ransomwares\\vxapi\\')
    ransom_name = request.POST.get('ransomname')
    hashes = functions.hash(soup)
    avs = functions.avs(soup, sha256)
    sections = functions.pe_secions(soup)
    hash = models.Samples(ransom_name=models.Ransomwares.objects.get(ransom_name=ransom_name), sha256=sha256,
                          ssdeep=hashes[0] if hashes[0] != '' else '',
                          authentihash=hashes[1] if hashes[1] != '' else '',
                          imphash=hashes[2] if hashes[2] != '' else '',
                          extension=request.POST.get('extension') if request.POST.get('extension') != '' else '',
                          wallettype=request.POST.get('wallettype') if request.POST.get('wallettype') != '' else '',
                          walletno=request.POST.get('walletno') if request.POST.get('walletno') != '' else '',
                          encryption=request.POST.get('encryption') if request.POST.get('encryption') != '' else '',
                          mutex=request.POST.get('mutex') if request.POST.get('mutex') != '' else '',
                          publickey=request.POST.get('publickey') if request.POST.get('publickey') != '' else '',
                          deckey=request.POST.get('deckey') if request.POST.get('deckey') != '' else '',
                          platform=request.POST.get('platform') if request.POST.get('platform') != '' else '',
                          additional=request.POST.get('additional') if request.POST.get('additional') != '' else '')

    hash.save()
    antiviruses = models.AVs(sample_id=models.Samples.objects.get(sha256=sha256), avast=avs[0], bitdefender=avs[1],
                             drweb=avs[2], emsisoft=avs[3], eset=avs[4], kasp=avs[5],
                             symantec=avs[6], malwarebytes=avs[7])
    antiviruses.save()
    socials = {}
    s = request.POST.get('social_id')
    if s is not None:
        first = s.split(',')
        for i in range(len(first)):
            socials[first[i].split(':')[0]] = first[i].split(':')[1]
    if request.POST.get('email') != '':
        email = models.Social(sample_id=models.Samples.objects.get(sha256=sha256),
                             email=request.POST.get('email') if request.POST.get('email') != '' else '')
        email.save()
    elif request.POST.get('social_id') != '':
        ids = list(socials.keys())
        platform = list(socials.values())
        for i in range(len(ids)):
            social = models.Social(sample_id=models.Samples.objects.get(sha256=sha256),
                                   social_id=ids[i] if ids[i] != '' else '',
                                   platform=platform[i] if platform[i] != '' else '')
            social.save()
    elif request.POST.get('email') != '' and request.POST.get('social_id') != '':
        email = models.Social(sample_id=models.Samples.objects.get(sha256=sha256),
                              email=request.POST.get('email') if request.POST.get('email') != '' else '')
        email.save()
        ids = list(socials.keys())
        platform = list(socials.values())
        for i in range(len(ids)):
            social = models.Social(sample_id=models.Samples.objects.get(sha256=sha256),
                                   social_id=ids[i] if ids[i] != '' else '',
                                   platform=platform[i] if platform[i] != '' else '')
            social.save()
    p = subprocess.Popen(
        'python vxapi.py report_get_summary ' + sha256 + ':120',
        stdout=subprocess.PIPE)
    content = p.stdout.read().decode('utf-8')
    if '"message": "Failed to get summary. Possibly requested sample does not exist."' not in content:
        q = content[:-5]
        x = json.loads(q)
        hosts, domains, mitre = functions.hybrid_analysis(x)
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
    elif '"message": "Failed to get summary. Possibly requested sample does not exist."' in content:
        p = subprocess.Popen(
            'python vxapi.py report_get_summary ' + sha256 + ':100',
            stdout=subprocess.PIPE)
        content = p.stdout.read().decode('utf-8')
        q = content[:-5]
        x = json.loads(q)
        hosts, domains, mitre = functions.hybrid_analysis(x)
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
    secname = list(sections.keys())
    sechash = list(sections.values())
    for i in range(len(secname)):
        section = models.Sections(sample_id=models.Samples.objects.get(sha256=sha256),
                                sec_name=secname[i] if secname[i] != '' else '',
                                sec_hash=sechash[i] if sechash[i] != '' else '')
        section.save()
    times = functions.timestamps(soup)
    time = models.Times(sample_id=models.Samples.objects.get(sha256=sha256),
                        compiletime=times['Compilation timestamp'] if 'Compilation timestamp' in times else '',
                        firstsubmisison=times['First submission'] if 'First submission' in times else '')
    time.save()
    return render(request, 'index.html', {'msg':'All data saved to database successfully.'})


def handle_ransomware(request):
    ransom = models.Ransomwares(ransom_name=request.POST.get('name'), parent=request.POST.get('parent'),
                                family=request.POST.get('family'), similar=request.POST.get('similar'),
                                sibling=request.POST.get('sibling'), isroot=request.POST.get('isroot'),
                                author=request.POST.get('author'), attacktype=request.POST.get('attacktype'),
                                targetusers=request.POST.get('targetusers'), activitystart=request.POST.get('activitystart'),
                                additional=request.POST.get('additional'))
    ransom.save()
    return render(request, 'index.html', {'msg':'Ransomware added.'})