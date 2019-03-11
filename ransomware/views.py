from django.shortcuts import render, redirect
from ransomware import functions
from ransomware import models
import requests, os, subprocess
from bs4 import BeautifulSoup
import json


def index(request):
    return render(request, 'index.html')


def newRansomware(request):
    ransomwares = list(models.Ransomwares.objects.values('ransom_name'))
    parentslist = list(models.Ransomwares.objects.values('parent'))
    parents = []
    ransomlist = []
    for i in range(len(ransomwares)):
        ransomlist.append(ransomwares[i]['ransom_name'])
    for parent in parentslist:
        if parent['parent'] not in ransomlist:
            parents.append(parent['parent'])
    return render(request, 'ransomware.html', {'ransomlist':ransomlist, 'parentslist':parents})


def newSample(request):
    ransomlist = models.Ransomwares.objects.values('ransom_name')
    return render(request, 'sample.html', {'ransomlist':ransomlist})


def handle_sample(request):
    sha256 = request.POST.get('sha256') if request.POST.get('sha256') != '' else None
    if sha256 is not None:
        resp = requests.get('https://www.virustotal.com/en/file/'+sha256+'/analysis/12756494724/')
        soup = BeautifulSoup(resp.content, 'html.parser')
        os.chdir('C:\\Users\\Milad\\PycharmProjects\\ransomwares\\vxapi\\')
        ransom_name = request.POST.get('ransomname')
        hashes = functions.hash(soup)
        avs = functions.avs(soup, sha256)
        sections = functions.pe_secions(soup)
        hash = models.Samples(ransom_name=models.Ransomwares.objects.get(ransom_name=ransom_name), sha256=sha256,
                              ssdeep=hashes[0] if hashes[0] != '' else None,
                              authentihash=hashes[1] if hashes[1] != '' else None,
                              imphash=hashes[2] if hashes[2] != '' else None,
                              extension=request.POST.get('extension') if request.POST.get('extension') != '' else None,
                              wallettype=request.POST.get('wallettype') if request.POST.get('wallettype') != '' else None,
                              walletno=request.POST.get('walletno') if request.POST.get('walletno') != '' else None,
                              encryption=request.POST.get('encryption') if request.POST.get('encryption') != '' else None,
                              mutex=request.POST.get('mutex') if request.POST.get('mutex') != '' else None,
                              publickey=request.POST.get('publickey') if request.POST.get('publickey') != '' else None,
                              deckey=request.POST.get('deckey') if request.POST.get('deckey') != '' else None,
                              additional=request.POST.get('additional') if request.POST.get('additional') != '' else None)

        hash.save()
        antiviruses = models.AVs(sample_id=models.Samples.objects.get(sha256=sha256), avast=avs[0], bitdefender=avs[1],
                                 drweb=avs[2], emsisoft=avs[3], eset=avs[4], kasp=avs[5],
                                 symantec=avs[6], malwarebytes=avs[7])
        antiviruses.save()
        socials = {}
        s = request.POST.get('social_id') if request.POST.get('social_id') != '' else None
        if s is not None:
            first = s.split(',')
            for i in range(len(first)):
                socials[first[i].split(':')[0]] = first[i].split(':')[1]
        if request.POST.get('email') != '':
            email = models.Social(sample_id=models.Samples.objects.get(sha256=sha256),
                                 email=request.POST.get('email') if request.POST.get('email') != '' else None)
            email.save()
        elif request.POST.get('social_id') != '':
            ids = list(socials.keys())
            platform = list(socials.values())
            for i in range(len(ids)):
                social = models.Social(sample_id=models.Samples.objects.get(sha256=sha256),
                                       social_id=ids[i] if ids[i] != '' else None,
                                       platform=platform[i] if platform[i] != '' else None)
                social.save()
        elif request.POST.get('email') != '' and request.POST.get('social_id') != '':
            email = models.Social(sample_id=models.Samples.objects.get(sha256=sha256),
                                  email=request.POST.get('email') if request.POST.get('email') != '' else None)
            email.save()
            ids = list(socials.keys())
            platform = list(socials.values())
            for i in range(len(ids)):
                social = models.Social(sample_id=models.Samples.objects.get(sha256=sha256),
                                       social_id=ids[i] if ids[i] != '' else None,
                                       platform=platform[i] if platform[i] != '' else None)
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
                                    sec_name=secname[i] if secname[i] != '' else None,
                                    sec_hash=sechash[i] if sechash[i] != '' else None)
            section.save()
        times = functions.timestamps(soup)
        time = models.Times(sample_id=models.Samples.objects.get(sha256=sha256),
                            compiletime=times['Compilation timestamp'] if 'Compilation timestamp' in times else None,
                            firstsubmisison=times['First submission'] if 'First submission' in times else None)
        time.save()
        return render(request, 'index.html', {'msg':'All data saved to database successfully.'})
    else:
        hash = models.Samples(ransom_name=models.Ransomwares.objects.get(ransom_name=request.POST.get('ransomname')),
                              sha256=None,
                              extension=request.POST.get('extension') if request.POST.get('extension') != '' else None,
                              wallettype=request.POST.get('wallettype') if request.POST.get('wallettype') != '' else None,
                              walletno=request.POST.get('walletno') if request.POST.get('walletno') != '' else None,
                              encryption=request.POST.get('encryption') if request.POST.get('encryption') != '' else None,
                              mutex=request.POST.get('mutex') if request.POST.get('mutex') != '' else None,
                              publickey=request.POST.get('publickey') if request.POST.get('publickey') != '' else None,
                              deckey=request.POST.get('deckey') if request.POST.get('deckey') != '' else None,
                              additional=request.POST.get('additional') if request.POST.get('additional') != '' else None)
        hash.save()
        socials = {}
        s = request.POST.get('social_id') if request.POST.get('social_id') != '' else None
        if s is not None:
            first = s.split(',')
            for i in range(len(first)):
                socials[first[i].split(':')[0]] = first[i].split(':')[1]
        if request.POST.get('email') != '' and request.POST.get('social_id') != '':
            email = models.Social(sample_id=models.Samples.objects.get(sample=models.Samples.objects.order_by('sample').latest('sample').sample),
                                  email=request.POST.get('email') if request.POST.get('email') != '' else None)
            email.save()
            ids = list(socials.keys())
            platform = list(socials.values())
            for i in range(len(ids)):
                social = models.Social(sample_id=models.Samples.objects.get(sample=models.Samples.objects.order_by('sample').latest('sample').sample),
                                       social_id=ids[i] if ids[i] != '' else None,
                                       platform=platform[i] if platform[i] != '' else None)
                social.save()
        elif request.POST.get('email') != '':
            email = models.Social(sample_id=models.Samples.objects.get(sample=models.Samples.objects.order_by('sample').latest('sample').sample),
                                  email=request.POST.get('email') if request.POST.get('email') != '' else None)
            email.save()
        elif request.POST.get('social_id') != '':
            ids = list(socials.keys())
            platform = list(socials.values())
            for i in range(len(ids)):
                social = models.Social(sample_id=models.Samples.objects.get(sample=models.Samples.objects.order_by('sample').latest('sample').sample),
                                       social_id=ids[i] if ids[i] != '' else None,
                                       platform=platform[i] if platform[i] != '' else None)
                social.save()

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


def edit_ransomware(request, ransomname):
    ransom = models.Ransomwares.objects.filter(ransom_name=ransomname).first()
    ransdict = {'name':ransom.ransom_name, 'parent':ransom.parent, 'sibling':ransom.sibling, 'family':ransom.family,
                'platform':ransom.platform, 'similar':ransom.similar, 'isroot':ransom.isroot, 'attacktype':ransom.attacktype,
                'author':ransom.author, 'activitystart':ransom.activitystart, 'targetusers':ransom.targetusers,
                'additional':ransom.additional}
    return render(request, 'edit.html', {'ransom':ransdict})


def handle_edit(request, ransomname):
    models.Ransomwares.objects.filter(ransom_name=ransomname)\
        .update(ransom_name = request.POST.get('name'),
                parent = request.POST.get('parent'),
                family = request.POST.get('family'),
                sibling = request.POST.get('sibling'),
                similar = request.POST.get('similar'),
                author = request.POST.get('author'),
                platform = request.POST.get('platform'),
                isroot = request.POST.get('isroot'),
                attacktype = request.POST.get('attacktype'),
                activitystart = request.POST.get('activitystart'),
                targetusers = request.POST.get('targetusers'),
                additional = request.POST.get('additional'))

    return render(request, 'index.html', {'msg':'Data edited successfully.'})


def addransomware(request, ransomname):
    ransomwares = list(models.Ransomwares.objects.values('ransom_name'))
    parentslist = list(models.Ransomwares.objects.values('parent'))
    parents = []
    ransomlist = []
    for i in range(len(ransomwares)):
        ransomlist.append(ransomwares[i]['ransom_name'])
    for parent in parentslist:
        if parent['parent'] not in ransomlist:
            parents.append(parent['parent'])
    return render(request, 'ransomware.html', {'ransomlist':ransomlist, 'parentslist':parents, 'ransomname':ransomname})


def info(request, ransomname):
    ransom = models.Ransomwares.objects.filter(ransom_name=ransomname).first()
    dict = {'Ransomware' : ransom.ransom_name,
    'Parent' : ransom.parent,
    'Family' : ransom.family,
    'Sibling' : ransom.sibling,
    'Similar To' : ransom.similar,
    'Author' : ransom.author,
    'Platform' : ransom.platform,
    'Is Root?' : ransom.isroot,
    'Attack Type' : ransom.attacktype,
    'Activity Start' : ransom.activitystart,
    'Target Users' : ransom.targetusers,
    'Additional' : ransom.additional}
    dict1 = {k: v for k, v in dict.items() if v is not None and v is not ''}
    heads = dict1.keys()
    data = dict1.values()
    '''heads = ['ransom_name', 'parent', 'family', 'sibling', 'similar', 'author', 'platform',
             'isroot', 'attacktype', ' activitystart', 'targetusers', 'additional']
    data = [ransom.ransom_name, ransom.parent, ransom.family, ransom.sibling, ransom.similar,
            ransom.author, ransom.platform, ransom.isroot, ransom.attacktype,
            ransom.activitystart, ransom.targetusers, ransom.additional]
    for i in range(len(data)):
        if data[i] == '' or data[i] is None:
            data.pop(i)'''
    return render(request, 'info.html', {'heads':dict1, 'data':data, 'ransomname':ransom.ransom_name})