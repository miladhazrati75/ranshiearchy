import string, os, subprocess, colorama, json



def avs(soup, sha256):
    title = ['Avast', 'BitDefender', 'DrWeb', 'Emsisoft', 'ESET-NOD32', 'Kaspersky', 'Symantec', 'Malwarebytes']
    avs_signs = []
    x = soup.select('td')
    for name in title:
        for td in x:
            if name in td.text:
                avs_signs.append(td.find_next('td').text.translate({ord(c): None for c in string.whitespace}))
                break
    return avs_signs


def hash(soup):
    title = ['ssdeep', 'authentihash', 'imphash']
    x = soup.select('div.enum')
    hashes =['','','']
    for name in title:
        for div in x:
            if name in div.text:
                if name == 'ssdeep':
                    hashes[0] = div.text.replace(name, '').translate({ord(c): None for c in string.whitespace})
                    break
                if name == 'authentihash':
                    hashes[1] = div.text.replace(name, '').translate({ord(c): None for c in string.whitespace})
                    break
                if name == 'imphash':
                    hashes[2] = div.text.replace(name, '').translate({ord(c): None for c in string.whitespace})
                    break
    return hashes


def hybrid_analysis(content):
    attck = []
    tactic = []
    technique = []
    hosts = content['hosts'] 
    domains = content['domains']
    mitre = content['mitre_attcks']
    for i in range(len(mitre)):
        attck.append(mitre[i]['attck_id'])
        tactic.append(mitre[i]['tactic'])
        technique.append(mitre[i]['technique'])
    complete = [[attck[i], tactic[i], technique[i]] for i in range(len(attck))]
    return hosts, domains, complete


def pe_secions(soup):
    sections = ['.text', '.data', '.rsrc', '.reloc', '.rdata', '.idata', '.edata', '.pdata']
    secdict = {}
    x = soup.select('div.enum')
    for name in sections:
        for span in x:
            if name in span.text:
                secdict[name] = span.text.translate({ord(c): None for c in string.whitespace})[-32:]
    return secdict


def timestamps(soup):
    title = ['Compilation timestamp', 'First submission']
    x = soup.select('span.field-key')
    times = {}
    for name in title:
        for span in x:
            if name in span.text:
                times[name] = span.parent.text.replace(name, '').translate(
                    {ord(c): None for c in string.whitespace})[:10]
    return times