import string , os, subprocess, colorama



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
    hashes = []
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


def hybrid_analysis(sha256):
    os.chdir('C:\\Users\\Milad\\PycharmProjects\\ransomwares\\vxapi\\')
    p = subprocess.Popen(
        'python vxapi.py report_get_summary ' + sha256 + ':100',
        stdout=subprocess.PIPE)
    content = p.stdout.read().decode('utf-8')
    all = []
    hosts = []
    domains = []
    attck = []
    tactic = []
    technique = []
    s = content.splitlines()
    for line in s:
        if not "]" in line:
            all.append(line)
    for i in range(len(all)):
        if "compromised_hosts" in all[i]:
            i += 1
            while "]" and "[" not in all[i]:
                hosts.append(
                    all[i].replace(',', '').replace('"', '').translate({ord(c): None for c in string.whitespace}))
                i += 1
            break
    for i in range(len(all)):
        if "domains" in all[i]:
            i += 1
            while "]" and "[" and "environment_description" not in all[i]:
                domains.append(
                    all[i].replace(',', '').replace('"', '').translate({ord(c): None for c in string.whitespace}))
                i += 1
            break
    for i in range(len(all)):
        if "attck_id" in all[i]:
            if "https" not in all[i]:
                # i += 1
                attck.append(all[i].split(':')[1].replace('"', '').replace(',', '').translate(
                    {ord(c): None for c in string.whitespace}))
    for i in range(len(all)):
        if "tactic" in all[i]:
            # i += 1
            tactic.append(all[i].split(':')[1].replace('"', '').replace(',', '').translate(
                {ord(c): None for c in string.whitespace}))
    for i in range(len(all)):
        if "technique" in all[i]:
            # i += 1
            technique.append(all[i].split(':')[1].replace('"', '').replace(',', '').translate(
                {ord(c): None for c in string.whitespace}))
    complete = [[attck[i], tactic[i], technique[i]] for i in range(len(attck))]
    return hosts, domains, complete