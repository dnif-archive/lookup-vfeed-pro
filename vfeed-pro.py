import os
import datetime
import yaml
import sqlite3
import tarfile
from boto3.session import Session

path = os.environ["WORKDIR"]

def execute():
    print ("hello the world!")

secondarypath = "/lookup_plugins/vfeed-pro/"

db_location = path + secondarypath + "vfeed.db"

yamlpath = path + secondarypath + "dnifconfig.yml"

with open(yamlpath, 'r') as ymlfile:
    cfg = yaml.safe_load(ymlfile)

access_key = cfg['lookup_plugin']['VF_ACCESS_KEY']
secret_key = cfg['lookup_plugin']['VF_SECRET_KEY']
plan_license = cfg['lookup_plugin']['VF_PLAN']
last_update = cfg['lookup_plugin']['VF_LAST_DB_UPDATE']
if last_update == "" or last_update == None:
    last_update = "2018-07-10 12:49"

def get_database():
    files = []
    try:
        session = Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        s3 = session.resource('s3')
        bucket = s3.Bucket(plan_license)

        for file in bucket.objects.all():
            files.append(file.key)
    except Exception as e:
        pass
    if len(files) > 0:
        try:
            for file in files:
                    update_file = file
            try:
                bucket.download_file(update_file, (path + secondarypath + update_file))
            except Exception as e:
                pass
            try:
                tar = tarfile.open((path + secondarypath + update_file), 'r:gz')
                tar.extractall(path=(path + secondarypath))
            except Exception as e:
                pass
            try:
                for file in os.listdir((path + secondarypath)):
                    if "tgz" in file or "update" in file:
                        os.remove((path + secondarypath + file))
                    else:
                        pass
            except Exception as e:
                pass
            cfg['lookup_plugin']['VF_LAST_DB_UPDATE'] = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
            with open(yamlpath, 'w') as ymlfile:
                yaml.dump(cfg, ymlfile, default_flow_style=False)
            connect_to_database()
        except Exception as e:
            pass

def connect_to_database():
    try:
        global c
        global conn
        conn = sqlite3.connect(db_location)
        c = conn.cursor()
    except Exception as e:
        print 'Database Error %s' %e

def initialize_database():
    if os.path.isfile(db_location) == True:
        now = datetime.datetime.now()
        last_update_date = datetime.datetime.strptime(last_update, "%Y-%m-%d %H:%M")
        if (now - last_update_date).days > 0:
            get_database()
        else:
            connect_to_database()
    else:
        get_database()

def validate_cve(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            try:
                orig_cve = i["$CVE"]
                cve = i[var_array[0]].upper()
                if (orig_cve[0:3]).upper() != "CVE":
                    cve  = "CVE-" + orig_cve
                if not 'CVE-' in cve:
                    cve = cve.replace('CVE', 'CVE-')
                if not '-' in cve[4:]:
                    cve = cve[0:8] + "-" + cve[8:]
                id = cve[9:]
                if len(id) <= 3:
                    zerosToAdd = 4 - len(id)
                    zeros = ""
                    m = 0
                    while(m < zerosToAdd):
                        zeros = zeros + "0"
                        m = m + 1
                    cve = cve[0:9] + zeros + str(id)
                i[var_array[0]] = cve
            except:
                pass
    return inward_array

def get_targets(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cpe_cve WHERE cve_id=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    targets = {}
                    targets = dict(i)
                    cpe22_id = data[0]
                    cpe23_id = data[1]
                    c.execute("SELECT title FROM cpe_db where cpe_id = ?", (cpe22_id,))
                    title = c.fetchone()
                    if title != None:
                        targets['$VFTargetsTitle'] = title[0]
                    targets.update({"$VFcpe2.2": cpe22_id, "$VFcpe2.3": cpe23_id})
                    if not targets in response:
                        response.append(targets)
            else:
                targets = dict(i)
                if not targets in response:
                    response.append(targets)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_cwe(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cwe_cve WHERE cve_id=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    cwe_id = data[0]
                    c.execute("SELECT title,link,class,relations FROM cwe_db WHERE cwe_id='%s' " % cwe_id)
                    cwe_data = c.fetchall()
                    if len(cwe_data) > 0:
                        for row in cwe_data:
                            title = row[0]
                            url = row[1]
                            cwe_class = row[2]
                            relationship = row[3]
                            weaknesses = {}
                            weaknesses = dict(i)
                            weaknesses.update({"$VFCWEid": cwe_id,
                                          "$VFCWEclass": cwe_class, "$VFCWEtitle": title,
                                          "$VFCWErelations": relationship, "$VFCWEurl": url})
                            if not weaknesses in response:
                                response.append(weaknesses)
                    else:
                        weaknesses = dict(i)
                        weaknesses['$VFCWEid'] = cwe_id
                        if not weaknesses in response:
                            response.append(weaknesses)
            else:
                weaknesses = dict(i)
                if not weaknesses in response:
                    response.append(weaknesses)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_capec(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cwe_cve WHERE cve_id=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    cwe_id = data[0]
                    c.execute("SELECT capec_id FROM cwe_db WHERE cwe_id='%s' AND capec_id <> '' " % cwe_id)
                    cwe_data = c.fetchall()
                    if len(cwe_data) > 0:
                        for row in cwe_data:
                            capec_ids = row[0]
                            for capec_id in capec_ids.split(','):
                                c.execute("SELECT title, link, attack_method, mitigations FROM capec_db WHERE capec_id='%s' " % capec_id)
                                capecrows = c.fetchall()
                                if len(capecrows) > 0:
                                    for data in capecrows:
                                        title = data[0]
                                        url = data[1]
                                        attack_methods = data[2]
                                        mitigations = data[3]
                                        capec = {"$VFCapecID": capec_id,
                                                 "$VFCapecTitle": title,
                                                 "$VFCapecAttackMethods": attack_methods,
                                                 "$VFCapecMitigations": mitigations,
                                                 "$VFCapecURL": url}
                                        capec.update(dict(i))
                                        capec.update({"$VFCweID":cwe_id})
                                        response.append(capec)
                                else:
                                    capec = dict(i)
                                    capec.update({"$VFCweID":cwe_id, "$VFCapecID":capec_id})
                                    if not capec in response:
                                        response.append(capec)
                    else:
                        capec = dict(i)
                        capec.update({"$VFCweID":cwe_id})
                        if not capec in response:
                            response.append(capec)
            else:
                capec = dict(i)
                if not capec in response:
                    response.append(capec)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_category(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cwe_cve WHERE cve_id=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    cwe_id = data[0]
                    c.execute("SELECT cwe_id,title,link,relations FROM cwe_db where class = 'category' and relations like ?", ('%' + cwe_id + '%',))
                    cwerows = c.fetchall()
                    if len(cwerows) > 0:
                        for cwedata in cwerows:
                            category_id = cwedata[0]
                            title = cwedata[1]
                            url = cwedata[2]
                            relations = cwedata[3].split(',')
                            category = {"$VFCategoryID": category_id, "$VFCategoryTitle": title, "$VFCategoryURL": url}
                            if cwe_id in relations:
                                category.update({"$VFCWEinRelations": "true"})
                            category.update(dict(i))
                            category.update({"$VFCweID":cwe_id})
                            if not category in response:
                                response.append(category)
                    else:
                        category = dict(i)
                        category.update({"$VFCweID":cwe_id})
                        if not category in response:
                            response.append(category)
            else:
                category = dict(i)
                if not category in response:
                    response.append(category)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_wasc(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cwe_cve WHERE cve_id=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    cwe_id = data[0]
                    c.execute("SELECT wasc_id,title,link FROM wasc_db WHERE cwe_id='%s' " % cwe_id)
                    wascrows = c.fetchall()
                    if len(wascrows) > 0:
                        for data in wascrows:
                            wasc_id = data[0]
                            title = data[1]
                            url = data[2]
                            wasc = {"$VFWascID": wasc_id, "$VFWascTitle": title, "$VFWascURL": url}
                            wasc.update(dict(i))
                            wasc.update({"$VFCweID":cwe_id})
                            response.append(wasc)
                    else:
                        wasc = dict(i)
                        wasc.update({"$VFCweID":cwe_id})
                        if not wasc in response:
                            response.append(wasc)
            else:
                wasc = dict(i)
                if not wasc in response:
                    response.append(wasc)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_attack_mitre(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM map_cwe_cve WHERE cve_id=?', (cve,))
            rows = c.fetchall()
            if len(rows) > 0:
                for data in rows:
                    cwe_id = data[0]
                    c.execute("SELECT capec_id FROM cwe_db WHERE cwe_id='%s' AND capec_id <> '' " % cwe_id)
                    cwe_data = c.fetchall()
                    if len(cwe_data) > 0:
                        for row in cwe_data:
                            capec_ids = row[0]
                            for capec_id in capec_ids.split(','):
                                c.execute("SELECT attack_mitre_id FROM capec_db WHERE capec_id='%s' " % capec_id)
                                id = c.fetchone()
                                if id and id[0] != '':
                                    c.execute("SELECT * FROM attack_mitre_db WHERE id='%s' " % id[0])
                                    mitrerows = c.fetchall()
                                    if len(mitrerows) > 0:
                                        for data in mitrerows:
                                            attack_mitre = {}
                                            try:
                                                if data[0]:
                                                    attack_mitre["$VFAttackID"] = data[0]
                                            except:
                                                pass
                                            try:
                                                if data[1]:
                                                    attack_mitre["$VFAttackProfile"] = data[1]
                                            except:
                                                pass
                                            try:
                                                if data[2]:
                                                    attack_mitre["$VFAttackName"] = data[2]
                                            except:
                                                pass
                                            try:
                                                if data[3]:
                                                    attack_mitre["$VFAttackDescription"] = data[3]
                                            except:
                                                pass
                                            try:
                                                if data[4]:
                                                    attack_mitre["VFAttackTactic"] = data[4]
                                            except:
                                                pass
                                            try:
                                                if data[5]:
                                                    attack_mitre["$VFAttackURL"] = data[5]
                                            except:
                                                pass
                                            try:
                                                if data[6]:
                                                    attack_mitre["$VFAttackFile"] = datal[6]
                                            except:
                                                pass
                                            attack_mitre.update(dict(i))
                                            attack_mitre.update({"$VFCweID":cwe_id, "$VFCapecID":capec_id})
                                            if not attack_mitre in response:
                                                response.append(attack_mitre)
                                    else:
                                        attack_mitre = dict(i)
                                        attack_mitre.update({"$VFMitreID":id[0], "$VFCweID":cwe_id, "$VFCapecID":capec_id})
                                        if not attack_mitre in response:
                                            response.append(attack_mitre)
                                else:
                                    attack_mitre = dict(i)
                                    attack_mitre.update({"$VFCweID":cwe_id, "$VFCapecID":capec_id})
                                    if not attack_mitre in response:
                                        response.append(attack_mitre)
                    else:
                        attack_mitre = dict(i)
                        attack_mitre.update({"$VFCweID":cwe_id})
                        if not attack_mitre in response:
                            response.append(attack_mitre)
            else:
                attack_mitre = dict(i)
                if not attack_mitre in response:
                    response.append(attack_mitre)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_advisory(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute("SELECT source FROM advisory_db GROUP BY source")
            sourcerows = c.fetchall()
            if len(sourcerows) > 0:
                for source in sourcerows:
                    source = source[0].strip()
                    c.execute("SELECT type,id,link FROM advisory_db WHERE source = '{0}' and cve_id=? ".format(source), (cve,))
                    advicerows = c.fetchall()
                    if len(advicerows) > 0:
                        for data in advicerows:
                            type = data[0]
                            id = data[1]
                            url = data[2]
                            advisory = {}
                            advisory = dict(i)
                            advisory.update({"$VFSource":source,"$VFPreventiveBulletinID": id, "$VFPreventiveBulletinClass": type, "$VFPreventiveBulletinURL": url})
                            response.append(advisory)
                    else:
                        advisory = dict(i)
                        advisory.update({"$VFSource":source})
                        if not advisory in response:
                            response.append(advisory)
            else:
                advisory = dict(i)
                if not advisory in response:
                    response.append(advisory)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_rules(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute("SELECT source FROM detection_db GROUP BY source")
            sourcerows = c.fetchall()
            if len(sourcerows) > 0:
                for source in sourcerows:
                    source = source[0].strip()
                    c.execute("SELECT id,class,title,link FROM detection_db WHERE source = '{0}' and cve_id=? ".format(source), (cve,))
                    rulesrows = c.fetchall()
                    if len(rulesrows) > 0:
                        for data in rulesrows:
                            id = data[0]
                            family = data[1]
                            title = data[2]
                            url = data[3]
                            rules = {}
                            rules = dict(i)
                            rules.update({"$VFSource":source,"$VFDetectiveRulesID": id, "$VFDetectiveRulesClass": family, "$VFDetectiveRulesURL": url,
                            "$VFDetectiveRulesTitle" : title})
                            response.append(rules)
                    else:
                        rules = dict(i)
                        rules.update({"$VFSource":source})
                        if not rules in response:
                            response.append(rules)
            else:
                rules = dict(i)
                if not rules in response:
                    response.append(rules)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_exploits(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute("SELECT source FROM exploits_db GROUP BY source")
            sourcerows = c.fetchall()
            if len(sourcerows) > 0:
                for source in sourcerows:
                    source = source[0].strip()
                    c.execute("SELECT id,title,file,link FROM exploits_db WHERE source = '{0}' and cve_id=? order by id".format(source), (cve,))
                    exploitsrows = c.fetchall()
                    if len(exploitsrows) > 0:
                        for data in exploitsrows:
                            id = data[0]
                            title = data[1]
                            file = data[2]
                            url = data[3]
                            exploits = {}
                            exploits = dict(i)
                            exploits.update({"$VFSource":source,"$VFExploitsID": id, "$VFExploitsTitle": title, "$VFExploitsURL": url,
                            "$VFExploitsFile" : file})
                            response.append(exploits)
                    else:
                        exploits = dict(i)
                        exploits.update({"$VFSource":source})
                        if not exploits in response:
                            response.append(exploits)
            else:
                exploits = dict(i)
                if not exploits in response:
                    response.append(exploits)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_information(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute("SELECT * FROM cve_db WHERE cve_id=?", (cve,))
            inforows = c.fetchall()
            if len(inforows) > 0:
                for inforow in inforows:
                    info = {}
                    info = dict(i)
                    info.update({"$CVEDatePublished": inforow[1], "$CVEDateModified": inforow[2],
                            "$CVESummary": inforow[3]})
                    response.append(info)
            else:
                info = dict(i)
                if not info in response:
                    response.append(info)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_references(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute("SELECT * FROM map_refs_cve WHERE cve_id=?", (cve,))
            refsrows = c.fetchall()
            if len(refsrows) > 0:
                for refsrow in refsrows:
                    vendor = refsrow[0]
                    url = refsrow[1]
                    ref = {}
                    ref = dict(i)
                    ref.update({"$CVEReferenceVendor": vendor, "$CVEURL": url})
                    response.append(ref)
            else:
                ref = dict(i)
                if not ref in response:
                    response.append(ref)
    if len(response) > 0:
        return response
    else:
        return inward_array

def keyword_to_cve(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            keyword = i[var_array[0]]
            c.execute("SELECT * FROM cve_db WHERE summary LIKE ?", ('%'+keyword+'%',))
            inforows = c.fetchall()
            if len(inforows) > 0:
                for inforow in inforows:
                    info = {}
                    info = dict(i)
                    info.update({"$CVE": inforow[0], "$CVEDatePublished": inforow[1], "$CVEDateModified": inforow[2],
                            "$CVESummary": inforow[3]})
                    response.append(info)
            else:
                info = dict(i)
                if not info in response:
                    response.append(info)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_remote_inspection_signatures(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute("SELECT source FROM scanners_db WHERE source NOT LIKE '%oval%' and cve_id=? GROUP BY source", (cve,))
            sourcerows = c.fetchall()
            if len(sourcerows) > 0:
                for sourcerow in sourcerows:
                    source = sourcerow[0].strip()
                    c.execute("SELECT id,family, name, file, link FROM scanners_db WHERE source = '{0}' and cve_id=? ".format(source), (cve,))
                    signrows = c.fetchall()
                    if len(signrows) > 0:
                        for data in signrows:
                            id = data[0]
                            family = data[1]
                            name = data[2]
                            file = data[3]
                            url = data[4]
                            signs = {}
                            signs = dict(i)
                            signs.update({"$VFSource":source,"$VFSignatureID": id,
                                    "$VFSignatureFamily": family, "$VFSignatureName": name,
                                    "$VFSignatureFile": file, "$VFSignatureURL": url})
                            response.append(signs)
                    else:
                        signs = dict(i)
                        signs.update({"$VFSource":source})
                        if not signs in response:
                            response.append(signs)
            else:
                signs = dict(i)
                if not signs in response:
                    response.append(signs)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_local_inspection_signatures(inward_array, var_array):
    response = []
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute("SELECT source FROM scanners_db WHERE source LIKE '%oval%' and cve_id=? GROUP BY source", (cve,))
            sourcerows = c.fetchall()
            if len(sourcerows) > 0:
                for sourcerow in sourcerows:
                    source = sourcerow[0].strip()
                    c.execute("SELECT id,family, name, file, link FROM scanners_db WHERE source = '{0}' and cve_id=? ".format(source), (cve,))
                    signrows = c.fetchall()
                    if len(signrows) > 0:
                        for data in signrows:
                            id = data[0]
                            family = data[1]
                            name = data[2]
                            file = data[3]
                            url = data[4]
                            signs = {}
                            signs = dict(i)
                            signs.update({"$VFSource":source,"$VFSignatureID": id,
                                    "$VFSignatureFamily": family, "$VFSignatureName": name,
                                    "$VFSignatureFile": file, "$VFSignatureURL": url})
                            response.append(signs)
                    else:
                        signs = dict(i)
                        signs.update({"$VFSource":source})
                        if not signs in response:
                            response.append(signs)
            else:
                signs = dict(i)
                if not signs in response:
                    response.append(signs)
    if len(response) > 0:
        return response
    else:
        return inward_array

def get_cvss2_score(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM cvss_scores WHERE cve_id=?', (cve,))
            cvssrow = c.fetchone()
            i['$VFCVSS2Base'] = cvssrow[0]
            i['$VFCVSS2Impact'] = cvssrow[1]
            i['$VFCVSS2Exploit'] = cvssrow[2]
            i['$VFCVSS2Vector'] = cvssrow[3]
            i['$VFCVSS2AccessVector'] = cvssrow[4]
            i['$VFCVSS2AccessComplexity'] = cvssrow[5]
            i['$VFCVSS2Authentication'] = cvssrow[6]
            i['$VFCVSS2ConfidentialityImpact'] = cvssrow[7]
            i['$VFCVSS2IntegrityImpact'] = cvssrow[8]
            i['$VFCVSS2AvailibilityImpact'] = cvssrow[9]
    return inward_array

def get_cvss3_score(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM cvss_scores WHERE cve_id=?', (cve,))
            cvssrow = c.fetchone()
            i['$VFCVSS3Base'] = cvssrow[10]
            i['$VFCVSS3Impact'] = cvssrow[11]
            i['$VFCVSS3Exploit'] = cvssrow[12]
            i['$VFCVSS3Vector'] = cvssrow[13]
            i['$VFCVSS3AccessVector'] = cvssrow[14]
            i['$VFCVSS3AccessComplexity'] = cvssrow[15]
            i['$VFCVSS3Authentication'] = cvssrow[16]
            i['$VFCVSS3ConfidentialityImpact'] = cvssrow[17]
            i['$VFCVSS3IntegrityImpact'] = cvssrow[18]
            i['$VFCVSS3AvailibilityImpact'] = cvssrow[19]
    return inward_array

def get_cvss_score(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            validate_cve(inward_array, var_array)
            cve = i[var_array[0]]
            c.execute('SELECT * FROM cvss_scores WHERE cve_id=?', (cve,))
            cvssrow = c.fetchone()
            i['$VFCVSS2Base'] = cvssrow[0]
            i['$VFCVSS2Impact'] = cvssrow[1]
            i['$VFCVSS2Exploit'] = cvssrow[2]
            i['$VFCVSS2Vector'] = cvssrow[3]
            i['$VFCVSS2AccessVector'] = cvssrow[4]
            i['$VFCVSS2AccessComplexity'] = cvssrow[5]
            i['$VFCVSS2Authentication'] = cvssrow[6]
            i['$VFCVSS2ConfidentialityImpact'] = cvssrow[7]
            i['$VFCVSS2IntegrityImpact'] = cvssrow[8]
            i['$VFCVSS2AvailibilityImpact'] = cvssrow[9]
            i['$VFCVSS3Base'] = cvssrow[10]
            i['$VFCVSS3Impact'] = cvssrow[11]
            i['$VFCVSS3Exploit'] = cvssrow[12]
            i['$VFCVSS3Vector'] = cvssrow[13]
            i['$VFCVSS3AccessVector'] = cvssrow[14]
            i['$VFCVSS3AccessComplexity'] = cvssrow[15]
            i['$VFCVSS3Authentication'] = cvssrow[16]
            i['$VFCVSS3ConfidentialityImpact'] = cvssrow[17]
            i['$VFCVSS3IntegrityImpact'] = cvssrow[18]
            i['$VFCVSS3AvailibilityImpact'] = cvssrow[19]
    return inward_array

initialize_database()
