
import json


def logToFile(strfilePathOut, strDataToLog, boolDeleteFile, strWriteMode):
    target = open(strfilePathOut, strWriteMode, encoding="utf-8")
    if boolDeleteFile == True:
      target.truncate()
    target.write(strDataToLog)
    target.close()   

def appendList(strlist, stritem):
    if strlist == "":
        strlist = stritem
    else:
        strlist = strlist +"^" + stritem
    return strlist

def isTID(strPotentialTID):
    if len(strPotentialTID) != 5:
        return False
    if strPotentialTID[:1] == "T":
        strEvalNum = strPotentialTID[1:5]
        if strEvalNum.isnumeric():
            return True
        else:
            return False
        

csvOutPath = "c:\\test\\MITREattack.csv"

with open('enterprise-attack.json') as json_file: #https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    data = json.load(json_file)
    for object in data['objects']:
        strName  = ""
        strTID = ""
        strDescription = ""
        strDataSources = ""
        strPlatforms = ""
        strKillchain = ""
        strDetection = ""
        strType = ""
        strPermissions = ""
        if 'name' in object:
            strName = object['name']
        
        if 'external_references' in object:
            for ereference in object['external_references']:
                if 'external_id' in ereference:
                    strTmpID= ereference['external_id']
                    if isTID(strTmpID):
                        strTID = strTmpID
        if strTID == "" and strName == "":
            continue
        strType = object['type']
        if (strType == 'identity' or strType == 'intrusion-set' or strType == 'malware') and strTID == "": #not a TID
            continue

        if 'x_mitre_deprecated' in object:
            if object['x_mitre_deprecated'] == True: #don't output deprecated techniques
                continue

        strDescription = object['description']
        
        if 'x_mitre_detection' in object:
            strDetection = object['x_mitre_detection']
            
        if 'kill_chain_phases' in object:
            strKillchain = appendList(strKillchain, object['kill_chain_phases'][0]['phase_name'])
                
                

        if 'x_mitre_data_sources' in object:
            for datasource in object['x_mitre_data_sources']:
                strDataSources = appendList(strDataSources,datasource)
        
        if 'x_mitre_platforms' in object:
            for platform in object['x_mitre_platforms']:
                strPlatforms = appendList(strPlatforms, platform)

        if 'x_mitre_permissions_required' in object:
            for permission in object['x_mitre_permissions_required']:
                strPermissions = appendList(strPermissions, permission)
        
        #remove new lines
        strDescription = strDescription.replace("\n", "\t")
        strDetection = strDetection.replace("\n", "\t")
        #build CSV
        outputLine = "\"" + strTID + "\"," + "\"" + strName + "\"," + "\"" + strPlatforms + "\"," + "\"" + strDataSources + "\"," + "\"" + strPermissions + "\"," + "\"" + strKillchain + "\"," + "\"" + strType + "\"," + "\"" + strDetection + "\"," + "\"" + strDescription + "\"" 
        #output CSV line
        logToFile(csvOutPath,outputLine + "\n", False, "a")