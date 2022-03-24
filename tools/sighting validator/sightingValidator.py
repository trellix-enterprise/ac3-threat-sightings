#############
## Author: Jose Luis Sanchez Martinez - @Joseliyo_Jstnk
## Team: Trellix - AC3 Team
## Date: 2022-03-16
## Version: 1.0
#############
import yamale, argparse, yaml
from prettytable import PrettyTable

def convertYMLtoJSON(yFile):
  """
  Convert a YML file to JSON.
  """
  with open(yFile, "r", encoding="utf8") as y_file: 
    yDic = yaml.load(y_file, Loader=yaml.FullLoader)
  return yDic

def coreIdDuplicate(yPath):
  """
  This function is just the orchestrator to check for duplicate uuids.
  """
  fList = []
  data = convertYMLtoJSON(yPath)
  uuidList, behList, huntBehList = IDlistGenerator(data)
  idsVerificated = IDverificator(uuidList, yPath)
  fList.append(idsVerificated)
  idsHuntingVerificated = huntingBehaviorVerification(behList, huntBehList, yPath)
  fList.append(idsHuntingVerificated)

  return [item for sublist in fList for item in sublist] # List compression

def IDlistGenerator(data):
  """
  This function creates a simple list with all the ids of the threatSightings section, behavior section and threatHunting section.
  """
  uuidList = [] # Full uuid list
  behList = [] # List with the behavior IDs
  huntBehList = [] # List with the behavior IDs into the hunting queries
  for sighting in data["threatSightings"]:
    uuidList.append(sighting["id"])
    for behavior in sighting["behaviors"]:
      uuidList.append(behavior["id"])
      behList.append(behavior["id"])

  # We use try except because threatHunting field is not required
  try:
    for hunt in data["threatHunting"]:
      uuidList.append(hunt["queryId"])
      for huntId in hunt["behaviorIds"]:
        huntBehList.append(huntId)
  except KeyError as e:
    # The key threatHunting doesn't exists
    pass

  return uuidList, behList, huntBehList

def huntingBehaviorVerification(behList, huntBehList, sigh):
  """
  This function check if there is any behavior ID into the hunting section that doesn't exists in the sighting.
  """
  l_error = []
  for b in huntBehList:
    if b not in behList:
      l_error.append(["-", "BehaviorId in huntingQuery that does not exist in behavior section", b, sigh])
  return l_error

def IDverificator(uuidList, sigh):
  """
  This function checks for duplicate ids and creates the format to prettytable
  """
  comparation = []
  l_error = []
  for uuid in uuidList:
    if uuid in comparation:
      l_error.append(["-", "Duplicate uuid", uuid, sigh])
    else:
      comparation.append(uuid)
  return l_error

def yamaleValidator(yFile):
  """
  This function checks the format of the sighting with yamale
  """
  l_error = []
  schema = yamale.make_schema(content="""
header: include('head', required=True)
threatSightings: list(include('sightings'), min=1, max=250, required=True)
threatHunting: list(include('hunting'), max=50, required=False)
iocs: list(include('indicators'), max=100, required=False)
footer: include('foot', required=True)

---
head:
  sightingReportId: str(required=True)
  status: str(required=True)
  description: str(required=True)
  author: str(required=True)
  contributor: list(required=False)
  acknowledgement: str(required=True)
  tlp: str(required=True)
  threatInformation:
    adversaries: list(required=False)
    malware: list(required=True)
    lolbas: list(required=True)
    tools: list(required=True)
    regions: list(required=False)
    industries: list(required=False)

sightings:
    sighting: str(required=True)
    id: str(required=True)
    behaviors: list(include('behaviorsA'), min=1, max=500)

behaviorsA:
    behavior: str(required=True)
    id: str(required=True)
    type: str(required=True)
    weapon: str(required=True)
    notes: list(required=False)
    files: list(include('filesA'), required=False)
    registries: list(include('registryA'), required=False)
    services: list(include('servicesA'), required=False)
    connections: list(include('connectionsA'), required=False)
    scheduledTasks: list(include('scheduledTasksA'), required=False)
    modules: list(include('modulesA'), required=False)
    emails: list(include('emailsA'), required=False)
    processes: list(include('processesA'), required=False)
    accesors: list(include('accesorsA'), required=False)
    scripts: list(include('scriptsA'), required=False)
    pipes: list(include('pipesA'), required=False) 
    injections: list(include('injectionsA'), required=False) 
    drivers: list(include('driversA'), required=False) 
    users: list(include('usersA'), required=False) 
    wmi: list(include('wmiA'), required=False) 
    apis: list(include('apisA'), required=False) 
    att&ck: include('attack', required=False) 

filesA:
  name: str(required=True) 
  fileSize: int(required=False) 
  path: str(required=False) 
  ssdeep: str(required=False)
  fileType: str(required=False)
  sha256: str(required=False) 
  embedFilename: str(required=False) 
  extension: str(required=False) 
  vHash: str(required=False)
  process: str(required=False)
  issuerName: str(required=False)
  publickKeyHashcertificate: str(required=False)
  subject: str(required=False)
  certNotBefore: day(required=False)
  certNotAfter: day(required=False)
  sha1: str(required=False)

registryA:
  keyName: str(required=True) 
  keyValue: str(required=False) 
  keyValueType: str(required=False)
  keyValueName: str(required=False)
  keyNewName: str(required=False) 
  keyOldName: str(required=False) 
  keyNewValue: str(required=False) 
  keyOldValue: str(required=False) 
  process: str(required=False)

servicesA:
  name: str(required=True)
  path: str(required=True)
  process: str(required=False)

connectionsA:
  protocol: str(required=True)
  direction: str(required=True)
  srcIp: str(required=False)
  dstIp: str(required=False)
  srcMAC: str(required=False)
  dstMAC: str(required=False)
  srcHost: str(required=False)
  dstHost: str(required=False)
  srcPort: int(required=False)
  dstPort: int(required=False)
  url: str(required=False)
  method: str(required=False)
  userAgent: str(required=False)
  requestHeader: str(required=False)
  responseHeader: str(required=False)
  certIssuerName: str(required=False)
  certPublicKeyChecksum: str(required=False)
  certNotBefore: str(required=False)
  certNotAfter: str(required=False)
  dnsType: str(required=False)
  dnsClass: str(required=False)
  process: str(required=False)

scheduledTasksA:
  commands: str(required=True)
  name: str(required=True)
  process: str(required=False)

modulesA:
  moduleName: str(required=True)
  sha256: str(required=False)
  process: str(required=False)

emailsA:
  sender: str(required=True)
  date: str(required=False)
  from: str(required=False)
  subject: str(required=False)
  link: str(required=False)
  body: str(required=False)
  xHeaders: list(required=False)
  senderIP: str(required=False)
  replyTo: str(required=False)
  attachments: list(include('attachmentsA'), required=False)
  process: str(required=False)

attachmentsA:
  name: str(required=True)
  ssdeep: str(required=False)
  fileType: str(required=False)
  sha256: str(required=False)
  md5: str(required=False)
  embedFilename: str(required=False)
  path: str(required=False)
  fileSize: int(required=False)
  process: str(required=False)

processesA:
  process: str(required=True)
  cmdLine: list(required=True)
  sha256: str(required=False)
  integrity: str(required=False)
  embedFilename: str(required=False)
  parentProcess: str(required=False)
  parentIntegrity: str(required=False)

accesorsA:
  from: str(required=True)
  target: str(required=True)
  openPermission: str(required=False)
  process: str(required=False)

scriptsA:
  name: str(required=True)
  lines: str(required=True)
  length: int(required=False)
  process: str(required=False)

pipesA:
  name: str(required=True)
  instanceMode: enum("local", "remote", required=False)
  process: str(required=False)

injectionsA:
  from: str(required=True)
  target: str(required=True)
  injectionType: str(required=False)
  process: str(required=False)

driversA:
  driver: str(required=True)
  sha256: str(required=False)
  process: str(required=False)

usersA:
  user: str(required=True)
  logonProcessName: str(required=False)
  ipAddress: str(required=False)
  ipPort: str(required=False)
  workstationName: str(required=False)
  logonType: str(required=False)
  domain: str(required=False)
  process: str(required=False)

wmiA:
  operation: str(required=True)
  local: str(required=True)
  type: str(required=False)
  ess: str(required=False)
  evid: str(required=False)
  user: str(required=False)
  fqdn: str(required=False)
  process: str(required=False)

apisA:
  apiName: str(required=True)
  type: enum("usermode", "kernel", required=False)
  moduleName: str(required=False)
  process: str(required=False)

hunting:
  query: str(required=True)
  queryId: str(required=True)
  type: str(required=True)
  behaviorIds: list(required=True)
  logsource: any(required=False)
  detection: any(required=False) 
  link: str(required=False) 
  search: str(required=False)

indicators:
  behaviorIds: list(required=True)
  indicators: list(required=True)

foot:  
  changeTracking: 
    created: day(required=True)
    lastModified: day(required=True)
    sightingVersion: num(required=True)
    schemaVersion: num(required=True)
  references: list(required=True)

attack:
  initialAccess: list(required=False)
  reconnaissance: list(required=False)
  resourceDevelopment: list(required=False)
  execution: list(required=False)
  persistence: list(required=False)
  privilegeEscalation: list(required=False)
  defenseEvasion: list(required=False)
  credentialAccess: list(required=False)
  discovery: list(required=False)
  lateralMovement: list(required=False)
  collection: list(required=False)
  commandAndControl: list(required=False)
  exfiltration: list(required=False)
  impact: list(required=False)


""")

  with open(yFile, "r", encoding="utf8") as y_file: 
    data = yamale.make_data(content=y_file.read())

  try:
    yamale.validate(schema, data)
  except ValueError as e:
    # In case of schema error, we work with the list error generated by Yamale.
    for res in e.results:
      for error in res.errors:
        keyerr = error.split(":", 1)
        l_error.append(["-", keyerr[1], keyerr[0], yFile])

  return l_error

def checkSchemaVersion(yPath):
  data = convertYMLtoJSON(yPath)
  if data["footer"]["changeTracking"]["schemaVersion"] != 1.7:
    return False
  else:
    return True

def main():
  parser = argparse.ArgumentParser(description="Threat Sightings Validator - This script allows you to validate if your threat sighting has a correct structure or not.")
  parser.add_argument("-f", "--file", dest="input_file", required=False, default="None", help="YAML File that you want verify the schema")
  args = parser.parse_args()

  # PrettyTable definition and cols
  pTable = PrettyTable()
  pTable.field_names = ["GUID", "Error", "Key", "Sighting"]

  if args.input_file != "None":
    # Verification of the extension
    if args.input_file.endswith(".yml") or args.input_file.endswith(".yaml"):
      # Verification of the threat sighting schema version
      if checkSchemaVersion(args.input_file) == True:
        # Start the validation of the threat sighting file
        yamale_result = yamaleValidator(args.input_file)
        pTable.add_rows(yamale_result)
        # Check the required fields
        idDuplicates = coreIdDuplicate(args.input_file)
        pTable.add_rows(idDuplicates)
      else:
        print("[*] You are using an unsupported version of threat sightings. This script is supports 1.7 version or higher. Use -h parameter to get information about the script.")
    else:
      print("[*] Only .yml or .yaml extension supported. Use -h parameter to get information about the script.")
  else:
    print("[*] Please, use -f parameter to validate a YAML File. Use -h parameter to get information about the script.")

  print(pTable)
  
if __name__ == '__main__':
  main()