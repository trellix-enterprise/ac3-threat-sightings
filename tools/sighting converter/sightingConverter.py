#############
## Author: Jose Luis Sanchez Martinez - @Joseliyo_Jstnk
## Team: Trellix - AC3 Team
## Date: 2022-03-21
## Version: 1.0
#############

import yaml, json, argparse, re, csv
from ioc_writer import ioc_api
from stix2 import Indicator, Malware, IPv4Address, URL, File, DomainName, Directory, WindowsRegistryKey, Relationship, Bundle, ThreatActor, Tool, AttackPattern, Malware, parse

def convertYMLtoJSON(yFile):
  """
  Just convert a YML file to JSON an returns it.
  """ 
  with open(yFile, "r", encoding="utf8") as y_file: 
    yDic = yaml.load(y_file, Loader=yaml.FullLoader)
  return yDic

def main(cfg, args):
	data = convertYMLtoJSON(args.input_file)

	if args.input_stats == True:
		# Create statistics file of the threat sighting
		res = createStatistics(data)

	if args.attack == True:
		# Create MITRE navigator layer
		attack(data, cfg)

	if args.input_weapon != 'None':
		# Print in the terminal all the behaviors related to the weapon selected
		x = getBehaviorsByWeapon(args.input_weapon, data, cfg)

	if args.input_ioc == True:
		# Create openioc file
		iocs = createOpenIOC(data)

	if args.input_stix_low == True:
		# Create stix low level file
		iocs = createSTIXLow(data)

	if args.input_stix_high == True:
		# Create stix high stix file
		iocs = createSTIXHigh(data)

	if args.input_maltego_high == True:
		# Create maltego high level file
		createMaltegoHigh(data)

	if args.input_maltego_low == True:
		# Create maltego low level file
		createMaltegoLow(data)

def createMaltegoLow(data):
	"""
		This method creates a csv file to be used in Maltego. The information is for low level analyst.
		The csv will contain adversaries and iocs with their behaviors and weapons
	"""
	adversaries = getAdversaries(data, False)
	behaviors = getBehaviors(data, False)

	with open("tsOutcome_maltegoLowLevel.csv", "w", encoding="utf8") as out:
		header = ["adversaries", "behaviors", "weapons", "iocs"]
		writer = csv.writer(out)
		writer.writerow(header)

		for behavior in behaviors:
			newRow = []
			newRow.append(' & '.join(adversaries))
			newRow.append(behavior["behavior"])
			newRow.append(behavior["weapon"])
			if not data.get("iocs"):
				print("[+] There is no 'iocs' key in the threat sighting to generate the maltego low level view")
				return False
			else:
				for i in data["iocs"]:
					for behaviorIOCId in i["behaviorIds"]:
						if behavior["id"] == behaviorIOCId:
							for indicator in i["indicators"]:
								for k,v in indicator.items():
									newRow = []
									newRow.extend([' & '.join(adversaries), behavior["behavior"], behavior["weapon"], v])
									writer.writerow(newRow)

	print("[+] tsOutcome_maltegoLowLevel.csv generated")
	return True

def createMaltegoHigh(data):
	"""
		This method creates a csv file to be used in Maltego. The information is for high level analyst.
		The csv will contain adversaries, behaviors, weapon related to the behaviors and MITRE tactics/techniques 
	"""
	adversaries = getAdversaries(data, False)
	behaviors = getBehaviors(data, False)
	techniques = getTechniques(data)
	tactics = getTactics(data)
	with open("tsOutcome_maltegoHighLevel.csv", "w", encoding="utf8") as out:
		header = ["adversaries", "behaviors", "weapons", "techniques", "tactics"]
		writer = csv.writer(out)
		writer.writerow(header)

		for behavior in behaviors:
			try:
				for tac,techs in behavior["att&ck"].items():
					if len(techs) > 1: 
						# More than 1 technique in the same tactic
						for tech in techs:
							newRow = []
							newRow.extend([' & '.join(adversaries), behavior["behavior"], behavior["weapon"], tech, tac])
							writer.writerow(newRow)
					else:
						# only one technique in the tactic
						newRow = []
						newRow.extend([' & '.join(adversaries), behavior["behavior"], behavior["weapon"], techs[0], tac])
						writer.writerow(newRow)
			except:
				# No ATT&CK in the behavior
				newRow = []
				newRow.extend([' & '.join(adversaries), behavior["behavior"], behavior["weapon"]])
				writer.writerow(newRow)

	print("[+] tsOutcome_maltegoHighLevel.csv generated")
	return True

def createListObject(sdo):
	"""
		This method creates a list of SDO Objects
	"""
	if sdo["type"] == "relationship":
		return {"name": "%s-%s"%(sdo["source_ref"],sdo["target_ref"]), "type": "%s"%(sdo["type"]), "id": "%s"%(sdo["id"]), "object": "%s"%(parse(sdo))}
	else:
		return {"name": "%s"%(sdo["name"]), "type": "%s"%(sdo["type"]), "id": "%s"%(sdo["id"]), "object": "%s"%(parse(sdo))}

def getObjectByName(name, objects):
	"""
		This method obtains an object by his name
	"""
	for obj in objects:
		if obj["name"] == name:
			return obj["object"]

def createSTIXHigh(data):
	"""
		This method creates STIX High level file with lolbas, malware, adversaries, behaviors and MITRE tactics/techniques
	"""
	sdoObjects, listStix, uniqueNames = [], [], []
	SDOAdversariesList = threatActorSTIX(getAdversaries(data, False))
	SDOToolsList = toolSTIX(getTools(data, False))
	SDOMalwaresList = malwareSTIX(getMalwares(data, False))
	SDOLolbasList = toolSTIX(getLolbas(data, False))
	SDOAttackPatternTechniqueList = attackPatternSTIX(getTechniques(data))
	SDOAttackPatternTacticList = attackPatternSTIX(getTactics(data))
	behaviorsList = getBehaviors(data, False)

	for lolbas in SDOLolbasList: sdoObjects.append(createListObject(lolbas)), uniqueNames.append(lolbas["id"]) if lolbas["id"] not in uniqueNames else False
	for malware in SDOMalwaresList: sdoObjects.append(createListObject(malware)), uniqueNames.append(malware["id"]) if malware["id"] not in uniqueNames else False
	for tool in SDOToolsList: sdoObjects.append(createListObject(tool)), uniqueNames.append(tool["id"]) if tool["id"] not in uniqueNames else False
	for adversary in SDOAdversariesList: sdoObjects.append(createListObject(adversary)), uniqueNames.append(adversary["id"]) if adversary["id"] not in uniqueNames else False
	for technique in SDOAttackPatternTechniqueList: sdoObjects.append(createListObject(technique)), uniqueNames.append(technique["id"]) if technique["id"] not in uniqueNames else False
	for tactic in SDOAttackPatternTacticList: sdoObjects.append(createListObject(tactic)), uniqueNames.append(tactic["id"]) if tactic["id"] not in uniqueNames else False

	for adversary in SDOAdversariesList:
		for tool in SDOToolsList: sdoObjects.append(createListObject(sroSTIX(adversary, tool, "uses")))
		for malware in SDOMalwaresList: sdoObjects.append(createListObject(sroSTIX(adversary, malware, "uses")))
		for lolbas in SDOLolbasList: sdoObjects.append(createListObject(sroSTIX(adversary, lolbas, "uses")))

	for behavior in behaviorsList:
		for obj in sdoObjects:
			if behavior["weapon"] == obj["name"]:
				for obj2 in sdoObjects:
					if behavior.get("att&ck"):
						for k,v in behavior["att&ck"].items():
							try:
								if obj2["name"] == v[0].split("-")[0].strip():
									sdoObjects.append(createListObject(sroSTIX(parse(obj["object"]), parse(obj2["object"]), "uses")))
								if obj2["name"] == k:
									tech = getObjectByName(v[0].split("-")[0].strip(), sdoObjects)
									sdoObjects.append(createListObject(sroSTIX(parse(tech), parse(obj2["object"]), "uses")))
							except:
								pass

	for obj in sdoObjects:
		listStix.append(json.loads(obj["object"]))

	with open("tsOutcome_STIX_highLevel.json", "w", encoding="utf8") as out:
		out.write(json.dumps(listStix, default=str, indent=4))

	print("[+] tsOutcome_STIX_highLevel.json file generated")
	return True

def threatActorSTIX(adversaries):
	"""
		Parse the adversaries key to convert it to STIX
	"""
	adversariesList = []
	for adv in adversaries: adversariesList.append(ThreatActor(name="%s"%(adv))) if len(adversaries) >= 1 else adversariesList.append(ThreatActor(name="%s"%(adversaries[0])))
	return adversariesList

def toolSTIX(tools):
	"""
		Parse the tool key to convert it to STIX
	"""
	toolList = []
	for tool in tools: toolList.append(Tool(name="%s"%(tool))) if len(tools) >= 1 else toolList.append(Tool(name="%s"%(tools[0])))
	return toolList

def malwareSTIX(malwares):
	"""
		Parse the malware key to convert it to STIX
	"""
	malwareList = []
	for malware in malwares: malwareList.append(Malware(name="%s"%(malware), is_family=True)) if len(malwares) >= 1 else malwareList.append(Malware(name="%s"%(malwares[0]), is_family=True))
	return malwareList

def attackPatternSTIX(techniques):
	"""
		Parse tactics and techniques to convert it to STIX
	"""
	attackPatternList = []
	if type(techniques) == dict:
		for k,v in techniques.items(): attackPatternList.append(AttackPattern(name="%s"%(k)))
	else:
		return AttackPattern(name="%s"%(techniques))
	return attackPatternList

def createSTIXLow(data):
	"""
		This method creates STIX low level file with lolbas, malware, adversaries, behaviors and iocs
	"""
	sdoObjects, listStix, uniqueNames = [], [], []
	SDOAdversariesList = threatActorSTIX(getAdversaries(data, False))
	SDOToolsList = toolSTIX(getTools(data, False))
	SDOMalwaresList = malwareSTIX(getMalwares(data, False))
	SDOLolbasList = toolSTIX(getLolbas(data, False))
	behaviorsList = getBehaviors(data, False)

	for lolbas in SDOLolbasList: sdoObjects.append(createListObject(lolbas)), uniqueNames.append(lolbas["id"]) if lolbas["id"] not in uniqueNames else False
	for malware in SDOMalwaresList: sdoObjects.append(createListObject(malware)), uniqueNames.append(malware["id"]) if malware["id"] not in uniqueNames else False
	for tool in SDOToolsList: sdoObjects.append(createListObject(tool)), uniqueNames.append(tool["id"]) if tool["id"] not in uniqueNames else False
	for adversary in SDOAdversariesList: sdoObjects.append(createListObject(adversary)), uniqueNames.append(adversary["id"]) if adversary["id"] not in uniqueNames else False

	for adversary in SDOAdversariesList:
		for tool in SDOToolsList: sdoObjects.append(createListObject(sroSTIX(adversary, tool, "uses")))
		for malware in SDOMalwaresList: sdoObjects.append(createListObject(sroSTIX(adversary, malware, "uses")))
		for lolbas in SDOLolbasList: sdoObjects.append(createListObject(sroSTIX(adversary, lolbas, "uses")))

	if data.get("iocs"):
		for i in data["iocs"]:
			for indicator in i["indicators"]:
				for k,v in indicator.items():
					stixType = mappingSightingPatternSTIX(k)
					sdoObjects.append(createListObject(indicatorSTIX(stixType, v)))
					for behaviorIOCId in i["behaviorIds"]:
						for behavior in behaviorsList:
							if behavior["id"] == behaviorIOCId:
								weapon = getObjectByName(behavior["weapon"], sdoObjects)
								ioc = getObjectByName(v, sdoObjects)
								sdoObjects.append(createListObject(sroSTIX(parse(weapon), parse(ioc), "indicates")))
	else:
		print("[+] There is no 'iocs' key in the threat sighting to generate the STIX low level view")
		return False

	for obj in sdoObjects:
		listStix.append(json.loads(obj["object"]))

	with open("tsOutcome_STIX_lowLevel.json", "w", encoding="utf8") as out:
		out.write(json.dumps(listStix, default=str, indent=4))

	print("[+] tsOutcome_STIX_lowLevel.json file generated")
	return True

def indicatorSTIX(stixType, v):
	"""
		Creates Indicators object with the iocs
	"""
	indicator = Indicator(name="%s"%(v),
                pattern="[%s = '%s']"%(stixType, v),
                pattern_type="stix")
	return indicator

def sroSTIX(id1, id2, term):
	"""
		method to create relations between two objects
	"""
	rel = Relationship(id1, term, id2)
	return rel

def scoSTIX(scotype, v):
	"""
		method to create cyber observable objects
	"""
	if scotype == 'ipv4':
		value = IPv4Address(value="%s"%(v))
	elif scotype == 'url':
		value = URL(value="%s"%(v))
	elif scotype == 'sha256':
		value = File(hashes={'SHA-256': '%s'%(v)})
	elif scotype == 'sha1':
		value = File(hashes={'SHA-1': '%s'%(v)})
	elif scotype == 'md5':
		value = File(hashes={'MD5': '%s'%(v)})
	elif scotype == 'ipv6':
		value = IPv6Address(value="%s"%(v))
	elif scotype == 'domain':
		value = DomainName(value="%s"%(v))
	elif scotype == 'dstHost':
		value = DomainName(value="%s"%(v))
	elif scotype == 'path':
		value = Directory(path="%s"%(v))
	elif scotype == 'key':
		value = WindowsRegistryKey(key="%s"%(v))
	elif scotype == 'file':
		value = File(name="%s"%(v))
	elif scotype ==  'name':
		value = File(name="%s"%(v))
	return value

def mappingSightingPatternSTIX(etype):
	"""
		 Map the patterns of stix 2.1 to threat sightings 
	"""
	mapping = {
		"sha256": "file:hashes.'SHA-256'",
		"ipv4": "ipv4-addr:value",
		"domain": "domain-name:value",
		"url": "url:value",
		"dstHost": "domain-name:value",
		"md5": "file:hashes.md5",
		"sha1": "file:hashes.'SHA-1'",
		"ipv6": "ipv6-addr:value",
		"file": "file:name",
		"name": "file:name",
		"path": "file:parent_directory_ref.path", # Expressed like this C:\\\\Windows
		"key": "windows-registry-key:key"
	}
	return mapping[etype]

def mappingSightingOpenIOC(etype):
	"""
		Map the openioc types to threat sightings
	"""
	mapping = {
		"sha256": "FileItem/Sha256sum",
		"ipv4": "DnsEntryItem/RecordData/IPv4Address",
		"domain": "Network/URI",
		"url": "UrlHistoryItem/URL",
		"dstHost": "Network/URI",
		"md5": "FileItem/Md5sum",
		"sha1": "FileItem/Sha1sum",
		"ipv6": "DnsEntryItem/RecordData/IPv6Address",
		"file": "FileItem/FileName",
		"name": "FileItem/FileName",
		"path": "FileItem/FilePath",
		"key": "RegistryItem/KeyPath"
	}
	return mapping[etype]

def sanitizeIOC(ioc):
	"""
		Method to sanitize IOCs
	"""
	newIOC = ioc.replace("[.]", ".").replace("hxxp", "http")
	return newIOC

def createOpenIOC(data):
	"""
		Method to create OpenIOC file 
	"""
	# Instance of the class
	IOC = ioc_api.IOC(name="OpenIOC generated automatically from Threat Sighting", description=data["header"]["description"], author="Trellix - AC3 Team")
	# First we have to create the first indicator level. This is <Indicator> tag. By default this must be OR
	IndicatorTop = IOC.top_level_indicator
	# Second we have to create the second level of indicator. This is <Indicator> tab inside of the first one.
	IndicatorLow = ioc_api.make_indicator_node("OR")
	# Append the second level into the first level.
	IndicatorTop.append(IndicatorLow)
	# Time to iterate the ioc section of the threat sighting in order to create new <IndicatorItem> tags for each ioc.
	try:
		for i in data["iocs"]:
			for indicator in i["indicators"]:
				for k,v in indicator.items():
					# We need to map our ioc type to openioc type
					openiocType = mappingSightingOpenIOC(k)
					# Also we need to remove broken iocs
					newIOC = sanitizeIOC(v)
					# Generate <IndicatorItem> tag
					IndicatorItem = ioc_api.make_indicatoritem_node("is", openiocType.split("/")[0], openiocType, "string", newIOC)
					IOC.set_lastmodified_date()
					# Append <IndicatorItem> to the second level IOC
					IndicatorLow.append(IndicatorItem)
	except KeyError as e:
		print("[+] There is no 'iocs' key in the threat sighting.")
		return False
	
	ioc_api.write_ioc(IOC.root)
	print("[+] %s.ioc OpenIOC file generated"%(str(IOC.iocid)))
	return True

def getBehaviorsByWeapon(weapon, d, cfg):
	"""
	 get the behaviors where the weapon is present
	"""
	for s in d["threatSightings"]:
		for b in s["behaviors"]:
			if weapon == b["weapon"]:
				print("*" * 20)
				print("+ Behavior: " + b["behavior"])
				print("+ type: " + b["type"])
				for k,v in b["att&ck"].items():
					print("+ Technique: " + v[0])
				# get sub-key of the behavior
				for k,v in cfg.items():
					if b["type"] in k:
						for item in b[v]:
							print("+ Procedures")
							for k2,v2 in item.items():
								print("\t |_ %s: %s"%(k2, v2))

def createStatistics(data):
	"""
		Method Core to create statistics
	"""
	summary = {"summary": {}}
	summary["summary"]["sightings"] = getSightingsLen(data)
	summary["summary"]["behaviors"] = getBehaviors(data, True)
	summary["summary"]["weapons"] = getWeapons(data)
	summary["summary"]["types"] = getTypes(data)
	summary["summary"]["lolbas"] = getLolbas(data, True)
	summary["summary"]["tools"] = getTools(data, True)
	summary["summary"]["malware"] = getMalwares(data, True)
	summary["summary"]["adversaries"] = getAdversaries(data, True)
	summary["summary"]["tactics"] = getTactics(data)
	summary["summary"]["techniques"] = getTechniques(data)
	with open("tsOutcome_statistics.json", "w", encoding="utf8") as out:
		out.write(json.dumps(summary, indent=4))

	print("[+] Generated tsOutcome_statistics.json file")
	return True

def getSightingsLen(d):
	# number of threatSightings key
	return  len(d["threatSightings"])

def getBehaviors(d, cnt=True):
	# number of behaviors key
	if cnt == True:
		behaviors = 0
		for s in d["threatSightings"]:
			behaviors += len(s["behaviors"])
	else: 
		behaviors = []
		for s in d["threatSightings"]:
			for b in s["behaviors"]:
				behaviors.append(b)

	return behaviors

def getWeapons(d):
	# number of weapons
	weapons = {}
	for s in d["threatSightings"]:
		for b in s["behaviors"]:
			try:
				weapons[b["weapon"]] += 1
			except KeyError as e:
				weapons[b["weapon"]] = 1
	return weapons

def getTypes(d):
	# number of types
	types = {}
	for s in d["threatSightings"]:
		for b in s["behaviors"]:
			try:
				types[b["type"]] += 1
			except KeyError as e:
				types[b["type"]] = 1
	return types

def getLolbas(d, cnt=True):
	# number of lolbas
	if cnt == True:
		return len(d["header"]["threatInformation"]["lolbas"])
	else:
		return d["header"]["threatInformation"]["lolbas"]

def getTools(d, cnt=True):
	# number of tools
	if cnt == True:
		return len(d["header"]["threatInformation"]["tools"])
	else:
		return d["header"]["threatInformation"]["tools"]

def getMalwares(d, cnt=True):
	# number of malware
	if cnt == True:
		return len(d["header"]["threatInformation"]["malware"])
	else:
		return d["header"]["threatInformation"]["malware"]


def getAdversaries(d, cnt=True):
	# number of adversaries
	if cnt == True:
		return len(d["header"]["threatInformation"]["adversaries"])
	else:
		return d["header"]["threatInformation"]["adversaries"]

def getTactics(d):
	# number of tactics
	tactics = {}
	for s in d["threatSightings"]:
		for b in s["behaviors"]:
			try:
				for k,v in b["att&ck"].items():
					try:
						tactics[k] += 1
					except KeyError as e:
						tactics[k] = 1
			except KeyError as e:
				pass
	return tactics

def getTechniques(d):
	# number of techniques
	techniques = {}
	for s in d["threatSightings"]:
		for b in s["behaviors"]:
			try:
				for k,v in b["att&ck"].items():
					try:
						techniques[v[0].split("-")[0].strip()] += 1
					except KeyError as e:
						techniques[v[0].split("-")[0].strip()] = 1
			except KeyError as e:
				pass
	return techniques

def parse_attack(data, cfg):
	"""
		Method to parse the ATT&CK from the threat sighting
	"""
	r = re.compile(r"[T|t][0-9]{4}(\.[0-9]{3})?")
	techniquesList = []
	techniqueAndBeh = {}
	for d in data["threatSightings"]:
		for behavior in d["behaviors"]:
				if 'att&ck' in behavior:
					for t in behavior["att&ck"].values():
						for te in t:
							techniquesList.append(r.match(te).group(0))
							# create a dictionary with techniques as keys and all the behaviors
							try:
								if techniqueAndBeh[r.match(te).group(0)]:
									for k,v in behavior.items():
										if k in cfg.values():
											techniqueAndBeh[r.match(te).group(0)].extend(behavior[k])
							except KeyError as e:
								for k,v in behavior.items():
									if k in cfg.values():
										techniqueAndBeh[r.match(te).group(0)] = behavior[k]

	return techniquesList, techniqueAndBeh

def create_navigator(techniques, techniquesAndBeh):
	"""
		Method that creates a navigator layer from a list with techniques
	"""
	fileLayer = "_layer.json"
	fileLayerOut = "tsOutcome_ATT&CK_Sightings_AC3.json"
	with open(fileLayer, "r") as layer:
		navi = json.load(layer)
	
	# Creating the navigator adding score and metadata
	for k,v in techniquesAndBeh.items():
		for t2 in navi["techniques"]:
			if t2["techniqueID"] == k:
				t2["score"] = techniques.count(k)
				t2["enabled"] = True
				t2["showSubtechniques"] = True
				for behavior in techniquesAndBeh[k]:
					t2["metadata"].append({"divider": True})
					for field,value in behavior.items():
						if type(value) == list and len(value) >= 1:
							for subvalue in value:
								t2["metadata"].append({"name": field, "value": subvalue})
						else:
							t2["metadata"].append({"name": field, "value": value})

	# pop techniques with score 0 to beautify the final JSON
	for t3 in navi["techniques"]:
		if t3["score"] == 0:
			[t3.pop(i) for i in t3.copy()]

	# remove empty dicts
	navi["techniques"] = [a for a in navi["techniques"] if a]

	with open(fileLayerOut, "w") as output:
		json.dump(navi, output, indent=4)

	print("[+] Generated navigator layer tsOutcome_ATT&CK_Sightings_AC3.json file")
	return 1

def attack(yJSON, cfg, path=False):
	## Method core to parse and creates a navigator layer of ATT&CK of the threat sighting.
	techniques, techniqueAndBeh = parse_attack(yJSON, cfg)
	create_navigator(techniques, techniqueAndBeh)

	return True

if __name__ == '__main__':
	_config_ = {
		"Process Created": "processes",
		"Network Accessed|DNS Queried": "connections",
		"ScheduledTask Changed|ScheduledTask Creation": "scheduledTasks",
		"DLL": "modules",
		"Email": "emails",
		"Process Accessed": "accesors",
		"Script Exeuted": "scripts",
		"NamedPipe Connected": "pipes",
		"Code Injection": "injections",
		"Driver Loaded|Driver Unloaded": "drivers",
		"User Logged": "users",
		"WMI Executed": "wmi",
		"Api Invoked": "apis",
		"Service Changed": "services",
		"File Created|File Modified|File Deleted|File Read|File Executed": "files",
		"RegKey Created|RegKey Modified|RegKey Deleted|RegKey Read|RegValue Created|RegValue Deleted|RegValue Modified|RegValue Read": "registries"
	}

	parser = argparse.ArgumentParser(description="Threat Sightings Converter - This script allows you to convert your threat sighting in other formats")
	parser.add_argument("-f", "--file", dest="input_file", required=True, default="None", help="Threat Sighting YAML file.")
	parser.add_argument("--attack", dest="attack", action="store_true", help="Create a navigator layer of ATT&CK MITRE with all the tactics and techniques")
	parser.add_argument("-w", "--weapon", dest="input_weapon", required=False, default="None", help="Show all the behaviors mapped to the weapon introduced. For example: cmd.exe")
	parser.add_argument("--openioc", dest="input_ioc", required=False, action="store_true", help="Create a XML file with OpenIOC format Based on the IOCs stored on the Threat Sighting")
	parser.add_argument("--stix-low-level", dest="input_stix_low", required=False, action="store_true", help="Create a JSON file with STIX format low high level information")
	parser.add_argument("--stix-high-level", dest="input_stix_high", required=False, action="store_true", help="Create a JSON file with STIX format with high level information")
	parser.add_argument("--stats", dest="input_stats", required=False, action="store_true", help="Create a JSON file with statistics from a threat sighting")
	parser.add_argument("--maltego-high-level", dest="input_maltego_high", required=False, action="store_true", help="Create Maltego CSV file with high level information to import into Maltego")
	parser.add_argument("--maltego-low-level", dest="input_maltego_low", required=False, action="store_true", help="Create Maltego CSV file with low level information to import into Maltego")
	args = parser.parse_args()
	main(_config_, args)