# Threat Sighting converter

This script allows you to create different outcomes from your threat sightings. We believe that threat sightings and their visual representations help to better understand the threats. For this reason, we have implemented different integrations with formats and standards used in the cybersecurity industry.

# Installation

Python3 is needed to run this script.

To install the dependencies run the following command.

```
pip install -r requirements.txt
```

**Note**: We recommend the use of virtualenv to install the dependencies. 

# Supported exports

- [x] ATT&CK MITRE Navigator Layer
- [x] STIX 2.1
  - [x] High level export (includes ATT&CK tactics and techniques)
  - [x] Low level export (includes iocs if any in the threat sighting)
- [x] OpenIOC 1.1
- [x] Maltego
  - [x] High level export (includes ATT&CK tactics and techniques)
  - [x] Low level export (includes iocs if any in the threat sighting)

Other exports supported

- [x] Statistics generator
- [x] Weapon filter

# Usage

After installing all the dependencies, the use of the script is simple.

```
> python sightingConverter.py -h
usage: sightingConverter.py [-h] -f INPUT_FILE [--attack] [-w INPUT_WEAPON] [--openioc] [--stix-low-level] [--stix-high-level] [--stats] [--maltego-high-level] [--maltego-low-level]

Threat Sightings Converter - This script allows you to convert your threat sighting in other formats

options:
  -h, --help            show this help message and exit
  -f INPUT_FILE, --file INPUT_FILE
                        Threat Sighting YAML file.
  --attack              Create a navigator layer of ATT&CK MITRE with all the tactics and techniques
  -w INPUT_WEAPON, --weapon INPUT_WEAPON
                        Show all the behaviors mapped to the weapon introduced. For example: cmd.exe
  --openioc             Create a XML file with OpenIOC format Based on the IOCs stored on the Threat Sighting
  --stix-low-level      Create a JSON file with STIX format low high level information
  --stix-high-level     Create a JSON file with STIX format with high level information
  --stats               Create a JSON file with statistics from a threat sighting
  --maltego-high-level  Create Maltego CSV file with high level information to import into Maltego
  --maltego-low-level   Create Maltego CSV file with low level information to import into Maltego
```

## Exports

#### Generate ATT&CK MITRE Navigator Layer

```
> python sightingConverter.py -f sighting_Guildma.yml --attack
```

```
[+] Generated navigator layer tsOutcome_ATT&CK_Sightings_AC3.json file
```

**IMPORTANT:** The file called `_layer.json` is the layer used to create the navigator. Ensure that is in the same path of your script.

The file `ATT&CK_Sightings_AC3.json` is generated in the same path where the script was executed. You can view the matrix on the official website of MITRE and import the JSON file.

MITRE ATT&CK® Navigator: https://mitre-attack.github.io/attack-navigator/

All techniques are displayed in a heatmap format based on the number of occurrences within the sighting.

![visualization_mitre1](https://raw.githubusercontent.com/mcafee-enterprise/ac3-threat-sightings/main/tools/sighting%20converter/imgs/navigator_visualization1.png)

If you put the mouse over a technique, you will be able to see all the observables associated with that technique. This visualization help you to see the most used techniques and their behaviors.

![visualization_mitre2](https://raw.githubusercontent.com/mcafee-enterprise/ac3-threat-sightings/main/tools/sighting%20converter/imgs/navigator_visualization2.png)

#### STIX high level export

```
> python sightingConverter.py -f sighting_Guildma.yml --stix-high-level
```

```
[+] tsOutcome_STIX_highLevel.json file generated
```

The file `tsOutcome_STIX_highLevel.json` generated has STIX 2.1 format. You can view the visualization of it in the STIX Viewer website of [OASIS](https://www.oasis-open.org/).

STIX Viewer: https://oasis-open.github.io/cti-stix-visualization/ You can choose your file and drop in the website or copy/paste it.

![stixhigh](https://raw.githubusercontent.com/mcafee-enterprise/ac3-threat-sightings/main/tools/sighting%20converter/imgs/stix_high.png)

#### STIX low level export

```
> python sightingConverter.py -f sighting_Guildma.yml --stix-low-level
```

```
[+] tsOutcome_STIX_lowLevel.json file generated
```

The file `tsOutcome_STIX_lowLevel.json` generated has STIX 2.1 format. You can view the visualization of it in the STIX Viewer website of [OASIS](https://www.oasis-open.org/).

STIX Viewer: https://oasis-open.github.io/cti-stix-visualization/ You can choose your file and drop in the website or copy/paste it.

![stixlow](https://raw.githubusercontent.com/mcafee-enterprise/ac3-threat-sightings/main/tools/sighting%20converter/imgs/stix_low.png)

#### OpenIOC export

```
> python sightingConverter.py -f sighting_Guildma.yml --openioc
```

```
[+] 658a0f0d-25d7-4beb-b75a-c29fc0fbd638.ioc OpenIOC file generated
```

The name of the OpenIOC file generated is the uuid of the file. You can use this file for different purposes, since this format is widely used for cybersecurity solutions.

![openioc](https://raw.githubusercontent.com/mcafee-enterprise/ac3-threat-sightings/main/tools/sighting%20converter/imgs/openioc.png)

#### Maltego high level export

```
> python sightingConverter.py -f sighting_Guildma.yml --maltego-high-level
```

```
[+] tsOutcome_maltegoHighLevel.csv generated
```

The file `tsOutcome_maltegoHighLevel.csv` generated is ready to be imported on Maltego. We recommend import it in the following way.

1. Go to `import` section and select `Import a 3rd Party Table`
2. On `Select File(s)` section, select the file generated previously with the `sightingConverter.py`
3. On `Connectivity Options` we recommend use `Sequential`, however you can use whatever you want
4. On `Mapping Configuration` we use the [ATT&CK MISP transforms](https://www.maltego.com/transform-hub/att-ck-misp-misp-and-mitre-attack/). If you too, map the information like the following image

![step4](https://raw.githubusercontent.com/mcafee-enterprise/ac3-threat-sightings/main/tools/sighting%20converter/imgs/maltego_step4.png)

5. On `Settings` section, use the following options

![step5](https://raw.githubusercontent.com/mcafee-enterprise/ac3-threat-sightings/main/tools/sighting%20converter/imgs/maltego_step5.png)

6. Finally import and use the visualization that will help you to understand the threat sighting!

![maltego](https://raw.githubusercontent.com/mcafee-enterprise/ac3-threat-sightings/main/tools/sighting%20converter/imgs/maltego.png)

#### Maltego low level export

```
> python sightingConverter.py -f sighting_Guildma.yml --maltego-low-level
```

```
[+] tsOutcome_maltegoLowLevel.csv generated
```

The file `tsOutcome_maltegoLowLevel.csv` generated is ready to be imported on Maltego. We recommend import it in the following way.

1. Go to `import` section and select `Import a 3rd Party Table`
2. On `Select File(s)` section, select the file generated previously with the `sightingConverter.py`
3. On `Connectivity Options` we recommend use `Sequential`, however you can use whatever you want
4. On `Mapping Configuration` we use the [ATT&CK MISP transforms](https://www.maltego.com/transform-hub/att-ck-misp-misp-and-mitre-attack/). If you too, map the information like the following image

![maltegostep4_2](https://raw.githubusercontent.com/mcafee-enterprise/ac3-threat-sightings/main/tools/sighting%20converter/imgs/maltego_step4_2.png)

5. On `Settings` section, use the following options

![maltego5](https://raw.githubusercontent.com/mcafee-enterprise/ac3-threat-sightings/main/tools/sighting%20converter/imgs/maltego_step5.png)

6. Finally import and use the visualization that will help you to understand the threat sighting!

![maltego2](https://raw.githubusercontent.com/mcafee-enterprise/ac3-threat-sightings/main/tools/sighting%20converter/imgs/maltego2.png)

#### Statistics export

```
> python sightingConverter.py -f sighting_Guildma.yml --stats
```

```
[+] Generated tsOutcome_statistics.json file
```

The file `tsOutcome_statistics.json` generated is a JSON file with statistics about the threat sighting like number of behaviors, sightings, weapons and times used, MITRE techniques, etc.

The following JSON is an example of `tsOutcome_statistics.json`.


```json
{
    "summary": {
        "sightings": 3,
        "behaviors": 20,
        "weapons": {
            "winrar.exe": 2,
            "cmd.exe": 8,
            "powershell.exe": 2,
            "mshta.exe": 4,
            "bitsadmin.exe": 1,
            "AutoIt3": 1,
            "dllhost.exe": 1,
            "timeout.exe": 1
        },
        "types": {
            "Process Created": 14,
            "File Created": 5,
            "Network Accessed": 1
        },
        "lolbas": 4,
        "tools": 4,
        "malware": 1,
        "adversaries": 1,
        "tactics": {
            "execution": 11,
            "defenseEvasion": 4,
            "commandAndControl": 2
        },
        "techniques": {
            "T1059.003": 8,
            "T1059.001": 2,
            "T1218.005": 2,
            "T1071.001": 1,
            "T1105": 1,
            "T1197": 2,
            "T1059": 1
        }
    }
}
```` 

#### Weapon filter

```
> python sightingConverter.py -f sighting_Guildma.yml --weapon powershell.exe
```

```
********************
+ Behavior: PowerShell command executed to load malicious .hta file
+ type: Process Created
+ Technique: T1059.001 - Command and Scripting Interpreter: PowerShell
+ Procedures
         |_ parentProcess: C:\\Windows\\System32\\cmd.exe
         |_ process: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
         |_ cmdLine: ['powershell  -Command "& \'C:\\Users\\Public\\Videos\\YqW.Hta\' ']
********************
+ Behavior: PowerShell.exe is spawned by cmd.exe to execute the AutoIt binary
+ type: Process Created
+ Technique: T1059.001 - Command and Scripting Interpreter: PowerShell
+ Procedures
         |_ parentProcess: C:\\Windows\\System32\\cmd.exe
         |_ process: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
         |_ cmdLine: ['powershell  -windowstyle hidden -Command "& "C:\\\\Users\\\\Public\\\\Videos\\\\VEO46570203888O\\\\ctfmon.exe" C:\\\\Users\\\\Public\\\\Videos\\\\VEO46570203888O\\\\ctfmon.log "']
```

The output of this parameter are all the behaviors of the weapon selected. In this case, we can see the behaviors related to `powershell.exe`.