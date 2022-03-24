# Threat Sighting validator

This script allows you to validate the schema of your threat sighting. when you are working on creating a threat sighting, there may be errors during the creation. Therefore, this script allows the user to validate if all the mandatory fields are defined and which ones that are not supported were entered.

# Installation
Python3 is needed to run this script.

To install the dependencies run the following command.

```
pip install -r requirements.txt
```

**Note**: We recommend the use of virtualenv to install the dependencies. 

# Usage

After installing all the dependencies, the use of the script is simple.

```
> python sightingValidator.py -h
usage: sightingValidator.py [-h] [-f INPUT_FILE]

Threat Sightings Validator - This script allows you to validate if your threat sighting has a correct structure or not.

options:
  -h, --help            show this help message and exit
  -f INPUT_FILE, --file INPUT_FILE
                        YAML File that you want verify the schema
```

## Validating a threat sighting

#### Without errors

```
> python sightingValidator.py -f sighting_Guildma.yml
```

```
+------+-------+-----+----------+
| GUID | Error | Key | Sighting |
+------+-------+-----+----------+
+------+-------+-----+----------+
```

#### Unexpected element

```
> python sightingValidator.py -f sighting_Guildma.yml
```

```
+------+---------------------+----------------------------------------+------------------------------+
| GUID |        Error        |                  Key                   |           Sighting           |
+------+---------------------+----------------------------------------+------------------------------+
|  -   |  Unexpected element | threatSightings.0.behaviors.1.proceses | .\sighting_Guildma.yml       |
+------+---------------------+----------------------------------------+------------------------------+
```

An error occurred in the first `sighting` key (position 0), and the second `behavior` key (position 1) with a field called `proceses` which doesn't exists in the schema. In this case, the correct form is `processes`.

#### Duplicate uuid

```
> python sightingValidator.py -f sighting_Guildma.yml
```

```
+------+----------------+--------------------------------------+------------------------------+
| GUID |     Error      |                 Key                  |           Sighting           |
+------+----------------+--------------------------------------+------------------------------+
|  -   | Duplicate uuid | 97f41fab-22c2-4b0c-8e47-d1aeee9f1e0e | .\sighting_Guildma.yml       |
+------+----------------+--------------------------------------+------------------------------+
```

Duplicate uuid found in threat sighting

#### Incorrect behaviorId in hunting section

```
> python sightingValidator.py -f sighting_Guildma.yml
```

```
+------+--------------------------------------------------------------------+--------------------------------------+------------------------------+
| GUID |                               Error                                |                 Key                  |           Sighting           |
+------+--------------------------------------------------------------------+--------------------------------------+------------------------------+
|  -   | BehaviorId in huntingQuery that does not exist in behavior section | 97f4sfab-22c2-4b0c-8e47-d1aeee9f1e0e | .\sighting_Guildma.yml       |
+------+--------------------------------------------------------------------+--------------------------------------+------------------------------+
```

A behaviorId in `threatHunting` section was found and wasn't declared in the threat sighting file on behaviors section.

