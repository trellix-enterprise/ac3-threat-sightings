<br />
<div align="center"><h2/><strong>Threat Sightings are not a Trellix Licensed Product</strong></h2></div>
<br />

# AC3 Threat Sightings - Brief Overview
A documented Threat Sighting represents the acquired knowledge about one specific threat or campaign.

Threat Sightings offer rich details (full command-lines, process genealogy, API calls, file system activity, network activity, etc) about the observed behaviors of the threat.

In our vision, Threat Sightings are fundamental elements that empower Blue Teamers for the design and implementation of active and passive countermeasures.

<br />

# Threat Sightings tools
We have developed scripts to do different operations with our threat sightings.

* `Sighting validator`: This script allows you to validate the schema of your threat sighting. You can find it [here](https://github.com/mcafee-enterprise/ac3-threat-sightings/tree/main/tools/sighting%20validator)
* `Sighting converter`: This script allows you to create different outcomes from your threat sightings. You can find it [here](https://github.com/mcafee-enterprise/ac3-threat-sightings/tree/main/tools/sighting%20converter)

<div align="center"><h2><strong>Security Product Awareness</strong></h2></div>

Because AV products work with `pattern matching` features, these tend to key in on `STRINGS` that are common in relation to activity observed or reported
publicly.

Therefore when you `GIT CLONE` the repo, it is possible that your `AV` solution produces a detection of alleged malware.



This means your `AV` is under the assumption that malware exists, but in reality it is simply using its legacy pattern matcher features. Because threat sightings
are `YAML` content in clear text, `AV` products will exhibit this behavior.

<hr />
<br />
<br />

<div align="center"><h1> 
  
  [docs-wiki-ac3-threat-sightings](https://mcafee-enterprise.github.io/ac3-threat-sightings/docs/Welcome) 
  
</h1></div>
