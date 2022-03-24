# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] Schema Version - 2022-03-16
### Added
- Each event type have his own object to represent the information. See the section [objects by event type](https://mcafee-enterprise.github.io/ac3-threat-sightings/docs/Getting%20Started/Schema#objects-by-event-types) in our wiki page.
- New script created to validate the schema of our threat sightings.

## Changed
- Some fields of the schema were updated.
- Wiki updated with the new content and typo fixed.

## [1.6.0] Schema Version - 2021-10-21
### Added
- Multiple instances of the same behavior can be represented using an array of items. See this [issue](https://github.com/mcafee-enterprise/ac3-threat-sightings/issues/7) for examples. 
- Contributors can be listed in the header of the sighting with a new field 'contributor'.
- Added 'keyValueType' field in docs

## Changed
- All Threat Sightings have been modified to adhere to the v1.6.0 of the schema. 
- Hunting queries on Threat Sighting for Cobalt Strike were updated.
- Some typo fixed in the Wiki.