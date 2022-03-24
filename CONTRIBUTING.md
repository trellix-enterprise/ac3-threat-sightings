# How to contribute
Thanks for your contribution!

If you want to contribute, it is very important that you first understand the [schema and fields supported](https://mcafee-enterprise.github.io/ac3-threat-sightings/docs/Getting%20Started/Schema). Once you understand and familiarize yourself with the scheme, you can write sightings from open source sources or based on incidents handled (important to anonymize any confidential information).

It is very important that the sightings always follow the same structure, since otherwise, they cannot be treated by different tools.

To verify that the schema is correctly written, we recommend use our `sightingValidator.py` script that you'll find in our [public github](https://github.com/mcafee-enterprise/ac3-threat-sightings/tree/main/tools). You only have to execute it with the `-f` parameter and the `filename` of the sighting.

```
python sightingValidator.py -f mysighting.yml
```

If the output is an empty table, means that the format is correct, otherwise, the table will show you the errors it found. However, we recommend see some of the possible outputs that the tool will show.

***Note***: Any pull request with confidential or non-anonymized information will not be added.


