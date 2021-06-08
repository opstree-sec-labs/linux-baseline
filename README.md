# Linux_Inspec

## Intrduction
This Linux Automation primarily built from scratch by opstree security to execute Linux checks from all platform.

We have written controls in ruby and all checks can be found in control directory.

## How to execute

This tool can be executed with help of chef inspec.
Ensure inspec is already installed.

```
inspec execute linux_inspec/

```

## Report 

### As per predefined functionality of chef inspec output can be generated in json, html2,xml, yaml format

#### HTML

```
inspec execute linux_inspec/ --reporter html2:filename
```

#### JSON

```
inspec execute linux_inspec/  --reporter json:filename
```
#### YAML

```
inspec execute linux_inspec/ --reporter yaml:filename
```