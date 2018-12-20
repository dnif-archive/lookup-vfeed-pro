## vFeed Professional
[https://vfeed.io/](https://vfeed.io/)

### Overview

vFeed technology helps in validating network related data with known **vulnerability** "Indicators Of Comprise"(IOCs). The required threat intel information is readily available within it's **vulnerability** and threat intelligence database and multi-formats feeds. vFeeds are focused 100% to empower customers technology, treat intelligence solutions, protect vulnerable and sensitive systems and enables it's clients to rapidly detect and react against cyber-attacks.

vFeed worldwide client base comprises of a wide and diverse range of individuals and businesses from hackers, consultancy firms, CERTs and freelancers to  governmental organizations, software companies and intelligence providers.

### vFeed Professional lookup plugin functions

Details of the functions that can be used with the vFeed Professional lookup plugin are given in this section.

- [keyword_to_cve](#keyword_to_cve)
- [get_targets](#get_targets)
- [get_cwe](#get_cwe)
- [get_capec](#get_capec)
- [get_category](#get_category)
- [get_wasc](#get_wasc)
- [get_advisory](#get_advisory)
- [get_rules](#get_rules)
- [get_exploits](#get_exploits)
- [get_information](#get_information)
- [get_references](#get_references)
- [get_remote_inspection_signatures](#get_remote_inspection_signatures)
- [get_local_inspection_signatures](#get_local_inspection_signatures)
- [get_cvss2_score](#get_cvss2_score)
- [get_cvss3_score](#get_cvss3_score)
- [get_cvss_score](#get_cvss_score)


### Note

In all the functions explained below, the examples use an event store named **testingintegrations**.  
**This event store does not exist in DNIF by default**. However, it can be created/imported.

### keyword_to_cve

Returns a list of CVEs whose description matches the input description

#### Input
- A keyword that matches a CVE

#### Example
```
_fetch $Keyword from testingintegrations limit 1
>>_lookup vfeed-pro keyword_to_cve $Keyword
```

#### Output

Click [here](https://drive.google.com/open?id=1EtgEbasTQC-V8ArXkjCWOUW1oC1qXD-X) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $Keyword | The keyword to search for in CVE database |
| $CVE | CVE that matched the given keyword |
| $CVEDatePublished | The date the CVE was first published |
| $CVEDateModified | The date the CVE was last modified |
| $CVESummary | Summary of the CVE that matched the given keyword |

### get_targets

Returns information about the targets that are affected by the given CVE's vulnerability.

#### Input
- CVE ID

#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_targets $CVE
```

#### Output

Click [here](https://drive.google.com/open?id=1qCVBhAeMORyrrSzOfhdmkr6_M6bshIuh) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE| CVE being queried |
| $VFTargetsTitle | The title given to the target |
| $VFcpe2.2 | The respective CPE2.2 ID |
| $VFcpe2.3 | The respective CPE2.3 ID |

### get_cwe

Returns CWE (Common Weakness Enumeration) information that matches the given CVE

#### Input
- CVE ID

#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_cwe $CVE
```
#### Output
Click [here](https://drive.google.com/open?id=1uvSJ5pxx_a-JEyGzT5K8u-ld7_hWk0xz) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $VFCWEid | A CWE ID that matches the given CVE |
| $VFCWEclass | The family or class that the weakness belongs to |
| $VFCWEtitle | The title given to the current CWE |
| $VFCWErelations | List of other CWEs that are related that the current CWE |
| $VFCWEurl | The Mitre URL for the current CWE |

### get_capec

Returns CAPEC information that matches the given CVE

#### Input
- CVE ID

#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_capec $CVE
```
#### Output

Click [here](https://drive.google.com/open?id=1RbzX2oQnakUt9ls_7Wp80vckzSe2Xikm) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $VFCweID | A CWE ID that matches the given CVE |
| $VFCapecID | A CAPEC ID that matches the current CWE ID |
| $VFCapecTitle | The title given the the CAPEC record |
| $VFCapecAttackMethods | List of attack methods related to the CAPEC ID |
| $VFCapecMitigations | List of mitigations related to the CAPEC ID |
| $VFCapecURL | The Mitre URL for the CAPEC ID |

### get_category

Returns CWE Weaknesses Category details (as Top 2011, CERT C++, Top 25, OWASP ....) for each CWE matched to the given CVE

#### Input
- CVE ID
#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_category $CVE
```
#### Output

Click [here](https://drive.google.com/open?id=12B6EhArTFWKqrhTCGZCBnVavLOnNK7tN) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE| CVE being queried |
| $VFCweID | CWE linked with the given CVE |
| $VFCategoryID | Category ID for the given CWE |
| $VFCategoryTitle | Category Titles for the given CWE |
| $VFCategoryURL | Category URL for more information on the given CWE |
| $VFCWEinRelations | True or false depending on whether the given CWE is in relation to the category |

### get_wasc

Returns Web Application Consortium details for each CWE linked to the given CVE
#### Input
- CVE ID
#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_wasc $CVE
```
#### Output

Click [here](https://drive.google.com/open?id=1Z6ogascO7cmqFHV21Aa9C4jy_yZ_-ldP) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE| CVE being queried |
| $VFCweID | CWE linked with the given CVE |
| $VFWascID | CWE linked to the given CVE |
| $VFWascTitle | CWE linked to the given CVE |
| $VFWascID | CWE linked to the given CVE |

### get_advisory

Returns bulletins and advisory data for the given CVE

#### Input
- CVE ID
#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_advisory $CVE
```
#### Output

Click [here](https://drive.google.com/open?id=1-kuS9RJMaiR4LxnRrEsflvlmtLsvTwfa) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $VFSource | The name of the source that provided the bulletin |
| $VFPreventiveBulletinClass | The class this bulletin falls under |
| $VFPreventiveBulletinID | The ID of the bulletin given by the source |
| $VFPreventiveBulletinURL | The URL of the bulletin |

### get_rules

Returns IPS and IDS signatures for the given CVE
#### Input
- CVE ID

#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_rules $CVE
```
#### Output

Click [here](https://drive.google.com/open?id=1IMagggyFbor_-r2gBVo1dIalEtn8Vx6u) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $VFSource | The name of the source that provided the information |
| $VFDetectiveRulesClass | The class this rule / signature information falls under |
| $VFDetectiveRulesID | The ID of the rule / signature given by the source |
| $VFDetectiveRulesTitle | The title of the rule / signature |
| $VFDetectiveRulesURL | The URL of the rule / signature |

### get_exploits

Returns exploits and PoC signatures for the given CVE
#### Input
- CVE ID
#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_exploits $CVE
```
#### Output

Click [here](https://drive.google.com/open?id=1MVgO2fOE60-ewMs6xfMge0RTOzS1mF1-) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $VFSource | The name of the source that provided the information |
| $VFExploitsID | The ID of the exploit given by the source |
| $VFExploitsTitle | The title of the exploit |
| $VFExploitsFile | The file resource related to the exploit |
| $VFExploitsURL | The URL of the exploit |

### get_information

Returns information for a given CVE

#### Input
- CVE ID

#### Example

```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_information $CVE
```
#### Output

Click [here](https://drive.google.com/open?id=1mVz8PIS0lzkKgTMfvcJCZmOIoLPbxIoq) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $CVEDateModified | The date the CVE was last modified |
| $CVEDatePublished | The date the CVE was first published |
| $CVESummary | A summary of the CVE |

### get_references

Returns vulnerability references for a given CVE
#### Input
- CVE ID
#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_references $CVE
```

#### Output

Click [here](https://drive.google.com/open?id=1r-juu1fVJjY9ELIQIyWtq0D7b1nTHEIR) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $CVEReferenceVendor | The vendor linked to the reference |
| $CVEURL | The URL provided for the reference |

### get_remote_inspection_signatures

Returns remote scanner signatures for a given CVE

#### Input
- CVE ID

#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_remote_inspection_signatures $CVE
```
#### Output

Click [here](https://drive.google.com/open?id=1E64mYouTYIc4BKLKsj6yTkd1j1QmgjJT) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $VFSource | The name of the source that provided the signature information |
| $VFSignatureID | The ID of the signature given by the source |
| $VFSignatureName | The name given to the signature |
| $VFSignatureFamily | The family the signature belongs to |
| $VFSignatureURL | The URL of the signature |
| $VFSignatureFile | The file resource related to the signature |

### get_local_inspection_signatures

Returns local scanner signatures for a given CVE
#### Input
- CVE ID

#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_local_inspection_signatures $CVE
```

#### Output

Click [here](https://drive.google.com/open?id=1MM5COcNgMKWMVo6oS1TX2JvIL0Ih4mSg) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $VFSource | The name of the source that provided the signature information |
| $VFSignatureID | The ID of the signature given by the source |
| $VFSignatureName | The name given to the signature |
| $VFSignatureFamily | The family the signature belongs to |
| $VFSignatureURL | The URL of the signature |
| $VFSignatureFile | The file resource related to the signature |

### get_cvss2_score

Returns the CVSS 2 Scores for a given CVE

#### Input
- CVE ID

#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_cvss2_score $CVE
```
#### Output

Click [here](https://drive.google.com/open?id=1qhpa5qP8KJBm0TFSh2rh5gcwPYVjxdQo) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $VFCVSS2AccessComplexity | The complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system |
| $VFCVSS2AccessVector | The vector reflecting how the vulnerability is exploited |
| $VFCVSS2Authentication | The number of times an attacker must authenticate to a target in order to exploit a vulnerability |
| $VFCVSS2AvailabilityImpact | The impact to availability of a successfully exploited vulnerability |
| $VFCVSS2Base | The CVSS2 Base metric score |
| $VFCVSS2ConfidentialityImpact | The impact on confidentiality of a successfully exploited vulnerability |
| $VFCVSS2Impact | The CVSS2 Impact metric score |
| $VFCVSS2Exploit | The CVSS2 Exploit metric score |
| $VFCVSS2IntegrityImpact | The impact to integrity of a successfully exploited vulnerability |
| $VFCVSS2Vector | An abbreviated list of CVSS2 vector metric names |

### get_cvss3_score

Returns the CVSS 3 Scores for a given CVE
#### Input
- CVE ID

#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_cvss3_score $CVE
```
#### Output

Click [here](https://drive.google.com/open?id=1KfdvohvH7zBCQX7JFqzfW2M44nQS2Mf-) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $VFCVSS3AccessComplexity | The complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system |
| $VFCVSS3AccessVector | The vector reflecting how the vulnerability is exploited |
| $VFCVSS3Authentication | The number of times an attacker must authenticate to a target in order to exploit a vulnerability |
| $VFCVSS3AvailabilityImpact | The impact to availability of a successfully exploited vulnerability |
| $VFCVSS3Base | The CVSS3 Base metric score |
| $VFCVSS3ConfidentialityImpact | The impact on confidentiality of a successfully exploited vulnerability |
| $VFCVSS3Impact | The CVSS3 Impact metric score |
| $VFCVSS3Exploit | The CVSS3 Exploit metric score |
| $VFCVSS3IntegrityImpact | The impact to integrity of a successfully exploited vulnerability |
| $VFCVSS3Vector | An abbreviated list of CVSS3 vector metric names |

### get_cvss_score

Returns both the CVSS 2 and CVSS 3 scores for a given CVE

#### Input
- CVE ID

#### Example
```
_fetch $CVE from testingintegrations limit 1
>>_lookup vfeed-pro get_cvss_score $CVE
```

#### Output

Click [here](https://drive.google.com/open?id=1xMOD4PtwZ5AT3w4jbSxbc55qX-JPTIfG) to view the output of the above example.  
 
The output of the lookup call has the following structure (for the available data):

|Field|Description|
|-|-|
| $CVE | CVE being queried |
| $VFCVSS2AccessComplexity | The complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system |
| $VFCVSS2AccessVector | The vector reflecting how the vulnerability is exploited |
| $VFCVSS2Authentication | The number of times an attacker must authenticate to a target in order to exploit a vulnerability |
| $VFCVSS2AvailabilityImpact | The impact to availability of a successfully exploited vulnerability |
| $VFCVSS2Base | The CVSS2 Base metric score |
| $VFCVSS2ConfidentialityImpact | The impact on confidentiality of a successfully exploited vulnerability |
| $VFCVSS2Impact | The CVSS2 Impact metric score |
| $VFCVSS2Exploit | The CVSS2 Exploit metric score |
| $VFCVSS2IntegrityImpact | The impact to integrity of a successfully exploited vulnerability |
| $VFCVSS2Vector | An abbreviated list of CVSS2 vector metric names |
| $VFCVSS3AccessComplexity | The complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system |
| $VFCVSS3AccessVector | The vector reflecting how the vulnerability is exploited |
| $VFCVSS3Authentication | The number of times an attacker must authenticate to a target in order to exploit a vulnerability |
| $VFCVSS3AvailabilityImpact | The impact to availability of a successfully exploited vulnerability |
| $VFCVSS3Base | The CVSS3 Base metric score |
| $VFCVSS3ConfidentialityImpact | The impact on confidentiality of a successfully exploited vulnerability |
| $VFCVSS3Impact | The CVSS3 Impact metric score |
| $VFCVSS3Exploit | The CVSS3 Exploit metric score |
| $VFCVSS3IntegrityImpact | The impact to integrity of a successfully exploited vulnerability |
| $VFCVSS3Vector | An abbreviated list of CVSS3 vector metric names |


## Using the vFeed Professional CVE Database with DNIF  
The vFeed Professional CVE Database can be found on the vFeed website at

  https://vfeed.io/

#### Getting started with vFeed Professional CVE Database with DNIF

1. ###### Login to your Data Store, Correlator, and A10 containers.  
   [ACCESS DNIF CONTAINER VIA SSH](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. ###### Move to the `/dnif/<Deployment-key>/lookup_plugins` folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/lookup_plugins/
```
3. ###### Clone using the following command  
```  
git clone https://github.com/dnif/lookup-vfeed-pro.git vfeed-pro
```
4. ###### Move to the `/dnif/<Deployment-key>/lookup_plugins/vfeed-pro/` folder path and open dnifconfig.yml configuration file     

 Replace the tags: `<Add_your_access_key_here>` with your vFeed Professional access key, `<Add_your_plan_name_here>` with your vFeed Professional
 plan name, and `<Add_your_secret_key_here>` with your vFeed Professional secret key.

```
lookup_plugin:
  VF_ACCESS_KEY: <Add_your_access_key_here>
  VF_LAST_DB_UPDATE:
  VF_PLAN: <Add_your_plan_name_here>
  VF_SECRET_KEY: <Add_your_secret_key_here>
```
