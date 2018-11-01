# scalable_P5
A project for team Practical assignment 5 of Scalable Computing(cs7ns1)


## Process
1. Crack given hashes
2. When you think you have k, call pwds_shares_to_secret(kpwds,kinds,diffs):
- Where
    - kpwds: k cracked passwords
    - kinds: index's of the cracked password in the list of passwords
    - diffs: all public shares
3. Call decrypt, from: https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html.
This needs to be augmented just as Stephen augmented encrypt from that link.

## K Checking Script : WIP**
Added a script to allow us to check if we have reached k yet, called kChecker.py  
usage: kChecker.py -p <cracked hashes and passwords file> -i <infernoBall json file>  
Currently passwords file must be in format <hash>:<password> per line.(normal hashcat output, this wull have to be altered for submission)  
Has error on checking k at the moment believed to be an issue in xor'ing the shares, currently working on fix.  


## Setup GCloud
  
1. https://cloud.google.com/
2. Click "Try GCP Free"
3. Enter in gmail credentials (not TCD)
4. Follow steps
5. You have to enter in payment details but you won't be charged


## Spin up instance

1. Got to console
2. Select Compute Engine > VM instances from hamburger menu
3. Select create new instance
4. The instance should be "europe 4 west a" region
5. Click "customize and add V100 GPU"

## To ssh into the instance

https://cloud.google.com/sdk/gcloud/reference/compute/config-ssh
 ** need to install gcloud for your machine for gcloud command to work
