# Not Dante's Inferno
## Notes for password specifics at each layer

Setup:
- Wrote README to get everyone one same page about GCLOUD, instructions essentially. 
- Wrote scripts to sort hashes
- Edit decrypt functions

### Layer 1
Passwords were easily cracked using rockyou.txt, and the ones we cracked generally took the form of typical human passwords. eg: Name1974

Method: Dedicated a password type to each team member.Ran a dictionary attack onthe hashes. PBK passwords cracked first.

K Value: 5

### Layer 2
Took time to figure out but passwords took the form of 8 character lowercase passwords which were a combinations of two four word passwords.

Method: We used linuxvoice-words.txt in combinator attack which seemed to crack most of the PBK. We also cracked some $6 but ETA was very large eg: 2 days 

K Value: 61


