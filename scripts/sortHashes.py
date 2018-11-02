hashes = open("../hashesL2.txt", 'r')
hashList=[]
for line in hashes:
	hashList.append(line)

hashList.sort()

sortedHashes = open("sortedHashesL2.txt",'w')

for i in hashList:
	sortedHashes.write(i)

sortedHashes.close()
