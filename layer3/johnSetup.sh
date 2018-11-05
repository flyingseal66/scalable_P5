sudo apt-get install libssl-dev -y
sudo apt-get install libssl -y
sudo apt-get install mozilla -y
sudo apt-get install libnss -y
sudo apt-get install libkrb5 -y
sudo apt-get install libgmp -y
sudo apt-get install wowsrp -y
cd src 
./configure && make
./configure && make -sj4
./configure && make -s clean && make -sj4
cd ../run
./john --test
