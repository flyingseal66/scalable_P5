sudo apt-get install libnss -y
sudo apt-get install libssl-dev -y
sudo apt-get install libssl -y
sudo apt-get install libkrb5 -y
sudo apt-get install libgmp -y
sudo apt-get install wowsrp -y
sudo apt-get install krb5-18/23 -y
sudo apt-get install mozilla -y
cd src
sudo ./configure && make
./configure && make -s clean && make -sj4
