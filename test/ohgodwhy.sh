sudo apt-get update
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.10
git clone https://github.com/pypa/setuptools.git && cd setuptools && sudo python3.10 setup.py install
sudo apt install python3.10-distutils
curl -sS https://bootstrap.pypa.io/get-pip.py | python3.10
cd
cd pycryptodome-master
sudo update-alternatives --install /usr/bin/python python /usr/bin/python3.10 1
sudo python setup.py install
