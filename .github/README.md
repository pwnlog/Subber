# Subfind

Find subnets within a network using ICMP.

# Install

Install the requirements:

```sh
pip install -r requirements.txt
```

## Usage 

Find multiple subnets with one input:

```sh
sudo python3 subfind.py 192.168.1-254.1-254
```

Store the output in TXT format:

```sh
sudo python3 subfind.py 192.168.1-254.1-254 -o subnets.txt
```

