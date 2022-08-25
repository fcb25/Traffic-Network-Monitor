# Network Traffic Monitor

This project is my master's thesis in Cybersecurity at the University of Alicante.
The project is a network traffic monitor that allows the capture of traffic in real time, store it and represent the data in a user interface. It also incorporates mechanisms to detect Man in the Middle attacks and possible Denial of Service attacks.

[![All Traffic][all-traffic]](https://github.com/fcb25/Traffic-Network-Monitor/blob/main/readme_images/all_traffic_graph.JPG)
[![DoS Attacks][dos-attakcs]](https://github.com/fcb25/Traffic-Network-Monitor/blob/main/readme_images/possible_dos_table.JPG)

## Technology Infrastructure
The project has been developed in Ubuntu 20.04 using Python3. It uses MySQL database and Grafana for data representation.

## Prerequisites
### List of libraries needed to use the software with Python3.

* Socket
* Ipaddress
* Struct
* Codecs
* Argparse
* Threading
* Datetime
* Requests


### Installation of MySQL and Python Connector
MySQL Installation
  ```sh
  sudo apt install mysql-server
  sudo mysql_secure_installation
  ```

Modify MySQL Configuration
  ```sh
   sudo mysql -u root -p password
   USE mysql;
   UPDATE user SET plugin='mysql_native_password' WHERE User='root';
   FLUSH PRIVILEGES;
   exit;
  ```

MySQL-connector-python Installation
  ```sh
   sudo dpkg -i mysql-connector-python-py3_8.0.28-1ubuntu20.04_amd64.deb
   sudo apt install mysql-connector-python-py3
  ```

### Installation of Grafana
  ```sh
  wget https://dl.grafana.com/enterprise/release/grafana-enterprise-8.4.5.linux-amd64.tar.gz
  tar -zxvf grafana-enterprise-8.4.5.linux-amd64.tar.gz
  ```


## Usage
  ```sh
   sudo python3 main.py
   ```

The program can receive the following arguments:
* -h: Help. Shows a help message with the different arguments of the program.
* -n: Network range. Specifies the range of the network to be monitored. It is composed of 2 values, initial IP and final IP.
* -d: DHCP Server IP. Specifies the IP of the DHCP server on the network.
* -v: Verbose. Shows the network packets on the screen once they have been processed and the attacks detected.
* -t: Scanning time. Specifies the time, in seconds, that the network connected devices will be scanned before starting the traffic monitor.

Example:
  ```sh
   sudo python3 main.py -n 192.168.0.1 192.168.0.255 -d 192.168.0.1 -v -t 5
   ```
