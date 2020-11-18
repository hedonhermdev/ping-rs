# ping-rs
This is a Rust implementation of the ping tool using the ICMP protocol. It's mostly useless and is made only for learning purposes. I intentionally left out features of libpnet so that I could implement them myself.  

## Usage
Apparently, you cannot create raw sockets in UNIX without being a root user so you'll have to use sudo. 

Using a domain name:  
```
$ sudo cargo run google.com
```
Using an IP address: 
```
$ sudo cargo run 8.8.8.8
```
