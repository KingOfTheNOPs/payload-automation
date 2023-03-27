# CS-payload-automation
Automating CS payload generation

This project currently automates the payload generation process for CS payloads using arsenal-kit, Uru, Ivy, BokuLoader, and Mangle. The project will continue to add additional payload generation frameworks as I discover them. 
In order to use this project I recommend building a windows VM and enabling SSH for LNK file creation. 

This project modified sleep_python_bridge to work with CS 4.6. This current version does not work on previous versions of CS, and may not work on newer versions.

## Install Requirements
`pip install -r requirements.txt`

Also ensure BokuLoader and Arsenal Kit is downloaded in the bofs folder!

## Usage Example
Download and run the project inside of your CS directory.
`python3 payload-automation.py [Teamserver IP Address] [Teamserver Port] [User] [Password] [CS Directory]`

Example:
`python3 payload-automation.py 192.168.0.2 50050 andrew password '/opt/cobaltstrike'`

## Shout Outs
This project couldn't have been done without the following existing projects:
https://github.com/Cobalt-Strike/sleep_python_bridge
https://github.com/boku7/BokuLoader
https://github.com/jbardin/scp.py


