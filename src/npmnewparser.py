import os
import re
import sys

Base_Dir = os.path.abspath(os.path.dirname(__file__))
print("Base_Dir: {}".format(Base_Dir))

Package_Versions = [ 
    '0.1.0', '0.2.0', '0.3.0', '0.4.0', '0.5.0', '0.6.0', '0.7.0',
    '0.8.0', '0.9.0', '0.9.1', '0.9.2', '0.9.3', '0.9.4', '0.9.5',
    '0.9.6', '2.0.0-alpha', '2.0.0-alpha2', '2.0.0-alpha3', '2.0.0-alpha4',
    '2.0.0-alpha5', '2.0.0-alpha6', '2.0.0-alpha7', '2.0.0-alpha8', '2.0.0-alpha9',
    '2.0.0-rc1', '2.0.0-rc2', '2.0.0', '2.0.1', '2.1.0', '2.1.1', '2.2.0', '2.3.0',
    '2.3.1', '2.3.2', '2.4.0', '2.4.1', '2.4.2', '2.4.3', '2.5.0', '2.5.1', '2.5.2',
    '2.5.3', '2.5.4', '2.5.5', '2.6.0', '2.6.1', '2.6.2', '2.7.0', '2.8.0', '2.9.0',
    '2.10.0', '2.10.1', '2.10.2', '2.11.0', '2.11.1', '2.12.0', '2.13.0', '2.14.0',
    '2.14.1', '2.15.0', '2.16.0' ]

def Only_Digits(s):
    return re.sub(r"[^0-9.\s]+", "", s)

def Delete_Empty_Elements_From_Array(Array):
    return [x for x in Array if x != ""]

Package_Name = "mysql"
Versions_File_Name = "versions.txt"
Versions_File_Path = os.path.join(Base_Dir, Versions_File_Name)
print("Versions_File_Path: {}".format(Versions_File_Path))
Command_Get_Npm_Versions = "npm show {} versions > {}".format(Package_Name, Versions_File_Path)
print("Get Versions of Package: {}".format(Package_Name))


# os.system(Command_Get_Npm_Versions)

Vulnerable_Versions = ">=2.0.0-alpha8 <=2.0.0-rc2 || >=2.0.0 <=2.13.0"
Patched_Versions = ">=2.14.0"


def Detect_Patched_Versions1(Package_Versions, Patched_Versions):
    if ">=" in Patched_Versions:
        print("Scan {} Package_Versions".format(len(Package_Versions)))
        Patched_Version = Patched_Versions.replace(" ", "").replace(">", "").replace("<", "").replace("=", "")
        Patched_Versions_Index = -1
        Index = 0
        for Package_Version in Package_Versions:
            if Package_Version == Patched_Version:
                Patched_Versions_Index = Index
                break
            Index += 1
        print("Patched_Versions_Index = {}".format(Patched_Versions_Index))
        Real_Vulnerable_Versions = Package_Versions[:Patched_Versions_Index]
        Real_Patched_Versions = Package_Versions[Patched_Versions_Index:]
        print("Vulnerable_Versions = {}".format(Real_Vulnerable_Versions))
        print("Patched_Versions = {}".format(Real_Patched_Versions))
    pass

# Detect_Patched_Versions1(Package_Versions, Patched_Versions)

Vulnerable_Versions = ">=5.0.3 < 6.0.0 || >=6.8.6"
if "||" in Vulnerable_Versions:
    print("Get two section in Vulnerable_Versions")
    Versions = Vulnerable_Versions.split("||")

    Left_Version = Versions[0]
    Right_Version = Versions[1]

    Left_Version_Only_Digits = Only_Digits(Left_Version)
    Right_Version_Only_Digits = Only_Digits(Right_Version)
    print(Left_Version_Only_Digits)
    print(Right_Version_Only_Digits)

    Splitted_Left = Left_Version_Only_Digits.split(" ")
    Splitted_Right = Right_Version_Only_Digits.split(" ")

    print(Splitted_Left)
    print(Splitted_Right)

    Splitted_Left_Without_Empty_Elements = Delete_Empty_Elements_From_Array(Splitted_Left)
    Splitted_Right_Without_Empty_Elements = Delete_Empty_Elements_From_Array(Splitted_Right)

    print(Splitted_Left_Without_Empty_Elements)
    print(Splitted_Right_Without_Empty_Elements)