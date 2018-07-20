import os
import re
import sys

Base_Dir = os.path.abspath(os.path.dirname(__file__))
# print("Base_Dir: {}".format(Base_Dir))

Package_Name = "mysql"
Versions_File_Name = "versions.txt"
Versions_File_Path = os.path.join(Base_Dir, Versions_File_Name)
# print("Versions_File_Path: {}".format(Versions_File_Path))
Command_Get_Npm_Versions = "npm show {} versions > {}".format(Package_Name, Versions_File_Path)
# print("Get Versions of Package: {}".format(Package_Name))

# os.system(Command_Get_Npm_Versions)

def Split_And_Remove_Empty_Elements(String):
    Splitted = String.split("||")
    Result = []
    for s in Splitted:
        Result.append(s)
    return Result

Package_Versions_From_Source = [ 
    '0.1.0', '0.2.0', '0.3.0', 
    '0.4.0', 
    '0.5.0', '0.6.0', '0.7.0',
    '0.8.0', 
    '0.9.0', '0.9.1', '0.9.2', '0.9.3', '0.9.4', '0.9.5', '0.9.6', '2.0.0-alpha', '2.0.0-alpha2', '2.0.0-alpha3', '2.0.0-alpha4', '2.0.0-alpha5', 
    '2.0.0-alpha6', '2.0.0-alpha7', '2.0.0-alpha8', '2.0.0-alpha9', '2.0.0-rc1', '2.0.0-rc2', '2.0.0', '2.0.1', '2.1.0', '2.1.1', '2.2.0', '2.3.0',
    '2.3.1', '2.3.2', '2.4.0', '2.4.1', '2.4.2', '2.4.3', '2.5.0', '2.5.1', '2.5.2', '2.5.3', '2.5.4', '2.5.5', '2.6.0', '2.6.1', '2.6.2', '2.7.0', '2.8.0', '2.9.0',
    '2.10.0', '2.10.1', '2.10.2', '2.11.0', '2.11.1', '2.12.0', '2.13.0', '2.14.0',
    '2.14.1', '2.15.0', '2.16.0' ]

# Vulnerable_Versions = ">=2.0.0-alpha8 <=2.0.0-rc2 || >=2.0.0 <=2.13.0"
# Vulnerable_Versions = ">=2.0.0-alpha8 || >=2.0.0 <=2.13.0"
# Vulnerable_Versions = ">=5.0.3 < 6.0.0 || >=6.8.6"
# Vulnerable_Versions = "< 1.6.16 || >=1.7 <1.7.11 || >= 1.8 <1.8.2-beta.4"
# Vulnerable_Versions = "<= 1.7.12 || >=1.8.0 <= 1.8.3 || >=2.0.0-beta.1 <= 2.0.0-beta.4"
# Vulnerable_Versions = ">=1.6.16 <1.7.0|| >=1.7.11 > 1.8.0 || >=1.8.2-beta.4"
# Vulnerable_Versions = "1.7.13 < 1.8.0 || 1.8.4 < 2.0.0 || >=2.0.0-beta.5"

Vulnerable_Versions = "< 0.3.0 || >=0.5.0 <0.7.0 || >= 0.9.0 <2.0.0-alpha5"
Patched_Versions = ">=2.14.0 <= 2.16.0"

def Process_Vulnerable_Versions(Package_Versions, Vulnerable_Versions):
    Diapasons = Split_And_Remove_Empty_Elements(Vulnerable_Versions)
    print("Diapasons:                  {}".format(Diapasons))

    Vulnerable_Versions_To_Save = []

    for Index in range(0, len(Diapasons)):
        print("------------------------------")
        Diap_0_Source = Diapasons[Index]
        Diap_0 = Diap_0_Source.replace(">", "").replace("<", "").replace("=", "")
        print("Diap_0:                     {}".format([Diap_0]))
        Diap_0_Splitted = Diap_0.split(" ")
        Diap_0_Splitted_Cleared = [x for x in Diap_0_Splitted if x != ""]
        print("Diap_0_Splitted_Cleared:    {}".format(Diap_0_Splitted_Cleared))
        Diap_0_Bounds = []
        Filled = False
        if len(Diap_0_Splitted_Cleared) == 1:
            Filled = True
            Diap_0_Bounds.append(Package_Versions[0])
            Diap_0_Bounds.append(Diap_0_Splitted_Cleared[0])
            print("Diap_0_Bounds:              {}".format(Diap_0_Bounds))
        elif len(Diap_0_Splitted_Cleared) == 2:
            Filled = False
            Diap_0_Bounds.append(Diap_0_Splitted_Cleared[0])
            Diap_0_Bounds.append(Diap_0_Splitted_Cleared[1])
            print("Diap_0_Bounds:              {}".format(Diap_0_Bounds))
        
        Start_Index = 0
        Stop_Index = 0

        if not Filled:
            if "<" in Diap_0_Source or ">" in Diap_0_Source:
                if ">" in Diap_0_Source:
                    Start_Index = Package_Versions.index(Diap_0_Bounds[0])
                    if Start_Index < len(Package_Versions):
                        Start_Index += 1
                if ">=" in Diap_0_Source:
                    Start_Index = Package_Versions.index(Diap_0_Bounds[0])
                if "<" in Diap_0_Source:
                    Stop_Index = Package_Versions.index(Diap_0_Bounds[1])
                if "<=" in Diap_0_Source:
                    Stop_Index = Package_Versions.index(Diap_0_Bounds[1])
                    if Stop_Index < len(Package_Versions):
                        Stop_Index += 1
            else:
                Start_Index = Package_Versions.index(Diap_0_Bounds[0])
                Stop_Index = Package_Versions.index(Diap_0_Bounds[1])
        else:
            Start_Index = Package_Versions.index(Diap_0_Bounds[0])
            if "<" in Diap_0_Source or ">" in Diap_0_Source:
                if "<" in Diap_0_Source:
                    Stop_Index = Package_Versions.index(Diap_0_Bounds[1])
                if "<=" in Diap_0_Source:
                    Stop_Index = Package_Versions.index(Diap_0_Bounds[1])
                    if Stop_Index < len(Package_Versions):
                        Stop_Index += 1
            else:
                Start_Index = Package_Versions.index(Diap_0_Bounds[0])
                Stop_Index = Package_Versions.index(Diap_0_Bounds[1])

        Vulnerable_Versions_From_Package = Package_Versions[Start_Index:Stop_Index]
        print("Package_Versions:           {}".format(Vulnerable_Versions_From_Package))

        Vulnerable_Versions_To_Save += Vulnerable_Versions_From_Package

    return Vulnerable_Versions_To_Save

def Process_Patched_Versions(Package_Versions, Patched_Versions):
    Diapasons = Split_And_Remove_Empty_Elements(Patched_Versions)
    print("Diapasons:                  {}".format(Diapasons))

    Patched_Versions_To_Save = []

    for Index in range(0, len(Diapasons)):
        print("------------------------------")
        Diap_0_Source = Diapasons[Index]
        Diap_0 = Diap_0_Source.replace(">", "").replace("<", "").replace("=", "")
        print("Diap_0:                     {}".format([Diap_0]))
        Diap_0_Splitted = Diap_0.split(" ")
        Diap_0_Splitted_Cleared = [x for x in Diap_0_Splitted if x != ""]
        print("Diap_0_Splitted_Cleared:    {}".format(Diap_0_Splitted_Cleared))
        Diap_0_Bounds = []
        Filled = False
        if len(Diap_0_Splitted_Cleared) == 1:
            Filled = True
            Diap_0_Bounds.append(Diap_0_Splitted_Cleared[0])
            Diap_0_Bounds.append(Package_Versions[-1])
            print("Diap_0_Bounds:              {}".format(Diap_0_Bounds))
        elif len(Diap_0_Splitted_Cleared) == 2:
            Filled = False
            Diap_0_Bounds.append(Diap_0_Splitted_Cleared[0])
            Diap_0_Bounds.append(Diap_0_Splitted_Cleared[1])
            print("Diap_0_Bounds:              {}".format(Diap_0_Bounds))

        Start_Index = 0
        Stop_Index = 0

        if not Filled:
            if "<" in Diap_0_Source or ">" in Diap_0_Source:
                if ">" in Diap_0_Source:
                    Start_Index = Package_Versions.index(Diap_0_Bounds[0])
                if Start_Index < len(Package_Versions):
                    Start_Index += 1
                if ">=" in Diap_0_Source:
                    Start_Index = Package_Versions.index(Diap_0_Bounds[0])
                if "<" in Diap_0_Source:
                    Stop_Index = Package_Versions.index(Diap_0_Bounds[1])
                if "<=" in Diap_0_Source:
                    Stop_Index = Package_Versions.index(Diap_0_Bounds[1])
                    if Stop_Index < len(Package_Versions):
                        Stop_Index += 1
            else:
                Start_Index = Package_Versions.index(Diap_0_Bounds[0])
                Stop_Index = Package_Versions.index(Diap_0_Bounds[1])   
        else:
            Start_Index = Package_Versions.index(Diap_0_Bounds[0])
            if "<" in Diap_0_Source or ">" in Diap_0_Source:
                if ">" in Diap_0_Source:
                    Stop_Index = Package_Versions.index(Diap_0_Bounds[1])
                if ">=" in Diap_0_Source:
                    Stop_Index = Package_Versions.index(Diap_0_Bounds[1])
                    if Stop_Index < len(Package_Versions):
                        Stop_Index += 1
            else:
                Start_Index = Package_Versions.index(Diap_0_Bounds[0])
                Stop_Index = Package_Versions.index(Diap_0_Bounds[1])

        # TODO: Without <>, <= >=

        Patched_Versions_From_Package = Package_Versions[Start_Index:Stop_Index]
        print("Package_Versions:           {}".format(Patched_Versions_From_Package))

        Patched_Versions_To_Save += Patched_Versions_From_Package

    return Patched_Versions_To_Save

Process_Patched_Versions(Package_Versions_From_Source, Patched_Versions)

# Process_Vulnerable_Versions(Package_Versions_From_Source, Vulnerable_Versions)

