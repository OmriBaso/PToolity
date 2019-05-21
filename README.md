# PToolity \ J3wker
Python based script used for PT / Replacing the exisiting known tools

ARP_PosionV1 VS ARP_PoisonV2 

ARP_PoisonV2 does something a bit different - 
___________________________________________________
insted of geting the TARGET MAC ADDRESS a few times in a loop 
 i took out the "get_mac" function out of the loop which prevents the App from 
crashing due to temporarily lose of connection - 
since the MAC ADDRESS is usally static there is no need to use 
the "get_mac" function inside
 the "Try:" loop
