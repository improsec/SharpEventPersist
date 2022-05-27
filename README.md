# SharpEventPersist
Persistence by writing/reading shellcode from Event Log.  
  
## Usage
The SharpEventPersist tool takes 4 case-sensitive parameters:  
* -file "C:\path\to\shellcode.bin"
* -instanceid 1337
* -source Persistence
* -eventlog "Key Management Service".  

The shellcode is converted to hex and written to the "Key Management Service", event level is set to "Information" and source is "Persistence".  
Run the SharpEventLoader tool to fetch shellcode from event log and execute it. Ideally this should be converted to a DLL and sideloaded on program start/boot.  
Remember to change the Event Log name and instanceId in the loader, if not running with default values.  

Default values will leave the following artifact:  
* A new key will be written to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Key Management Service named "Persistance".
* This new "Persistance" key will not have a provider GUID or TypesSupported which the default key "KmsRequests" have. This can be used to build detections.  

![image info](./demo.png)
