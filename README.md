# SharpEventPersist
Persistence by writing/reading shellcode from Event Log.  
  
## Usage
Run the SharpEventPersist tool and specify path to raw x64 shell like this "execute-assembly C:\path\to\SharpEventPersist.exe C:\path\to\shellcode.bin".  
The shellcode is converted to hex and written to the "Key Management Service", event level is set to "Information" and source is "Persistence".  
Run the SharpEventLoader tool to fetch shellcode from event log and execute it. Ideally this should be converted to a DLL and sideloaded on program start/boot.  
![image info](./demo.png)