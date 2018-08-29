# ZeroBank-ring0-bundle
Kernel-Mode rootkit that connects to a remote server to send & recv commands using the TDI (Transport Driver Interface) network layer

Proyect compiled using VS 2013 and WDK 8.1 <br />
To use change ip address in both driver & server <br />
Win 7 x86 only supported for the moment <br />
Use under Virtualization <br />

# Currently Working Features

Function Hashing (API functions resolved at runtime using hashing) <br />
Process Explorer <br />
Thread Explorer <br />
File Explorer <br />
File Transfer (Kernel to server) <br />
TDI connections filter <br />
Encrypted communications (RC4) <br />
More information about project parts and overview can be found here <br />

http://alexvogtkernel.blogspot.com/
