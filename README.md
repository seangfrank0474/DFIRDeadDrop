# DFIRDeadDrop
Took some of my code from the nightshift C2 and created a quick client/server script to pull DFIR evidence off of a machine to a machine where the forensics work will occur. Also created an exe for Windows. This is only using http so be sure to password/encypt any evidence prior to transfer. Also if you want to change the keys for the DGA/hash function you can and if you want to change the port or URI you can do that too. I just used pyinstaller to make the exe. You will have to rerun pyinstaller to reflect the changes made to the python script.

<dl>
  <dt><b>Usage:</b></dt>
  <dt><b>Running the server on your forensics machine and with a firewall rule open for http/8081</b></dt>
  <dd><i>python3 deaddrop.py --server or deaddrop.exe --server</i></dd>
  <dt>Running the client on the Windows machine you are pulling evidence</dt>
  <dd><i>deaddrop.exe --client -h http://(ip or domain goes here) -f C:\path\to\file\here</i></dd>
</dl>
