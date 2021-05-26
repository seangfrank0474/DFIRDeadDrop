# DFIRDeadDrop
Took some of my code from the nightshift C2 and created a quick client/server script to pull DFIR evidence off of a machine to a machine where the forensics work will occur. Also created an exe for Windows.

<dl>
  <dt><b>Usage:</b></dt>
  <dt><b>Running the server on your forensics machine and with a firewall rule open for http/8081</b></dt>
  <dd><i>python3 deaddrop.py --server or deaddrop.exe --server</i></dd>
  <dt>Running the client on the Windows machine you are pulling evidence</dt>
  <dd><i>deaddrop.exe --client -h http://(ip or domain goes here) -f C:\path\to\file\here</i></dd>
</dl>
