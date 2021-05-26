# DFIRDeadDrop
Took some of my code from the nightshift C2 and created a quick client/server script to pull DFIR evidence off of a machine to a machine where the forensics work will occur. Also created an exe for Windows.

<dl>
  <dt><b>Usage:</b></dt>
  <dt>On your forensics server and with a firewall rule open for http/8081 run - python3 deaddrop.py --server or deaddrop.exe --server</dt>
  <dd><i>python3 nightshift_cmd_conf.py --conf (to generate a client/server configuration file)</i></dd>
  <dt>Writing the 404 command</dt>
  <dd><i>python3 nightshift_cmd_conf.py --cmd (to generate the fof c2 command)</i></dd>
  <dt>Starting up the server, currently runs on 8080</dt>
  <dd><i>python3 nighshift_server.py</i></dd>
  <dt>Starting up the client.</dt>
  <dd><i>python3 nighshift_client.py</i></dd>
</dl>
