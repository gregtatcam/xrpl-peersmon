# xrpl-peersmon
Monitor XRPL peers. Receive selected messages from peers and dump them in json
format.
Prerequisites are rippled, lz4, and date 
(https://github.com/HowardHinnant/date.git).
Makefile has to be updated to point to the correct prerequisites directories.
Peers are passed in via --peers option, which could be either a file or a coma
separated list of peers. Type of messages is selected with --messages option. 
For instance --messages 2,3,30-42.