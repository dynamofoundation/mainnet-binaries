Sample command line for users who want to run a full node with minimal resource requirements and fastest sync time:

dynamo-server -dbcache=2048 -txindex=0 -prune=1000 -nodebuglogfile

-dbcache sets the database cache size (in MB).  You can specify a larger value if you have the additional RAM, however values beyond 8GB don't seem to improve performance.

-txindex will set transaction indexing off.  This is not needed unless you are using the RPC to get specific transactions (such as in a wallet or chain explorer).  Disabling this will speed the sync time and reduce disk I/O.

-prune will set the maximum database size (in MB).  You can omit this parameter if you want to store the full block history, however this is usually not needed unless you are running a node for an explorer or other specific purposes that allows retrieval of all transactions since genesis.

(note that -prune will automatically disable transaction indexing, I included both parameters for clarity but really only -prune is required)

-nodebuglogfile will supress the generation of the debug.log file in the default Dynamo directory.  This will save disk space and load time.

Using these parameters, a t3a.medium Amazon instance will perform initial block download in about an hour as of this writing (October 2021).  Dynamo Core prioritizes getting headers first, so the initial blocks retrieved will seem slow, however once all headers are retrieved the block download rate will increase significantly.  During this time, the block download rate may also be increased by minimizing the Windows or Ubuntu console window to eliminate latency with CRT draw.
