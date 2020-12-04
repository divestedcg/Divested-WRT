  /usr/sbin/bridge monitor fdb | while read mac d dev rest; do
    if [ $mac != Deleted ]; then
      echo "FDB: Found $mac on $dev";
      /usr/sbin/bridge fdb show br br-lan | while read omac d odev rest; do
        if [ $omac = $mac ] && [ $odev != $dev ]; then
          echo "FDB: Removing $mac from $odev as old";
          /usr/sbin/bridge fdb del $mac dev $odev $rest;
        fi;
      done;
    fi;
  done;
