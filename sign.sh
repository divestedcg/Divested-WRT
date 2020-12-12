#!/bin/sh
#Copyright (c) 2020 Divested Computing Group
#License: GPL-2.0

sign() {
	checksum=$1;
	echo "GPG signing $checksum";
	gpg --sign --local-user 6395FC9911EDCD6158712DF7BADFCABDDBF5B694 --clearsign "$checksum";
	if [ "$?" -eq "0" ]; then
		mv -f "$checksum.asc" "$checksum";
	fi;
}

signAll() {
	for checksum in */sha256sums; do
		sign "$checksum";
	done;
}
