for checksum in */sha256sums; do
	echo -e "\e[0;32mGPG signing $checksum\e[0m";
	gpg --sign --local-user 6395FC9911EDCD6158712DF7BADFCABDDBF5B694 --clearsign "$checksum";
	if [ "$?" -eq "0" ]; then
		mv -f "$checksum.asc" "$checksum";
	fi;
done;
