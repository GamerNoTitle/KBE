# KBE

Extract the keyboard input from wireshark datapack

As we all know that wireshark can capture the keyboard input and store it in `pcapng` file. You can find them in every `usb.capdata` attribute.

This script can help you extract the keyboard input and restore them into the key. 

If you need more options when using `tshark`, I recommend that you use the python script instead of using the binary executable program.

**CAUTION: The result that restored by this script sometimes may not be the `$flag`, it may also encrypted by other way.**

