SHELL := powershell.exe
CC := gcc
CFLAGS := -L "C:\npcap-sdk\Lib\x64" -I "C:\npcap-sdk\Include"
LDFLAGS := -lwpcap -lPacket
PROG := arp_flood
RM := Remove-Item

$(PROG): $(PROG).c 
	$(CC) $(CFLAGS) -o $(PROG) $(PROG).c $(LDFLAGS)
clean: 
	if (Test-Path $(PROG).exe) { $(RM) $(PROG).exe }