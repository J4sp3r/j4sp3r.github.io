---
layout: writeup
title: Strange PCAP
ctf: HackTM CTF 2020
category: forensics
challenge_name: Strange PCAP
challenge_description: "We managed to get all the data to incriminate our CEO for selling company secrets. Can you please help us and give us the secret data that he has leaked?</BR></BR>Author: Legacy"
challenge_points: 114
challenge_files: /files/hacktm-ctf-2020/strange-pcap/
---
We participated in the hacktm 2020 CTF and generally I briefly look over the challenges. This was a challenge I skipped at first, but later came back to. I was really glad I did, because after solving it I really liked it.

## Gathering information
The challenge gives us a pcap file, which I opened in Wireshark. It looked like this:

![Wireshark](/files/hacktm-ctf-2020/strange-pcap/img/wireshark.png)

It was immediately clear that it was USB traffic as Wireshark indicates nicely. When I open a pcap file in Wireshark I scroll through the whole file to get a rough idea about the different kinds of traffic. It seems like multiple devices connect via USB and exchange information. This is mainly clear from the fact that there are different destinations in the file.

One thing was interesting to me. Some entries had a specific string:

`Generic Flash Disk 8.07`

This could mean that there is a USB drive connected to the host and this is the traffic. Interesting! What if files would be transferred? To check this I ordered the entries on size. I manually skimmed through the largest entries. And indeed something even more interesting is found:

![Wireshark-2](/files/hacktm-ctf-2020/strange-pcap/img/wireshark-2.png)
![Wireshark-3](/files/hacktm-ctf-2020/strange-pcap/img/wireshark-3.png)

In the first image it seems as there exists a file called `SECRETZIP` or something along those lines. And the second file mentions `Flag.txt`. This seems like our target!

_In this guide I did not use any tool to further inspect the traffic between USB devices and specifically USB flash drives. At this time I do not know any tool which does this, but if you know one I would love to know as well. Please leave a comment!_

## Exfiltration
I manually extracted the last entry by exporting the packet bytes of the payload and calling the file `secret.zip`. I checked if it was indeed a zip file by running file:

```bash
$ file secret.zip 
secret.zip: Zip archive data, at least v2.0 to extract
```

Yes, now let's extract it!

```bash
$ unzip secret.zip 
Archive:  secret.zip
[secret.zip] Flag.txt password: 
```

This is unexpected. The ZIP file needs a password. Luckily we can crack the password with John right?

```bash
$ zip2john secret.zip > hashes
ver 2.0 secret.zip/Flag.txt PKZIP Encr: cmplen=77, decmplen=72, crc=3345C065
$ john --wordlist=rockyou.txt hashes

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2020-02-04 22:25) 0g/s 9076Kp/s 9076Kc/s 9076KC/s !jonaluz28!..*7¡Vamos!
Session completed
$ john --show hashes 
0 password hashes cracked, 1 left
```

Ai, this does not look good. We need to find the password. But where?

## Grabbing a cup of coffee
At this moment I was stuck. This is totally normal. My main tactic is to take a step back. Just grab a coffee (or any drink will do) and look at what you have. I tried to think about how this challenge fits into a context. We see a capture of a user, sitting behind a computer, using some USB appliances. One of them is probably a USB stick, containing our ZIP file. The user probably copied it over to the computer. And then... Filled in the password to unlock it..? Of course! The user could have a keyboard connected to the system via USB as well. I thougt immediately of a challenge where the goal was to extract keyboard strokes from a USB capture. We could try this here as well.

Let's open the Wireshark file again. After 17 seconds into the capture the file is copied. After that we expect some kind of keyboard strokes. 


## Script
After some searching the web I found this nice resource: 

<https://bitvijays.github.io/LFC-Forensics.html>

It clearly describes how keyboard traffic can be monitored. I copied their script and slightly modified it for our case.

_Note: I first struggled with the script not identifying capital letters correctly. This is something I had to fix._

```python
#!/usr/bin/env python3

usb_codes = {
   0x04:"aA", 0x05:"bB", 0x06:"cC", 0x07:"dD", 0x08:"eE", 0x09:"fF",
   0x0A:"gG", 0x0B:"hH", 0x0C:"iI", 0x0D:"jJ", 0x0E:"kK", 0x0F:"lL",
   0x10:"mM", 0x11:"nN", 0x12:"oO", 0x13:"pP", 0x14:"qQ", 0x15:"rR",
   0x16:"sS", 0x17:"tT", 0x18:"uU", 0x19:"vV", 0x1A:"wW", 0x1B:"xX",
   0x1C:"yY", 0x1D:"zZ", 0x1E:"1!", 0x1F:"2@", 0x20:"3#", 0x21:"4$",
   0x22:"5%", 0x23:"6^", 0x24:"7&", 0x25:"8*", 0x26:"9(", 0x27:"0)",
   0x2C:"  ", 0x2D:"-_", 0x2E:"=+", 0x2F:"[{", 0x30:"]}",  0x32:"#~",
   0x33:";:", 0x34:"'\"",  0x36:",<",  0x37:".>", 0x4f:">", 0x50:"<"
   }
buff = ""

pos = 0
for x in open("strokes","r").readlines():
    code = int(x[4:6],16)

    if code == 0:
        continue
    if code == 0x28:
        buff += "[ENTER]"
        continue
    if int(x[0:2],16) == 2 or int(x[0:2],16) == 0x20:
        buff += usb_codes[code][1]
    else:
        buff += usb_codes[code][0]


print(buff)
```

Now let's check if it works. We begin by extracting the usb codes (the sed part is to remove empty lines):

```bash
tshark -r ../challenge/Strange.pcapng -T fields -e usb.capdata | sed '/^\s*$/d' > strokes
```

When inspected manually it does not seem quite right.

```bash
$ cat strokes 
0000000104000100000000000000
0000000104000100000000000000000100000000000000000000000000000000000000000000
210008
210010
210012
0000240000000000
0000000000000000
0000190000000000
0000000000000000
00000a0000000000
0000000000000000
00000d0000000000
0000000000000000
0000210000000000
0000000000000000
0200000000000000
0200160000000000
0200000000000000
0200160000000000
0200000000000000
0000000000000000
2000000000000000
20000f0000000000
0000000000000000
0000260000000000
0000000000000000
2000000000000000
2000110000000000
2000000000000000
0000000000000000
2000000000000000
20000b0000000000
2000000000000000
0000000000000000
2000000000000000
2000190000000000
2000000000000000
0000000000000000
0000180000000000
0000000000000000
0200000000000000
02000e0000000000
0200000000000000
0000000000000000
0000270000000000
0000000000000000
0200000000000000
0200070000000000
0200000000000000
0000000000000000
0000230000000000
0000000000000000
0000070000000000
0000000000000000
0000200000000000
0000000000000000
0200000000000000
0200090000000000
0200000000000000
0000000000000000
0000280000000000
0000000000000000
210010
```

So I removed the lines with an incorrect length. The file now looks like this:

```bash
$ cat strokes
0000240000000000
0000000000000000
0000190000000000
0000000000000000
00000a0000000000
0000000000000000
00000d0000000000
0000000000000000
0000210000000000
0000000000000000
0200000000000000
0200160000000000
0200000000000000
0200160000000000
0200000000000000
0000000000000000
2000000000000000
20000f0000000000
0000000000000000
0000260000000000
0000000000000000
2000000000000000
2000110000000000
2000000000000000
0000000000000000
2000000000000000
20000b0000000000
2000000000000000
0000000000000000
2000000000000000
2000190000000000
2000000000000000
0000000000000000
0000180000000000
0000000000000000
0200000000000000
02000e0000000000
0200000000000000
0000000000000000
0000270000000000
0000000000000000
0200000000000000
0200070000000000
0200000000000000
0000000000000000
0000230000000000
0000000000000000
0000070000000000
0000000000000000
0000200000000000
0000000000000000
0200000000000000
0200090000000000
0200000000000000
0000000000000000
0000280000000000
0000000000000000
```

Perfect! Lets run the script.

```bash
./solve.py 
7vgj4SSL9NHVuK0D6d3F[ENTER]
```

Great. The enter indicates we are on the right track, as the user would end the password with an enter. Lets check if the password works.

## Flag

```bash
$ unzip secret.zip 
Archive:  secret.zip
[secret.zip] Flag.txt password: 
  inflating: Flag.txt
$ cat Flag.txt 
HackTM{88f1005c6b308c2713993af1218d8ad2ffaf3eb927a3f73dad3654dc1d00d4ae}
```

It works! Challenge solved.

## Conclusion
I like this challenge. I have seen a challenge before in which I had to recover the keyboard strokes from USB traffic as well, so that definitely helped. I liked the fact that two different things are nicely combined; the data transfer and the keyboard strokes. The keyboard strokes was also a logical step after the ZIP file was discovered.

Thank you for reading. This was my first write-up. Did you like it? Or perhaps not? Please let me know with a comment!