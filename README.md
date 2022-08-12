1) `tctl auth export --type=windows > user-ca.cer`
2) `./generate_blob_certificate.py user-ca.cer`
3) share directory with windows
4) log into windows and open powershell
5) go to the directory with scripts and type `.\3_step_configure.ps1`


We can easily remove step 1 & 2 and just crete teleport command that will generate powershell script with all data already included