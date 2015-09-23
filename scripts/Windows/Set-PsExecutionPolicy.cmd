@echo off
REM #AUTHOR   : CPE-RMP
REM #VERSION  : 1.01.01
REM #DATE     : 2015-04-09
REM #SYNOPSIS : Sets Powershell Execution Policy

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList 'Set-ExecutionPolicy Unrestricted -Force' -Verb RunAs}"
